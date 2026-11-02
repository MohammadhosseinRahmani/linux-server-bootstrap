#!/usr/bin/env bash
# Checks for the full-baseline verifier, tests/verify.sh.
#
# verify.sh is sourced by a generated probe rather than executed, because a real
# pass would read this host's /etc/shadow and its running kernel. The probe points
# the shared paths at fixtures in a temporary directory and puts stub commands in
# front of PATH, so every proof is exercised against a known answer.
#
# Usage: bash tests/unit/test_verify.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

TESTS_RUN=0
TESTS_FAILED=0

ok() { printf '  PASS  %s\n' "$*"; }
nok() { printf '  FAIL  %s\n' "$*"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

assert_has() {
    local label="$1" haystack="$2" needle="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if grep -qF -- "${needle}" <<< "${haystack}"; then
        ok "${label}"
    else
        nok "${label}: missing '${needle}'"
        printf '%s\n' "${haystack}" | tail -20 | sed 's/^/        out: /'
    fi
}

assert_lacks() {
    local label="$1" haystack="$2" needle="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if grep -qF -- "${needle}" <<< "${haystack}"; then
        nok "${label}: unexpectedly found '${needle}'"
    else
        ok "${label}"
    fi
}

assert_eq() {
    local label="$1" want="$2" got="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${want}" == "${got}" ]]; then
        ok "${label}"
    else
        nok "${label}: expected '${want}', got '${got}'"
    fi
}

assert_rc() {
    local label="$1" want="$2" got="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${want}" == "${got}" ]]; then
        ok "${label}"
    else
        nok "${label}: expected rc ${want}, got ${got}"
    fi
}

write_fixture() {
    local path="$1" id="$2" like="$3" version="$4"
    {
        printf 'NAME="%s"\n' "${id}"
        printf 'ID=%s\n' "${id}"
        if [[ -n "${like}" ]]; then
            printf 'ID_LIKE="%s"\n' "${id} ${like}"
        fi
        printf 'VERSION_ID="%s"\n' "${version}"
    } > "${path}"
}

write_fixture "${WORK_DIR}/debian" debian '' '24'
write_fixture "${WORK_DIR}/rhel" rhel fedora '9'

STUB_DIR="${WORK_DIR}/stub"
mkdir -p "${STUB_DIR}"

new_stub() {
    local dir="$1" name="$2" body="$3"
    printf '#!/bin/sh\n%s\n' "${body}" > "${dir}/${name}"
    chmod +x "${dir}/${name}"
}

# A kernel that answers for every parameter the fixture lists, and nothing else.
new_stub "${STUB_DIR}" sysctl 'if [ "$1" = "-n" ]; then
    grep "^$2=" "${FAKE_SYSCTL_VALUES}" | cut -d= -f2-
    exit 0
fi
exit 0'

# Nothing running and nothing enabled, which is what a disabled legacy unit has to
# look like for the services check to accept it.
new_stub "${STUB_DIR}" systemctl 'case "$1" in
    is-active) exit 1 ;;
    is-enabled) exit 1 ;;
    *) exit 0 ;;
esac'

new_stub "${STUB_DIR}" getenforce 'printf "%s\n" "${FAKE_SELINUX_MODE}"'
new_stub "${STUB_DIR}" aa-status 'case "$1" in
    --enabled) exit "${FAKE_AA_ENABLED_RC}" ;;
    --enforce) exit "${FAKE_AA_ENFORCE_RC}" ;;
    *) exit 0 ;;
esac'
new_stub "${STUB_DIR}" auditctl 'case "$1" in
    -l) printf "%s\n" "${FAKE_AUDIT_RULES}" ;;
    -s) printf "enabled %s\n" "${FAKE_AUDIT_ENABLED}" ;;
    *) exit 0 ;;
esac'

SANDBOX="${WORK_DIR}/sandbox"
BACKUPS="${SANDBOX}/backups"
STATE="${SANDBOX}/state"
mkdir -p "${BACKUPS}" "${STATE}" "${SANDBOX}/limits.d" "${SANDBOX}/systemd" \
    "${SANDBOX}/pam" "${SANDBOX}/sysctl.d" "${SANDBOX}/audit" "${SANDBOX}/sshd.d"

# verify.sh runs main only when it is executed, so the probe sources it and picks
# the one check to exercise.
cat > "${WORK_DIR}/probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -uo pipefail

# shellcheck disable=SC1090
source "${PROJECT_DIR}/lib/common.sh"
if ! detect_os > /dev/null 2>&1; then
    echo "DETECT_FAILED"
    exit 1
fi
INIT_SYSTEM="${FAKE_INIT:-none}"
# shellcheck disable=SC1090
source "${PROJECT_DIR}/tests/verify.sh"
# shellcheck disable=SC2206
SSH_ALLOW_USERS=(${FAKE_USERS:-})
SSH_PORT=2222

case "$1" in
    gate_absent)
        verify_stage sysctl "Kernel parameters" check_sysctl
        list_not_applied
        ;;
    gate_skip_fw)
        SKIP_FIREWALL=1
        verify_stage firewall "Firewall" check_firewall
        ;;
    gate_skip_f2b)
        SKIP_FAIL2BAN=1
        verify_stage fail2ban "fail2ban" check_fail2ban
        ;;
    recorded)
        recorded_value sysctl SYSCTL_TARGET
        ;;
    sysctl_live)
        check_sysctl
        ;;
    limits_ok)
        check_limits
        ;;
    auth_ok)
        check_auth
        ;;
    users_missing)
        check_users
        ;;
    audit_ok)
        check_audit
        ;;
    mac_apparmor)
        check_mac
        ;;
    mac_selinux)
        check_mac
        ;;
    services_off)
        check_services
        ;;
    marker)
        banner_marker
        ;;
    rollback_points)
        check_rollback_points
        ;;
    *)
        echo "UNKNOWN_PROBE $1"
        ;;
esac
PROBE

# probe <action> [fixture]  -> the output of that one check
probe() {
    local action="$1" fixture="${2:-${WORK_DIR}/debian}"
    (
        cd "${PROJECT_DIR}" || exit 1
        export PROJECT_DIR
        export OS_RELEASE_FILE="${fixture}"
        export PATH="${STUB_DIR}:${PATH}"
        export BACKUP_ROOT="${BACKUPS}"
        export STATE_DIR="${STATE}"
        export LOG_FILE="${SANDBOX}/verify.log"
        export SSH_PORT=2222
        export LIMITS_TARGET="${SANDBOX}/limits.d/99.conf"
        export SYSTEMD_LIMITS_DROPIN="${SANDBOX}/systemd/99.conf"
        export LOGIN_DEFS_FILE="${SANDBOX}/login.defs"
        export FAILLOCK_CONF="${SANDBOX}/faillock.conf"
        export PWQUALITY_CONF="${SANDBOX}/pwquality.conf"
        export SSH_BANNER_TARGET="${SANDBOX}/sshd.d/banner.conf"
        export SSH_CONFIG_DIR="${SANDBOX}/sshd.d"
        export PAM_DIR="${SANDBOX}/pam"
        export APPARMOR_PROFILE_DIR="${SANDBOX}/apparmor.d"
        export SELINUX_CONFIG="${SANDBOX}/selinux_config"
        export SUDOERS_DIR="${SANDBOX}/sudoers.d"
        bash "${WORK_DIR}/probe.sh" "${action}" 2>&1
    )
}

printf 'PASSWORD_MAX_DAYS=365\nLOCKOUT_DENY=3\nLOGIN_UMASK=027\n' > "${STATE}/state.env"
printf 'PASSWORD_MIN_LEN=14\nLOCKOUT_FAIL_INTERVAL=900\n' >> "${STATE}/state.env"
printf 'CORE_LIMIT=0\nMAX_LOGINS=4\n' >> "${STATE}/state.env"
printf 'DISABLED_SERVICES=telnet.socket ypbind\nPERM_PATHS=28\n' >> "${STATE}/state.env"

echo "== the applied gate =="
OUT="$(probe gate_absent)"
assert_has "no backup reads as not applied" "${OUT}" \
    "[SKIP] Kernel parameters was not applied, so there is nothing to check."
assert_has "the skipped stage is listed" "${OUT}" "left unchecked: Kernel parameters"

OUT="$(probe gate_skip_fw)"
assert_has "an explicit skip stays a skip" "${OUT}" "skipped on purpose (--skip-firewall)"

OUT="$(probe gate_skip_f2b)"
assert_has "the fail2ban skip flag is honoured" "${OUT}" "skipped on purpose (--skip-fail2ban)"

echo "== a stage that did run gets checked =="
mkdir -p "${BACKUPS}/sysctl/2026-01-01T00-00-00"
ln -s "2026-01-01T00-00-00" "${BACKUPS}/sysctl/latest"
printf 'SYSCTL_TARGET=%s\n' "${SANDBOX}/sysctl.d/99.conf" \
    > "${BACKUPS}/sysctl/2026-01-01T00-00-00/manifest.env"
OUT="$(probe recorded)"
assert_eq "the manifest carries the installed path" "${SANDBOX}/sysctl.d/99.conf" "${OUT}"

printf 'kernel.randomize_va_space = 2\nkernel.core_uses_pid = 1\nfs.protected_symlinks = 1\n' \
    > "${SANDBOX}/sysctl.d/99.conf"
export FAKE_SYSCTL_VALUES="${SANDBOX}/sysctl-values"
printf 'kernel.randomize_va_space=2\nkernel.core_uses_pid=1\nfs.protected_symlinks=1\n' \
    > "${FAKE_SYSCTL_VALUES}"
OUT="$(probe sysctl_live)"
assert_has "every parameter reads back" "${OUT}" "all 3 kernel parameters are live"
assert_lacks "no sysctl failure" "${OUT}" "[FAIL]"

printf 'kernel.randomize_va_space=0\n' > "${FAKE_SYSCTL_VALUES}"
OUT="$(probe sysctl_live)"
assert_has "a value the kernel ignored is reported" "${OUT}" \
    "[FAIL] sysctl: kernel.randomize_va_space is 0, expected 2"

: > "${SANDBOX}/sysctl.d/99.conf"
OUT="$(probe sysctl_live)"
assert_has "an empty baseline fails" "${OUT}" "baseline file is missing or empty"

echo "== login limits =="
printf '* hard core 0\n* hard maxlogins 4\n' > "${SANDBOX}/limits.d/99.conf"
printf '[Manager]\nDefaultLimitCORE=0\n' > "${SANDBOX}/systemd/99.conf"
export FAKE_INIT=systemd
OUT="$(probe limits_ok)"
assert_has "core limit proven" "${OUT}" "limits: core dumps are limited to 0"
assert_has "maxlogins proven" "${OUT}" "limits: concurrent logins are capped at 4"
assert_has "systemd default proven" "${OUT}" "limits: systemd DefaultLimitCORE=0"
assert_lacks "no limits failure" "${OUT}" "[FAIL]"

printf '* hard core 0\n' > "${SANDBOX}/limits.d/99.conf"
OUT="$(probe limits_ok)"
assert_has "a missing maxlogins line is reported" "${OUT}" \
    "[FAIL] limits: no 'hard maxlogins 4' line"

echo "== authentication policy =="
{
    # The distribution's own defaults sit outside the block, so reading the block
    # is the only way the check can tell the two apart.
    printf 'PASS_MAX_DAYS\t999999\nUMASK\t\t022\n'
    printf '# BEGIN linux-server-bootstrap\n'
    printf 'PASS_MAX_DAYS\t365\n'
    printf 'UMASK\t\t027\n'
    printf '# END linux-server-bootstrap\n'
} > "${SANDBOX}/login.defs"
printf 'deny = 3\nfail_interval = 900\nunlock_time = 900\n' > "${SANDBOX}/faillock.conf"
printf 'minlen = 14\n' > "${SANDBOX}/pwquality.conf"
printf 'auth required pam_faillock.so preauth\n' > "${SANDBOX}/pam/common-auth"
OUT="$(probe auth_ok)"
assert_has "managed block found" "${OUT}" "carries the managed block"
assert_has "PASS_MAX_DAYS proven" "${OUT}" "auth: PASS_MAX_DAYS is 365"
assert_has "UMASK proven" "${OUT}" "auth: UMASK is 027"
assert_has "minlen proven" "${OUT}" "auth: pwquality minlen is 14"
assert_has "deny proven" "${OUT}" "auth: faillock denies after 3 failures"
assert_has "faillock in the stack" "${OUT}" "auth: a PAM stack calls pam_faillock"
assert_has "fail_interval proven" "${OUT}" "auth: faillock fail_interval is 900"

printf 'PASS_MAX_DAYS\t999999\n' > "${SANDBOX}/login.defs"
printf '# BEGIN linux-server-bootstrap\nPASS_MAX_DAYS\t999\nUMASK\t\t027\n# END linux-server-bootstrap\n' \
    >> "${SANDBOX}/login.defs"
OUT="$(probe auth_ok)"
assert_has "a drifted value is reported" "${OUT}" \
    "[FAIL] auth: PASS_MAX_DAYS is 999, expected 365"

echo "== accounts =="
export FAKE_USERS="verifynope"
OUT="$(probe users_missing)"
assert_has "an absent account is reported" "${OUT}" \
    "[FAIL] users: account verifynope does not exist"

echo "== audit rules =="
printf 'AUDIT_RULES_FILE=%s\n' "${SANDBOX}/audit/99.rules" >> "${STATE}/state.env"
{
    printf -- '-w /etc/passwd -p wa -k identity\n'
    printf -- '-e 2\n'
} > "${SANDBOX}/audit/99.rules"
export FAKE_AUDIT_RULES="-w /etc/passwd -p wa -k identity"
export FAKE_AUDIT_ENABLED=2
export FAKE_INIT=none
OUT="$(probe audit_ok)"
assert_has "rule count reported" "${OUT}" "audit: 2 rule(s) in"
assert_has "rules are loaded" "${OUT}" "audit: the running kernel has rules loaded"
assert_has "the lock is proven" "${OUT}" "audit: the ruleset is locked until the next reboot"

export FAKE_AUDIT_ENABLED=1
OUT="$(probe audit_ok)"
assert_has "an unlocked ruleset is reported" "${OUT}" \
    "but the kernel is not enabled level 2"

echo "== mandatory access control =="
export FAKE_AA_ENABLED_RC=0
export FAKE_AA_ENFORCE_RC=0
printf 'MAC_KIND=apparmor\n' >> "${STATE}/state.env"
OUT="$(probe mac_apparmor)"
assert_has "AppArmor enabled is proven" "${OUT}" "mac: AppArmor is enabled"
assert_has "enforce mode is proven" "${OUT}" \
    "at least one AppArmor profile is in enforce mode"

export FAKE_AA_ENFORCE_RC=1
OUT="$(probe mac_apparmor)"
assert_has "complain-only profiles are reported" "${OUT}" \
    "[FAIL] mac: no AppArmor profile is in enforce mode"
export FAKE_AA_ENFORCE_RC=0

export FAKE_SELINUX_MODE=Permissive
printf '# policy\nSELINUX=permissive\n' > "${SANDBOX}/selinux_config"
sed -i 's/^MAC_KIND=apparmor$/MAC_KIND=selinux/' "${STATE}/state.env"
OUT="$(probe mac_selinux "${WORK_DIR}/rhel")"
assert_has "permissive SELinux is reported" "${OUT}" \
    "[FAIL] mac: SELinux reports Permissive, expected Enforcing"
assert_has "the config file is checked too" "${OUT}" "does not set SELINUX=enforcing"

export FAKE_SELINUX_MODE=Enforcing
printf 'SELINUX=enforcing\n' > "${SANDBOX}/selinux_config"
OUT="$(probe mac_selinux "${WORK_DIR}/rhel")"
assert_has "enforcing is proven" "${OUT}" "mac: SELinux is enforcing"
assert_has "the config survives a reboot" "${OUT}" "survives a reboot"

echo "== legacy services =="
export FAKE_INIT=systemd
OUT="$(probe services_off)"
assert_has "a stopped unit is proven" "${OUT}" "services: telnet.socket is disabled and stopped"
assert_has "the second unit is proven" "${OUT}" "services: ypbind is disabled and stopped"

echo "== banner =="
OUT="$(probe marker)"
assert_has "the marker comes from the template" "${OUT}" \
    "This system is for authorised use only."

echo "== rollback points =="
OUT="$(probe rollback_points)"
assert_has "state without a backup is reported" "${OUT}" "perms: PERM_PATHS is recorded but"
mkdir -p "${BACKUPS}/perms/2026-01-01T00-00-00"
ln -s "2026-01-01T00-00-00" "${BACKUPS}/perms/latest"
OUT="$(probe rollback_points)"
assert_lacks "a backup silences the complaint" "${OUT}" "PERM_PATHS is recorded but"

echo "== command line =="
HELP_OUT="$(cd "${PROJECT_DIR}" && bash tests/verify.sh --help 2>&1)"
assert_has "usage explains the gate" "${HELP_OUT}" "is reported as not applied"
(cd "${PROJECT_DIR}" && bash tests/verify.sh --nonsense > /dev/null 2>&1)
assert_rc "an unknown flag exits 2" "2" "$?"

echo
printf 'test_verify: %s check(s), %s failure(s)\n' "${TESTS_RUN}" "${TESTS_FAILED}"
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
printf 'test_verify: OK\n'
exit 0
