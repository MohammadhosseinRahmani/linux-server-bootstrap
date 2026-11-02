#!/usr/bin/env bash
# Hardening module checks: the PAM splice, the managed-block writer, and the
# dry-run transcript of every stage added for the CIS baseline.
#
# The PAM and login.defs work is the part that can lock a real operator out, so
# it is tested against fixtures on disk rather than through a plan-only pass.
# Those fixtures live in a temporary directory and install_file is replaced by a
# plain copy, so the runner's own authentication stack is never touched.
#
# Usage: bash tests/unit/test_hardening.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

export BACKUP_ROOT="${WORK_DIR}/backups"
export STATE_DIR="${WORK_DIR}/state"
export LOG_FILE="${WORK_DIR}/test.log"

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
        printf '%s\n' "${haystack}" | tail -15 | sed 's/^/        out: /'
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

# A stage that legitimately stops early on a bare host still has to say where it
# stopped, so either ending of its transcript is acceptable.
assert_has_any() {
    local label="$1" haystack="$2"
    shift 2
    TESTS_RUN=$((TESTS_RUN + 1))
    local needle
    for needle in "$@"; do
        if grep -qF -- "${needle}" <<< "${haystack}"; then
            ok "${label}"
            return 0
        fi
    done
    nok "${label}: none of the expected lines appeared"
    printf '%s\n' "${haystack}" | tail -15 | sed 's/^/        out: /'
}

assert_absent_file() {
    local label="$1" path="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -e "${path}" ]]; then
        nok "${label}: ${path} exists"
    else
        ok "${label}"
    fi
}

# Runs one function from lib/drivers/_pam.sh or lib/common.sh against a fixture.
# install_file is the only writer these helpers use, so redirecting it keeps the
# test inside the temporary directory: fixtures are written where they are named,
# and a hard-coded absolute path lands in a shadow tree.
install_shadow() {
    local src="$2" dest="$3" target
    case "${dest}" in
        "${WORK_DIR}"/*) target="${dest}" ;;
        /*) target="${WORK_DIR}/root${dest}" ;;
        *) target="${dest}" ;;
    esac
    mkdir -p "$(dirname -- "${target}")"
    cp -- "${src}" "${target}"
}

run_lib() {
    (
        cd "${PROJECT_DIR}" || exit 1
        export LOG_FILE="${WORK_DIR}/lib.log"
        # shellcheck disable=SC1091
        source lib/common.sh
        # shellcheck disable=SC1091
        source lib/drivers/_pam.sh
        DRY_RUN=1
        install_file() { install_shadow "$@"; }
        "$@"
    )
}

auth_fixture() {
    local dir="$1"
    shift
    mkdir -p "${dir}"
    if [[ $# -gt 0 ]]; then
        printf '%s\n' "$@" > "${dir}/auth"
    else
        cat > "${dir}/auth" <<'EOF'
# here are the per-package modules that the distribution uses
auth    required                        pam_env.so
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
EOF
    fi
    cat > "${dir}/account" <<'EOF'
account required pam_unix.so
account sufficient pam_localuser.so
account required pam_permit.so
EOF
}

echo "== the faillock splice keeps the stack's success jump correct =="
FIRST_DIR="${WORK_DIR}/pam-first"
auth_fixture "${FIRST_DIR}"
SPLICE_OUT="$(run_lib pam_splice_faillock "${FIRST_DIR}/auth" "${FIRST_DIR}/account" 2>&1)"
assert_rc "the splice succeeded" 0 "$?"
FIRST_AUTH="$(cat "${FIRST_DIR}/auth")"
assert_has "the jump counts the inserted line" "${FIRST_AUTH}" "[success=2 default=ignore]"
assert_has "preauth is inserted" "${FIRST_AUTH}" "pam_faillock.so preauth silent"
assert_has "authfail follows the unix line" "${FIRST_AUTH}" "pam_faillock.so authfail"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -c 'pam_deny.so' <<< "${FIRST_AUTH}")" == "1" ]]; then
    ok "pam_deny is still in the stack"
else
    nok "pam_deny was lost: ${FIRST_AUTH}"
fi
# The order is the safety property: a successful password must still reach
# pam_permit, and a failure must still reach pam_deny.
STACK_ORDER="$(grep -E 'pam_(faillock|unix|deny|permit)\.so' <<< "${FIRST_AUTH}" \
    | sed 's/.*pam_\(faillock\|unix\|deny\|permit\)\.so.*/\1/' | tr '\n' ' ')"
assert_eq "stack order is preauth unix authfail deny permit" \
    "faillock unix faillock deny permit " "${STACK_ORDER}"
ACCOUNT_AFTER="$(cat "${FIRST_DIR}/account")"
assert_has "the account rule was added" "${ACCOUNT_AFTER}" "account     required      pam_faillock.so"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -n 'pam_faillock' "${FIRST_DIR}/account" | cut -d: -f1)" == "1" ]]; then
    ok "the account rule precedes pam_unix"
else
    nok "the account rule is not first: ${ACCOUNT_AFTER}"
fi

echo
echo "== a second run does not stack a second pair of rules =="
REPEAT_OUT="$(run_lib pam_splice_faillock "${FIRST_DIR}/auth" "${FIRST_DIR}/account" 2>&1)"
assert_rc "the re-run succeeded" 0 "$?"
assert_has "the existing stack is recognised" "${REPEAT_OUT}" "already references pam_faillock"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -c 'pam_faillock' "${FIRST_DIR}/auth")" == "2" ]]; then
    ok "exactly one preauth and one authfail line"
else
    nok "faillock lines stacked: $(cat "${FIRST_DIR}/auth")"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -c 'pam_faillock' "${FIRST_DIR}/account")" == "1" ]]; then
    ok "the account rule is not duplicated"
else
    nok "account rule duplicated: $(cat "${FIRST_DIR}/account")"
fi
assert_eq "the jump is not raised twice" "1" "$(grep -c '\[success=2 ' "${FIRST_DIR}/auth")"

echo
echo "== a two-digit jump is raised correctly =="
BIG_DIR="${WORK_DIR}/pam-big"
auth_fixture "${BIG_DIR}" \
    'auth    [success=10 default=ignore]     pam_unix.so nullok' \
    'auth    requisite                       pam_deny.so' \
    'auth    required                        pam_permit.so'
run_lib pam_splice_faillock "${BIG_DIR}/auth" "${BIG_DIR}/account" > /dev/null 2>&1
assert_has "10 becomes 11" "$(cat "${BIG_DIR}/auth")" "[success=11 default=ignore]"
assert_lacks "no leftover of the old number" "$(cat "${BIG_DIR}/auth")" "[success=10 "

echo
echo "== a stack without pam_unix is refused instead of guessed at =="
NONE_DIR="${WORK_DIR}/pam-none"
auth_fixture "${NONE_DIR}" 'auth    required    pam_permit.so'
NONE_BEFORE="$(cat "${NONE_DIR}/auth")"
NONE_OUT="$(run_lib pam_splice_faillock "${NONE_DIR}/auth" "${NONE_DIR}/account" 2>&1)"
assert_rc "the splice reports failure" 1 "$?"
assert_has "the refusal is explained" "${NONE_OUT}" "No pam_unix auth line was found"
assert_eq "the stack was left exactly as found" "${NONE_BEFORE}" "$(cat "${NONE_DIR}/auth")"

write_confs() {
    faillock_conf_write 5 60 1800
    pwquality_conf_write 16
}

echo
echo "== the lockout and complexity files carry the requested values =="
CONF_OUT="$(run_lib write_confs 2>&1)"
assert_rc "the writers ran" 0 "$?"
assert_has "the security directory is created through run_cmd" "${CONF_OUT}" \
    "[dry-run] mkdir -p -- /etc/security"
FAILLOCK_TEXT="$(cat "${WORK_DIR}/root/etc/security/faillock.conf")"
PWQUALITY_TEXT="$(cat "${WORK_DIR}/root/etc/security/pwquality.conf")"
assert_has "deny is written" "${FAILLOCK_TEXT}" "deny = 5"
assert_has "the window is written" "${FAILLOCK_TEXT}" "fail_interval = 60"
assert_has "the unlock time is written" "${FAILLOCK_TEXT}" "unlock_time = 1800"
assert_has "root is locked out too" "${FAILLOCK_TEXT}" "even_deny_root"
assert_has "the file names its manager" "${FAILLOCK_TEXT}" "Managed by linux-server-bootstrap"
assert_has "the minimum length is written" "${PWQUALITY_TEXT}" "minlen = 16"

echo
echo "== a managed block is replaced, not stacked =="
BLOCK_FILE="${WORK_DIR}/login.defs"
printf '# begin\nPASS_MAX_DAYS 99999\n# end\nSOMETHING_ELSE 1\n' > "${BLOCK_FILE}"
block_test() {
    printf 'PASS_MAX_DAYS %s\n' "$1" > "${WORK_DIR}/block.content"
    run_lib managed_block_set "${BLOCK_FILE}" '# BEGIN lsb' '# END lsb' "${WORK_DIR}/block.content" \
        > /dev/null 2>&1
}
block_test 365
block_test 90
BLOCK_AFTER="$(cat "${BLOCK_FILE}")"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -c 'BEGIN lsb' <<< "${BLOCK_AFTER}")" == "1" ]]; then
    ok "one block after two runs"
else
    nok "blocks stacked: ${BLOCK_AFTER}"
fi
assert_has "the later value wins" "${BLOCK_AFTER}" "PASS_MAX_DAYS 90"
assert_lacks "the earlier value is gone" "${BLOCK_AFTER}" "PASS_MAX_DAYS 365"
assert_has "the untouched lines survive" "${BLOCK_AFTER}" "SOMETHING_ELSE 1"

echo
export DRY_RUN=1
echo "== hardening stage dry-runs plan without touching the host =="
SYSCTL_OUT="$(cd "${PROJECT_DIR}" && bash hardening/sysctl.sh --yes --dry-run 2>&1)"
assert_rc "sysctl.sh plans successfully" 0 "$?"
assert_has "the drop-in target is named" "${SYSCTL_OUT}" "99-linux-server-bootstrap.conf"
assert_has "the kernel plan completes" "${SYSCTL_OUT}" "Kernel parameter plan is complete."

LIMITS_OUT="$(cd "${PROJECT_DIR}" && bash hardening/limits.sh --yes --dry-run --max-logins 5 2>&1)"
assert_rc "limits.sh plans successfully" 0 "$?"
assert_has "the limits drop-in target is named" "${LIMITS_OUT}" "99-linux-server-bootstrap.conf"
assert_has "the limit plan completes" "${LIMITS_OUT}" "Login limit plan is complete."

PERMS_OUT="$(cd "${PROJECT_DIR}" && bash hardening/perms.sh --yes --dry-run 2>&1)"
assert_rc "perms.sh plans successfully" 0 "$?"
assert_has "the modes go through dry-run only" "${PERMS_OUT}" "[dry-run] chmod"
assert_has "the permission plan completes" "${PERMS_OUT}" "Permission plan is complete."

AUDIT_OUT="$(cd "${PROJECT_DIR}" && bash hardening/audit.sh --yes --dry-run --watch-privileged 2>&1)"
assert_rc "audit.sh plans successfully" 0 "$?"
assert_has "the rules file target is named" "${AUDIT_OUT}" "99-linux-server-bootstrap.rules"
assert_has "the privileged watches are announced" "${AUDIT_OUT}" "watch every setuid"
assert_has "the audit plan completes" "${AUDIT_OUT}" "Audit rule plan is complete."
assert_lacks "an absent auditctl is not reported as loaded" "${AUDIT_OUT}" "rule(s) loaded"

# A MAC plan depends on what the host actually ships, and a slim container image
# has neither AppArmor nor SELinux tools. The fixtures give each family a definite
# answer, so the same assertion holds on Debian, RPM and SUSE runners.
MAC_STUB="${WORK_DIR}/mac-stub"
mkdir -p "${MAC_STUB}" "${WORK_DIR}/apparmor.d"
printf 'profile unittest /bin/true {\n}\n' > "${WORK_DIR}/apparmor.d/unittest"
printf 'case "$1" in\n  --enabled) exit 0 ;;\nesac\nexit 0\n' > "${MAC_STUB}/aa-status"
printf 'printf "Enforcing\\n"\nexit 0\n' > "${MAC_STUB}/getenforce"
printf 'exit 0\n' > "${MAC_STUB}/setenforce"
chmod +x "${MAC_STUB}/aa-status" "${MAC_STUB}/getenforce" "${MAC_STUB}/setenforce"
printf 'SELINUX=permissive\n' > "${WORK_DIR}/selinux_config"

MAC_OUT="$(cd "${PROJECT_DIR}" \
    && PATH="${MAC_STUB}:${PATH}" \
        APPARMOR_PROFILE_DIR="${WORK_DIR}/apparmor.d" \
        SELINUX_CONFIG="${WORK_DIR}/selinux_config" \
        bash hardening/mac.sh --yes --dry-run 2>&1)"
assert_rc "mac.sh plans successfully" 0 "$?"
assert_has "the MAC plan completes" "${MAC_OUT}" \
    "Mandatory access control plan is complete."

SERVICES_OUT="$(cd "${PROJECT_DIR}" && bash hardening/services.sh --yes --dry-run --include-optional 2>&1)"
assert_rc "services.sh plans successfully" 0 "$?"
assert_has_any "the service scope is reported" "${SERVICES_OUT}" \
    "legacy service" "Service plan is complete."

BANNER_OUT="$(cd "${PROJECT_DIR}" && bash hardening/banner.sh --yes --dry-run 2>&1)"
assert_rc "banner.sh plans successfully" 0 "$?"
assert_has "the console banner is planned" "${BANNER_OUT}" "/etc/issue"
assert_has "the banner plan completes" "${BANNER_OUT}" "Banner plan is complete."

AUTH_OUT="$(cd "${PROJECT_DIR}" && bash hardening/auth_policy.sh --yes --dry-run --deny 4 2>&1)"
assert_rc "auth_policy.sh plans successfully" 0 "$?"
assert_has "the aging block is planned" "${AUTH_OUT}" "/etc/login.defs"
assert_has "the requested deny count is used" "${AUTH_OUT}" "4 failures"
assert_has "the authentication plan completes" "${AUTH_OUT}" "Authentication policy plan is complete."

BAD_DENY="$(cd "${PROJECT_DIR}" && bash hardening/auth_policy.sh --yes --dry-run --deny 0 2>&1)"
assert_rc "a deny of zero is refused" 2 "$?"
assert_has "the refusal explains the range" "${BAD_DENY}" "--deny"

echo
echo "== no dry-run wrote to the host =="
assert_absent_file "no sysctl drop-in on the host" "/etc/sysctl.d/99-linux-server-bootstrap.conf"
assert_absent_file "no limits drop-in on the host" "/etc/security/limits.d/99-linux-server-bootstrap.conf"
assert_absent_file "no audit rules file on the host" "/etc/audit/rules.d/99-linux-server-bootstrap.rules"
assert_absent_file "no banner drop-in on the host" "/etc/ssh/sshd_config.d/10-linux-server-bootstrap-banner.conf"
assert_lacks "the host login.defs has no managed block" "$(cat /etc/login.defs)" "BEGIN linux-server-bootstrap"

echo
echo "Ran ${TESTS_RUN} checks, ${TESTS_FAILED} failed."
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0
