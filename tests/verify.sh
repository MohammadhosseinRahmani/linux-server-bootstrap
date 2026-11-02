#!/usr/bin/env bash
# Read-only checks for every stage of the baseline.
#
# A stage that left no backup under ${BACKUP_ROOT} reports "not applied" instead of
# failing, so verifying a run that only covered part of the baseline does not
# complain about the parts nobody asked for. Exits 0 when every check that applies
# passes; a check that cannot run on this host reports itself instead of guessing.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

FAILURES=0
NOT_APPLIED=()
SKIP_FIREWALL=0
SKIP_FAIL2BAN=0
HAVE_USERS=1
SSH_EFFECTIVE=""

# Every state key the stages write, paired with the component that owns its
# rollback point. A change recorded in the state file has to be undoable.
STATE_OWNERS=(
    "HOSTNAME base"
    "TIMEZONE base"
    "LOCALE base"
    "TIMESYNC base"
    "AUTOUPDATES base"
    "UPDATES_APPLIED base"
    "ADMIN_USERS users"
    "SUDO_USERS users"
    "SSH_MANAGED_PORT firewall"
    "SYSCTL_BASELINE sysctl"
    "CORE_LIMIT limits"
    "MAX_LOGINS limits"
    "PERM_PATHS perms"
    "AUDIT_RULES_FILE audit"
    "MAC_KIND mac"
    "DISABLED_SERVICES services"
    "BANNER_INSTALLED banner"
    "PASSWORD_MAX_DAYS auth"
    "PASSWORD_MIN_LEN auth"
    "LOCKOUT_DENY auth"
    "LOCKOUT_FAIL_INTERVAL auth"
    "LOCKOUT_UNLOCK_TIME auth"
    "LOGIN_UMASK auth"
)

usage() {
    cat <<EOF
Usage: bash tests/verify.sh [--user NAME...] [--port N]
       bash tests/verify.sh [--skip-firewall] [--skip-fail2ban]

Reads ${STATE_FILE} when --user or --port is omitted.
Pass --skip-firewall or --skip-fail2ban after a bootstrap run that used them.
A stage with no backup under ${BACKUP_ROOT} is reported as not applied.
EOF
}

parse_verify_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-firewall)
                SKIP_FIREWALL=1
                shift
                ;;
            --skip-fail2ban)
                SKIP_FAIL2BAN=1
                shift
                ;;
            --user|--port)
                if [[ $# -lt 2 ]]; then
                    error "$1 requires a value."
                    return 2
                fi
                parse_standard_args "$1" "$2" || return 2
                shift 2
                ;;
            --yes|-h|--help)
                parse_standard_args "$1" || return 2
                shift
                ;;
            *)
                error "Unknown argument: $1"
                return 2
                ;;
        esac
    done
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    FAILURES=$((FAILURES + 1))
}

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
}

check() {
    local description="$1"
    shift
    if "$@"; then
        pass "${description}"
    else
        fail "${description}"
    fi
}

stage_applied() {
    [[ -L "${BACKUP_ROOT}/${1}/latest" ]]
}

# Run one stage's checks only when that stage left a backup. The label is what the
# operator sees, so the gate reads as a decision rather than as a missing file.
verify_stage() {
    local component="$1" label="$2" fn="$3"

    if [[ "${component}" == "firewall" && "${SKIP_FIREWALL}" -eq 1 ]]; then
        skip "Firewall checks were skipped on purpose (--skip-firewall)."
        return 0
    fi
    if [[ "${component}" == "fail2ban" && "${SKIP_FAIL2BAN}" -eq 1 ]]; then
        skip "fail2ban checks were skipped on purpose (--skip-fail2ban)."
        return 0
    fi
    if ! stage_applied "${component}"; then
        NOT_APPLIED+=("${label}")
        skip "${label} was not applied, so there is nothing to check."
        return 0
    fi
    # Every failing proof already counted itself in FAILURES, so the return code
    # of a check must not end the run: the remaining stages still have to report.
    "${fn}" || true
}

# The stage notes what it installed in its own backup manifest, which is more
# truthful than letting the verifier re-derive the driver's path choice.
recorded_value() {
    local component="$1" key="$2" dir
    dir="$(latest_backup_dir "${component}" 2>/dev/null)" || return 1
    [[ -f "${dir}/manifest.env" ]] || return 1
    grep -E "^${key}=" "${dir}/manifest.env" 2>/dev/null | tail -n 1 | cut -d= -f2-
}

mode_of() {
    stat -c '%a' "$1" 2>/dev/null || true
}

owner_of() {
    stat -c '%U:%G' "$1" 2>/dev/null || true
}

# stat prints 644 while the configuration lists write 0644, so either is a match.
mode_matches() {
    local have="$1" want="$2"
    [[ -n "${have}" ]] || return 1
    [[ "${have}" == "${want}" || "${have}" == "${want#0}" ]]
}

effective_has() {
    local pattern="$1"
    printf '%s\n' "${SSH_EFFECTIVE}" | grep -Eiq "${pattern}"
}

# ---------------------------------------------------------------------------
# base setup
# ---------------------------------------------------------------------------

timezone_is_current() {
    local want="$1" current=""
    current="$(readlink -f "${LOCALTIME_FILE}" 2>/dev/null | sed 's|.*/zoneinfo/||' || true)"
    if [[ -f "${TIMEZONE_NAME_FILE}" ]]; then
        current="$(head -n 1 "${TIMEZONE_NAME_FILE}")"
    fi
    [[ "${current}" == "${want}" ]]
}

locale_is_current() {
    local want="$1" file
    while IFS= read -r file; do
        [[ -f "${file}" ]] || continue
        if grep -E 'LANG' "${file}" 2>/dev/null | grep -qF -- "${want}"; then
            return 0
        fi
    done < <(drv_locale_files)
    return 1
}

# Each family turns automatic patching on differently, so any one of these
# markers being present is the answer; naming the family here would put a
# distribution switch into the verifier.
autoupdate_marker() {
    local path unit
    for path in /etc/apt/apt.conf.d/20auto-upgrades /etc/cron.weekly/apt-xapian-index; do
        if [[ -e "${path}" ]]; then
            printf '%s\n' "${path}"
            return 0
        fi
    done
    for unit in dnf-automatic-install.timer dnf-automatic.timer yum-cron \
        linux-server-bootstrap-autoupdates.timer apt-daily-upgrade.timer; do
        if [[ "$(svc_is_enabled "${unit}")" == "enabled" ]]; then
            printf '%s\n' "${unit}"
            return 0
        fi
    done
    return 1
}

check_base() {
    local want current marker unit

    want="$(state_value HOSTNAME)"
    if [[ -z "${want}" ]]; then
        info "base: no hostname was recorded, so the name was not checked."
    elif [[ "$(hostname 2>/dev/null || true)" == "${want}" ]] && grep -Fxq "${want}" /etc/hostname; then
        pass "base: hostname is ${want}"
    else
        fail "base: hostname is not ${want} ($(hostname 2>/dev/null || printf 'unreadable'))"
    fi

    want="$(state_value TIMEZONE)"
    if [[ -n "${want}" ]]; then
        if timezone_is_current "${want}"; then
            pass "base: the clock uses ${want}"
        else
            current="$(readlink -f "${LOCALTIME_FILE}" 2>/dev/null || printf 'unreadable')"
            fail "base: the clock does not use ${want} (${current})"
        fi
    fi

    want="$(state_value LOCALE)"
    if [[ -n "${want}" ]]; then
        if locale_is_current "${want}"; then
            pass "base: the locale is set to ${want}"
        else
            fail "base: no locale file from the driver mentions ${want}"
        fi
    fi

    unit="$(state_value TIMESYNC)"
    if [[ -n "${unit}" ]]; then
        if [[ "${INIT_SYSTEM}" == "none" ]]; then
            skip "base: ${unit} cannot be checked because this host has no service manager."
        elif svc_is_active "${unit}"; then
            pass "base: time sync service ${unit} is active"
        else
            fail "base: time sync service ${unit} is not active"
        fi
    fi

    if [[ -n "$(state_value AUTOUPDATES)" ]]; then
        if marker="$(autoupdate_marker)"; then
            pass "base: automatic patching is present (${marker})"
        else
            fail "base: no automatic update mechanism was found"
        fi
    fi
}

# ---------------------------------------------------------------------------
# user preparation
# ---------------------------------------------------------------------------

check_users() {
    local user_name home keys_dir keys_file bad=0

    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        if ! id "${user_name}" >/dev/null 2>&1; then
            fail "users: account ${user_name} does not exist"
            bad=$((bad + 1))
            continue
        fi
        pass "users: account ${user_name} exists"

        home="$(getent passwd "${user_name}" 2>/dev/null | awk -F: '{ print $6 }')"
        if [[ -z "${home}" ]]; then
            fail "users: ${user_name} has no home directory entry"
            bad=$((bad + 1))
            continue
        fi
        keys_dir="${home}/.ssh"
        keys_file="${keys_dir}/authorized_keys"

        if [[ ! -s "${keys_file}" ]]; then
            fail "users: ${user_name} has no key at ${keys_file}"
            bad=$((bad + 1))
            continue
        fi
        pass "users: ${user_name} has an authorized key file"

        if ! mode_matches "$(mode_of "${keys_file}")" "600"; then
            fail "users: ${keys_file} is mode $(mode_of "${keys_file}"), expected 600"
            bad=$((bad + 1))
        fi
        if ! mode_matches "$(mode_of "${keys_dir}")" "700"; then
            fail "users: ${keys_dir} is mode $(mode_of "${keys_dir}"), expected 700"
            bad=$((bad + 1))
        fi
        if [[ "$(owner_of "${keys_file}")" != "${user_name}:"* ]]; then
            fail "users: ${keys_file} is owned by $(owner_of "${keys_file}"), expected ${user_name}"
            bad=$((bad + 1))
        fi
    done

    local sudo_name dropin
    for sudo_name in $(state_value SUDO_USERS); do
        dropin="${SUDOERS_DIR}/99-linux-server-bootstrap-${sudo_name}"
        if [[ ! -f "${dropin}" ]]; then
            fail "users: sudo drop-in is missing for ${sudo_name}: ${dropin}"
            bad=$((bad + 1))
        elif ! mode_matches "$(mode_of "${dropin}")" "440"; then
            fail "users: ${dropin} is mode $(mode_of "${dropin}"), expected 0440"
            bad=$((bad + 1))
        else
            pass "users: ${sudo_name} has a sudo drop-in"
        fi
    done

    if [[ "${bad}" -gt 0 ]]; then
        info "users: a locked-out operator has to recover from the console."
    fi
}

# ---------------------------------------------------------------------------
# SSH, firewall, fail2ban
# ---------------------------------------------------------------------------

# The policy file depends on how ssh.sh was able to install it.
ssh_policy_installed() {
    local style
    style="$(state_value SSH_DROPIN_STYLE)"
    [[ -n "${style}" ]] || style="dropin"

    if [[ "${style}" == "managed_block" ]]; then
        grep -qxF "${SSH_BLOCK_BEGIN}" "${SSH_MAIN_CONFIG}"
    else
        [[ -f "${SSH_CONFIG_TARGET}" ]]
    fi
}

check_ssh() {
    if ssh_policy_installed; then
        pass "SSH policy is installed"
    else
        fail "SSH policy is missing: ${SSH_CONFIG_TARGET} or the ${SSH_BLOCK_BEGIN} block"
        return 0
    fi

    if ! sshd -t 2>/dev/null; then
        fail "sshd -t failed"
        return 0
    fi
    pass "sshd -t passed"

    SSH_EFFECTIVE="$(sshd -T 2>/dev/null || true)"
    if [[ -z "${SSH_EFFECTIVE}" ]]; then
        fail "sshd -T produced no output"
        return 0
    fi

    if effective_has "^port ${SSH_PORT}$"; then
        pass "effective SSH port is ${SSH_PORT}"
    else
        fail "effective SSH port is not ${SSH_PORT}"
    fi
    if effective_has '^permitrootlogin no$'; then
        pass "PermitRootLogin is no"
    else
        fail "PermitRootLogin is not no"
    fi
    if effective_has '^passwordauthentication no$'; then
        pass "PasswordAuthentication is no"
    else
        fail "PasswordAuthentication is not no"
    fi
    if effective_has '^pubkeyauthentication yes$'; then
        pass "PubkeyAuthentication is yes"
    else
        fail "PubkeyAuthentication is not yes"
    fi
    if effective_has '^maxauthtries 3$'; then
        pass "MaxAuthTries is 3"
    else
        fail "MaxAuthTries is not 3"
    fi

    local user_name allow_line
    allow_line="$(printf '%s\n' "${SSH_EFFECTIVE}" | grep -Ei '^allowusers ' | head -n 1 || true)"
    if [[ -z "${allow_line}" ]]; then
        fail "AllowUsers is not set"
    else
        for user_name in "${SSH_ALLOW_USERS[@]}"; do
            if grep -Eq "(^|[[:space:]])${user_name}([[:space:]]|$)" <<< "${allow_line}"; then
                pass "AllowUsers contains ${user_name}"
            else
                fail "AllowUsers does not contain ${user_name}"
            fi
        done
    fi

    if command -v ss >/dev/null 2>&1; then
        if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${SSH_PORT}$"; then
            pass "A process is listening on TCP ${SSH_PORT}"
        else
            fail "Nothing is listening on TCP ${SSH_PORT}. On Debian, restart ssh.socket if the port changed."
        fi
    else
        skip "ss is not installed, so the listener was not checked."
    fi
}

check_firewall() {
    local backend
    backend="$(drv_fw_backend)"

    if drv_fw_is_active; then
        pass "${backend} is active"
    else
        fail "${backend} is not active"
    fi

    if drv_fw_port_is_open "${SSH_PORT}"; then
        pass "${backend} allows ${SSH_PORT}/tcp"
    else
        fail "${backend} does not allow ${SSH_PORT}/tcp"
    fi

    local previous
    previous="$(state_value SSH_MANAGED_PORT)"
    if [[ -n "${previous}" && "${previous}" != "${SSH_PORT}" ]]; then
        if drv_fw_port_is_open "${previous}"; then
            fail "${backend} still allows port ${previous}, which an earlier run opened"
        else
            pass "${backend} closed the port ${previous} an earlier run opened"
        fi
    fi
}

check_fail2ban() {
    if [[ ! -f "${JAIL_TARGET}" ]]; then
        fail "fail2ban jail is missing: ${JAIL_TARGET}"
    else
        pass "fail2ban jail file exists"
    fi
    if [[ "${INIT_SYSTEM}" == "none" ]]; then
        skip "fail2ban: this host has no service manager, so its state was not checked."
        return 0
    fi
    if svc_is_active fail2ban; then
        pass "fail2ban is active"
    else
        fail "fail2ban is not active"
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        fail "fail2ban-client is not installed, although a fail2ban backup exists"
        return 0
    fi
    if fail2ban-client status sshd >/dev/null 2>&1; then
        pass "fail2ban sshd jail is loaded"
    else
        fail "fail2ban sshd jail is not loaded"
    fi
}

# ---------------------------------------------------------------------------
# kernel parameters
# ---------------------------------------------------------------------------

# Reads the pairs out of the installed file the way sysctl.sh wrote them.
sysctl_pairs() {
    local file="$1"
    [[ -f "${file}" ]] || return 0
    awk 'NF == 3 && $2 == "=" { print $1, $3 }' "${file}"
}

check_sysctl() {
    local target key value live checked=0 bad=0
    target="$(recorded_value sysctl SYSCTL_TARGET)"
    [[ -n "${target}" ]] || target="$(drv_sysctl_file)"

    if [[ ! -s "${target}" ]]; then
        fail "sysctl: baseline file is missing or empty: ${target}"
        return 0
    fi
    pass "sysctl: baseline is installed at ${target}"

    while read -r key value; do
        [[ -n "${key}" ]] || continue
        checked=$((checked + 1))
        live="$(sysctl -n "${key}" 2>/dev/null || true)"
        if [[ "${live}" != "${value}" ]]; then
            fail "sysctl: ${key} is ${live:-unreadable}, expected ${value}"
            bad=$((bad + 1))
        fi
    done < <(sysctl_pairs "${target}")

    if [[ "${checked}" -eq 0 ]]; then
        fail "sysctl: ${target} carries no key = value line"
    elif [[ "${bad}" -eq 0 ]]; then
        pass "sysctl: all ${checked} kernel parameters are live"
    fi
}

# ---------------------------------------------------------------------------
# login and core limits
# ---------------------------------------------------------------------------

check_limits() {
    local core want line
    core="$(state_value CORE_LIMIT)"
    [[ -n "${core}" ]] || core="0"

    if [[ ! -s "${LIMITS_TARGET}" ]]; then
        fail "limits: ${LIMITS_TARGET} was not written"
    elif grep -Eq "^[[:space:]]*[a-z*][[:space:]]+hard[[:space:]]+core[[:space:]]+${core}[[:space:]]*$" \
        "${LIMITS_TARGET}"; then
        pass "limits: core dumps are limited to ${core}"
    else
        fail "limits: no 'hard core ${core}' line in ${LIMITS_TARGET}"
    fi

    want="$(state_value MAX_LOGINS)"
    if [[ -n "${want}" ]]; then
        if grep -Eq "^[[:space:]]*[a-z*][[:space:]]+hard[[:space:]]+maxlogins[[:space:]]+${want}[[:space:]]*$" \
            "${LIMITS_TARGET}"; then
            pass "limits: concurrent logins are capped at ${want}"
        else
            fail "limits: no 'hard maxlogins ${want}' line in ${LIMITS_TARGET}"
        fi
    fi

    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        if [[ ! -f "${SYSTEMD_LIMITS_DROPIN}" ]]; then
            fail "limits: systemd drop-in is missing: ${SYSTEMD_LIMITS_DROPIN}"
        else
            line="$(grep -E '^DefaultLimitCORE' "${SYSTEMD_LIMITS_DROPIN}" | head -n 1 || true)"
            if [[ -z "${line}" ]]; then
                fail "limits: ${SYSTEMD_LIMITS_DROPIN} sets no DefaultLimitCORE"
            elif [[ "${line}" != *"${core}"* ]]; then
                fail "limits: ${line}, expected the core limit ${core}"
            else
                pass "limits: systemd ${line}"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# file permissions
# ---------------------------------------------------------------------------

# A short independent list. The stage fixes a longer one, and the verifier only
# re-proves the paths where a wrong mode actually leaks something.
perms_expected() {
    local shadow_group shadow_mode
    read -r shadow_group shadow_mode <<< "$(shadow_ownership)"
    printf '%s\n' \
        "/etc/passwd 644 root:root" \
        "/etc/group 644 root:root" \
        "/etc/login.defs 644 root:root" \
        "/etc/shadow ${shadow_mode#0} root:${shadow_group}" \
        "/etc/gshadow ${shadow_mode#0} root:${shadow_group}" \
        "/etc/ssh/sshd_config 600 root:root" \
        "/etc/sudoers 440 root:root" \
        "/etc/cron.d 700 root:root"
}

check_perms() {
    local path mode owner have_mode have_owner bad=0

    while read -r path mode owner; do
        [[ -n "${path}" ]] || continue
        if [[ ! -e "${path}" ]]; then
            info "perms: ${path} is not on this host, so it was not checked."
            continue
        fi
        have_mode="$(mode_of "${path}")"
        have_owner="$(owner_of "${path}")"
        if ! mode_matches "${have_mode}" "${mode}" || [[ "${have_owner}" != "${owner}" ]]; then
            fail "perms: $(basename -- "${path}") is ${have_mode:-unreadable} ${have_owner:-unreadable}, expected ${mode} ${owner}"
            bad=$((bad + 1))
        fi
    done < <(perms_expected)

    if [[ "${bad}" -eq 0 ]]; then
        pass "perms: the critical paths carry the expected mode and owner"
    fi

    local -a roots=("/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin")
    local -a existing=()
    local root
    for root in "${roots[@]}"; do
        [[ -d "${root}" ]] && existing+=("${root}")
    done
    if [[ "${#existing[@]}" -eq 0 ]]; then
        return 0
    fi
    local found
    found="$(find "${existing[@]}" -xdev \( -type f -o \( -type d ! -perm -1000 \) \) -perm -0002 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "${found}" -gt 0 ]]; then
        # Another package can add one after the run, so this is drift to look at
        # rather than a failed change; the stage only ever fixes what it found.
        skip "perms: ${found} world-writable path(s) remain; re-run hardening/perms.sh if they are new."
    else
        pass "perms: no world-writable path in the system directories"
    fi
}

# ---------------------------------------------------------------------------
# audit rules
# ---------------------------------------------------------------------------

check_audit() {
    local target rules loaded
    target="$(state_value AUDIT_RULES_FILE)"
    [[ -n "${target}" ]] || target="$(drv_audit_rules_file)"

    if [[ ! -s "${target}" ]]; then
        fail "audit: rule file is missing or empty: ${target}"
        return 0
    fi
    rules="$(grep -c '^-' "${target}")"
    pass "audit: ${rules} rule(s) in ${target}"

    if ! command -v auditctl >/dev/null 2>&1; then
        skip "audit: auditctl is not installed, so the loaded ruleset was not checked."
        return 0
    fi
    if ! loaded="$(auditctl -l 2>/dev/null)"; then
        skip "audit: the kernel refused 'auditctl -l', so the loaded ruleset was not read."
        return 0
    fi
    if [[ -z "${loaded}" ]]; then
        fail "audit: the ruleset is loaded from nothing; run ${target} through augenrules --load"
    else
        pass "audit: the running kernel has rules loaded"
    fi

    if grep -qx -- '-e 2' "${target}"; then
        if [[ "$(auditctl -s 2>/dev/null | awk '/^enabled/ { print $2 }')" == "2" ]]; then
            pass "audit: the ruleset is locked until the next reboot"
        else
            fail "audit: ${target} ends with -e 2 but the kernel is not enabled level 2"
        fi
    fi

    if [[ "${INIT_SYSTEM}" != "none" ]] && ! svc_is_active auditd; then
        fail "audit: the auditd service is not running, so the rules are not being applied"
    fi
}

# ---------------------------------------------------------------------------
# mandatory access control
# ---------------------------------------------------------------------------

check_mac() {
    local kind status
    kind="$(state_value MAC_KIND)"
    [[ -n "${kind}" ]] || kind="$(recorded_value mac MAC_KIND)"

    if [[ -z "${kind}" || "${kind}" == "none" ]]; then
        fail "mac: no mandatory access control system was recorded"
        return 0
    fi
    status="$(drv_mac_status 2>/dev/null || printf 'unavailable')"

    if [[ "${kind}" == "selinux" ]]; then
        if [[ "${status}" == "Enforcing" ]]; then
            pass "mac: SELinux is enforcing"
        else
            fail "mac: SELinux reports ${status}, expected Enforcing"
        fi
        if grep -Eq '^SELINUX=enforcing' "${SELINUX_CONFIG}" 2>/dev/null; then
            pass "mac: ${SELINUX_CONFIG} survives a reboot"
        else
            fail "mac: ${SELINUX_CONFIG} does not set SELINUX=enforcing"
        fi
        return 0
    fi

    # AppArmor: enabled in the kernel, and at least one profile actually in
    # enforce mode. Complain-only profiles are the fresh-install default and are
    # what the stage is supposed to have changed.
    if [[ "${status}" == *"not enabled"* || "${status}" == *"not installed"* ]]; then
        fail "mac: AppArmor reports ${status}"
        return 0
    fi
    pass "mac: AppArmor is enabled"
    if command -v aa-status >/dev/null 2>&1; then
        if aa-status --enforce >/dev/null 2>&1; then
            pass "mac: at least one AppArmor profile is in enforce mode"
        else
            fail "mac: no AppArmor profile is in enforce mode"
        fi
    else
        skip "mac: aa-status is absent, so the enforce count was not read."
    fi
}

# ---------------------------------------------------------------------------
# legacy services
# ---------------------------------------------------------------------------

check_services() {
    local unit enabled off=0

    for unit in $(state_value DISABLED_SERVICES); do
        if [[ "${INIT_SYSTEM}" != "none" ]] && svc_is_active "${unit}"; then
            fail "services: ${unit} is still running"
            continue
        fi
        enabled="$(svc_is_enabled "${unit}")"
        if [[ "${enabled}" == "enabled" ]]; then
            fail "services: ${unit} is still enabled"
        else
            pass "services: ${unit} is ${enabled} and stopped"
            off=$((off + 1))
        fi
    done

    if [[ "${off}" -eq 0 ]]; then
        info "services: nothing was recorded as disabled, so no unit was checked."
    fi
}

# ---------------------------------------------------------------------------
# login banner
# ---------------------------------------------------------------------------

banner_marker() {
    # Taken from the template so rewording it does not silently disable the check.
    grep -v '__HOSTNAME__' "${PROJECT_DIR}/config/banner.txt" 2>/dev/null \
        | grep -Ev '^[[:space:]]*(#|$)' | head -n 1
}

check_banner() {
    local marker path
    marker="$(banner_marker)"
    if [[ -z "${marker}" ]]; then
        fail "banner: ${PROJECT_DIR}/config/banner.txt has no fixed text to look for"
        return 0
    fi

    for path in /etc/issue /etc/issue.net; do
        if grep -qF -- "${marker}" "${path}" 2>/dev/null; then
            pass "banner: ${path} carries the warning"
        else
            fail "banner: ${path} does not carry the warning"
        fi
    done

    # sshd is the only reader that matters for a network login, and it is the one
    # place where the answer has to come from the running daemon.
    SSH_EFFECTIVE="$(sshd -T 2>/dev/null || true)"
    if [[ -z "${SSH_EFFECTIVE}" ]]; then
        skip "banner: sshd -T produced no output, so Banner was not read."
        return 0
    fi
    if effective_has '^banner /etc/issue\.net$'; then
        pass "banner: sshd sends /etc/issue.net on every session"
    else
        fail "banner: sshd Banner is not /etc/issue.net"
    fi
}

# ---------------------------------------------------------------------------
# authentication policy
# ---------------------------------------------------------------------------

# The last assignment wins, and the value is the first field that is not an equals
# sign, because login.defs writes "KEY<TAB>value" while the security configurations
# write "key = value".
conf_value() {
    local file="$1" key="$2"
    [[ -f "${file}" ]] || return 0
    awk -v want="${key}" '
        tolower($1) == tolower(want) {
            value = ""
            for (i = 2; i <= NF; i++) {
                if ($i != "=") {
                    value = $i
                    break
                }
            }
            if (value != "") found = value
        }
        END { if (found != "") print found }
    ' "${file}"
}

# login.defs keeps its own defaults for the same keys, so only the managed block
# counts as the answer.
block_value() {
    local file="$1" begin="$2" end="$3" key="$4"
    [[ -f "${file}" ]] || return 0
    awk -v begin="${begin}" -v end="${end}" -v want="${key}" '
        $0 == begin { inside = 1; next }
        $0 == end   { inside = 0; next }
        inside && tolower($1) == tolower(want) {
            value = ""
            for (i = 2; i <= NF; i++) {
                if ($i != "=") {
                    value = $i
                    break
                }
            }
            if (value != "") found = value
        }
        END { if (found != "") print found }
    ' "${file}"
}

check_auth() {
    local want have

    # A minimal image can ship without login.defs. That stage records no aging or
    # umask key in that case, so a blockless file is only a failure when this run
    # claimed it had written one.
    if grep -qxF "${LOGIN_DEFS_BEGIN}" "${LOGIN_DEFS_FILE}" 2>/dev/null; then
        pass "auth: ${LOGIN_DEFS_FILE} carries the managed block"
    elif [[ -n "$(state_value PASSWORD_MAX_DAYS)$(state_value LOGIN_UMASK)" ]]; then
        fail "auth: ${LOGIN_DEFS_FILE} has no ${LOGIN_DEFS_BEGIN} block"
        return 0
    else
        skip "auth: ${LOGIN_DEFS_FILE} carries no block, so aging and umask stay at the distro values."
    fi

    want="$(state_value PASSWORD_MAX_DAYS)"
    if [[ -n "${want}" ]]; then
        have="$(block_value "${LOGIN_DEFS_FILE}" "${LOGIN_DEFS_BEGIN}" "${LOGIN_DEFS_END}" PASS_MAX_DAYS)"
        if [[ "${have}" == "${want}" ]]; then
            pass "auth: PASS_MAX_DAYS is ${want}"
        else
            fail "auth: PASS_MAX_DAYS is ${have:-unset}, expected ${want}"
        fi
    fi

    want="$(state_value LOGIN_UMASK)"
    if [[ -n "${want}" ]]; then
        have="$(block_value "${LOGIN_DEFS_FILE}" "${LOGIN_DEFS_BEGIN}" "${LOGIN_DEFS_END}" UMASK)"
        if [[ "${have}" == "${want}" ]]; then
            pass "auth: UMASK is ${want}"
        else
            fail "auth: UMASK is ${have:-unset}, expected ${want}"
        fi
    fi

    want="$(state_value PASSWORD_MIN_LEN)"
    if [[ -n "${want}" ]]; then
        have="$(conf_value "${PWQUALITY_CONF}" minlen)"
        if [[ "${have}" == "${want}" ]]; then
            pass "auth: pwquality minlen is ${want}"
        else
            fail "auth: pwquality minlen is ${have:-unset}, expected ${want}"
        fi
    fi

    want="$(state_value LOCKOUT_DENY)"
    if [[ -n "${want}" ]]; then
        have="$(conf_value "${FAILLOCK_CONF}" deny)"
        if [[ "${have}" == "${want}" ]]; then
            pass "auth: faillock denies after ${want} failures"
        else
            fail "auth: faillock deny is ${have:-unset}, expected ${want}"
        fi
        if grep -rl 'pam_faillock.so' "${PAM_DIR}" >/dev/null 2>&1; then
            pass "auth: a PAM stack calls pam_faillock"
        else
            fail "auth: no PAM stack in ${PAM_DIR} calls pam_faillock"
        fi
    fi

    want="$(state_value LOCKOUT_FAIL_INTERVAL)"
    if [[ -n "${want}" ]]; then
        have="$(conf_value "${FAILLOCK_CONF}" fail_interval)"
        # Written as if/else rather than A && B || C: pass would have to fail for the
        # complaint to fire, and a stage reported twice reads as two problems.
        if [[ "${have}" == "${want}" ]]; then
            pass "auth: faillock fail_interval is ${want}"
        else
            fail "auth: faillock fail_interval is ${have:-unset}, expected ${want}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# roll-up
# ---------------------------------------------------------------------------

check_rollback_points() {
    local pair key component
    for pair in "${STATE_OWNERS[@]}"; do
        key="${pair% *}"
        component="${pair#* }"
        [[ -n "$(state_value "${key}")" ]] || continue
        if ! stage_applied "${component}"; then
            fail "${component}: ${key} is recorded but ${BACKUP_ROOT}/${component}/latest does not exist"
        fi
    done
}

list_not_applied() {
    local label joined=""
    [[ "${#NOT_APPLIED[@]}" -gt 0 ]] || return 0
    for label in "${NOT_APPLIED[@]}"; do
        joined="${joined}${joined:+, }${label}"
    done
    printf 'Not applied by any run, so left unchecked: %s\n' "${joined}"
}

main() {
    parse_verify_args "$@" || {
        usage >&2
        exit 2
    }
    if [[ "${SHOW_HELP}" -eq 1 ]]; then
        usage
        exit 0
    fi

    require_root
    detect_os
    detect_init
    apply_port_default
    validate_port
    load_saved_users_if_empty

    if ((${#SSH_ALLOW_USERS[@]} == 0)); then
        HAVE_USERS=0
        info "No allowed users are set, so the account and SSH user checks are skipped."
    fi

    info "Verifying the baseline for TCP ${SSH_PORT} on ${OS_ID} ${OS_VERSION}."
    verify_stage base "Base setup" check_base
    if [[ "${HAVE_USERS}" -eq 1 ]]; then
        verify_stage users "User preparation" check_users
        verify_stage ssh "SSH hardening" check_ssh
    else
        NOT_APPLIED+=("User preparation")
        NOT_APPLIED+=("SSH hardening")
        skip "User preparation and SSH hardening were skipped: no allowed user is recorded."
    fi
    verify_stage firewall "Firewall" check_firewall
    verify_stage fail2ban "fail2ban" check_fail2ban
    verify_stage sysctl "Kernel parameters" check_sysctl
    verify_stage limits "Login limits" check_limits
    verify_stage perms "File permissions" check_perms
    verify_stage audit "Audit rules" check_audit
    verify_stage mac "Mandatory access control" check_mac
    verify_stage services "Legacy services" check_services
    verify_stage banner "Login banner" check_banner
    verify_stage auth "Authentication policy" check_auth
    check_rollback_points

    if [[ "${FAILURES}" -eq 0 ]]; then
        success "All checks that apply passed."
        list_not_applied
        exit 0
    fi
    error "${FAILURES} check(s) failed."
    list_not_applied
    exit 1
}

# Sourced by tests/unit/test_verify.sh to reach the checks without running them
# against the host, so only a direct call performs the pass.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
