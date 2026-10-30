#!/usr/bin/env bash
# Read-only checks for a server after bootstrap.
# Exits 0 when every check passes.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

FAILURES=0
SKIP_FIREWALL=0
SKIP_FAIL2BAN=0
SSH_DROPIN="/etc/ssh/sshd_config.d/00-linux-server-bootstrap.conf"
JAIL_TARGET="/etc/fail2ban/jail.d/00-linux-server-bootstrap.conf"

usage() {
    cat <<EOF
Usage: bash tests/verify.sh [--user NAME...] [--port N]
       bash tests/verify.sh [--skip-firewall] [--skip-fail2ban]

Reads ${STATE_FILE} when --user or --port is omitted.
Pass --skip-firewall or --skip-fail2ban after a bootstrap run that used them.
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

check() {
    local description="$1"
    shift
    if "$@"; then
        pass "${description}"
    else
        fail "${description}"
    fi
}

effective_has() {
    local pattern="$1"
    printf '%s\n' "${SSH_EFFECTIVE}" | grep -Eiq "${pattern}"
}

check_ssh() {
    if [[ ! -f "${SSH_DROPIN}" ]]; then
        fail "SSH drop-in is missing: ${SSH_DROPIN}"
        return 0
    fi
    pass "SSH drop-in exists"

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
        warn "ss is not installed, so the listener was not checked."
    fi
}

ufw_lists_port() {
    # Match the rule column exactly, so port 22 does not pass on a 222/tcp rule.
    ufw status | awk -v rule="${SSH_PORT}/tcp" '$1 == rule { found = 1 } END { exit found ? 0 : 1 }'
}

check_firewall() {
    if [[ "${OS_FAMILY}" == "debian" ]]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | head -n 1 | grep -q 'Status: active'; then
            pass "ufw is active"
        else
            fail "ufw is not active"
        fi
        if command -v ufw >/dev/null 2>&1 && ufw_lists_port; then
            pass "ufw has a rule for ${SSH_PORT}/tcp"
        else
            fail "ufw does not list ${SSH_PORT}/tcp"
        fi
    else
        if systemctl is-active --quiet firewalld; then
            pass "firewalld is active"
        else
            fail "firewalld is not active"
        fi
        if firewall-cmd --query-port="${SSH_PORT}/tcp" >/dev/null 2>&1; then
            pass "firewalld allows ${SSH_PORT}/tcp"
        elif [[ "${SSH_PORT}" == "22" ]] && firewall-cmd --query-service=ssh >/dev/null 2>&1; then
            pass "firewalld allows the ssh service"
        else
            fail "firewalld does not allow ${SSH_PORT}/tcp"
        fi
    fi
}

check_fail2ban() {
    if [[ ! -f "${JAIL_TARGET}" ]]; then
        fail "fail2ban jail is missing: ${JAIL_TARGET}"
    else
        pass "fail2ban jail file exists"
    fi
    if systemctl is-active --quiet fail2ban; then
        pass "fail2ban is active"
    else
        fail "fail2ban is not active"
    fi
    if fail2ban-client status sshd >/dev/null 2>&1; then
        pass "fail2ban sshd jail is loaded"
    else
        fail "fail2ban sshd jail is not loaded"
    fi
}

check_backups() {
    local -a components=(ssh)
    if [[ "${SKIP_FIREWALL}" -eq 0 ]]; then
        components+=(firewall)
    fi
    if [[ "${SKIP_FAIL2BAN}" -eq 0 ]]; then
        components+=(fail2ban)
    fi

    local component
    for component in "${components[@]}"; do
        if [[ -L "${BACKUP_ROOT}/${component}/latest" ]]; then
            pass "Backup exists for ${component}"
        else
            fail "No backup symlink at ${BACKUP_ROOT}/${component}/latest"
        fi
    done
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
    apply_port_default
    validate_port
    load_saved_users_if_empty

    if ((${#SSH_ALLOW_USERS[@]} == 0)); then
        error "No allowed users were passed and ${STATE_FILE} has none."
        exit 2
    fi

    info "Verifying SSH port ${SSH_PORT} for: ${SSH_ALLOW_USERS[*]}"
    check_ssh
    if [[ "${SKIP_FIREWALL}" -eq 0 ]]; then
        check_firewall
    else
        warn "Not checking the firewall (--skip-firewall)."
    fi
    if [[ "${SKIP_FAIL2BAN}" -eq 0 ]]; then
        check_fail2ban
    else
        warn "Not checking fail2ban (--skip-fail2ban)."
    fi
    check_backups

    if [[ "${FAILURES}" -eq 0 ]]; then
        success "All checks passed."
        exit 0
    fi
    error "${FAILURES} check(s) failed."
    exit 1
}

main "$@"
