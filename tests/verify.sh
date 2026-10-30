#!/usr/bin/env bash
# Read-only checks for a server after bootstrap.
# Exits 0 when every check passes.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

FAILURES=0
SSH_DROPIN="/etc/ssh/sshd_config.d/00-linux-server-bootstrap.conf"
JAIL_TARGET="/etc/fail2ban/jail.d/00-linux-server-bootstrap.conf"

usage() {
    cat <<EOF
Usage: bash tests/verify.sh [--user NAME...] [--port N]

Reads ${STATE_FILE} when --user or --port is omitted.
EOF
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

check_firewall() {
    if [[ "${OS_FAMILY}" == "debian" ]]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | head -n 1 | grep -q 'Status: active'; then
            pass "ufw is active"
        else
            fail "ufw is not active"
        fi
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "${SSH_PORT}/tcp"; then
            pass "ufw allows ${SSH_PORT}/tcp"
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
    local component
    for component in ssh firewall fail2ban; do
        if [[ -L "${BACKUP_ROOT}/${component}/latest" ]]; then
            pass "Backup exists for ${component}"
        else
            fail "No backup symlink at ${BACKUP_ROOT}/${component}/latest"
        fi
    done
}

main() {
    parse_standard_args "$@" || {
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
    check_firewall
    check_fail2ban
    check_backups

    if [[ "${FAILURES}" -eq 0 ]]; then
        success "All checks passed."
        exit 0
    fi
    error "${FAILURES} check(s) failed."
    exit 1
}

main "$@"
