#!/usr/bin/env bash
# Install fail2ban and enable an SSH jail.
# Debian-family bans through ufw. RPM-family bans through firewalld.
# RPM installs enable EPEL when the fail2ban package is not in the base repos.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

JAIL_TEMPLATE="${PROJECT_DIR}/config/fail2ban-sshd.conf"
JAIL_TARGET="/etc/fail2ban/jail.d/00-linux-server-bootstrap.conf"

usage() {
    cat <<EOF
Usage: bash hardening/fail2ban.sh [--port N] [--yes]
       bash hardening/fail2ban.sh --rollback

Enables the sshd jail: 3 failures in 10 minutes, 1 hour ban.
Backups: ${BACKUP_ROOT}/fail2ban/<timestamp>
EOF
}

install_epel_if_needed() {
    if [[ "${OS_FAMILY}" != "rhel" || "${OS_ID}" == "fedora" || "${OS_ID}" == "amzn" ]]; then
        return 0
    fi
    if rpm -q epel-release >/dev/null 2>&1; then
        return 0
    fi

    info "Installing EPEL so fail2ban is available..."
    if pkg_try_install epel-release; then
        return 0
    fi

    local major
    major="$(rpm -E %rhel 2>/dev/null || true)"
    if [[ -z "${major}" || "${major}" == "%rhel" ]]; then
        error "Could not detect the EL major version for EPEL."
        return 1
    fi
    pkg_try_install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm"
}

install_fail2ban_package() {
    if pkg_try_install fail2ban; then
        return 0
    fi
    install_epel_if_needed || return 1
    pkg_try_install fail2ban
}

render_jail() {
    local dest="$1"
    local action="$2"
    awk -v port="${SSH_PORT}" -v action="${action}" '
        {
            gsub("__SSH_PORT__", port)
            if ($0 ~ /^banaction = /) {
                if (action != "") {
                    print "banaction = " action
                }
                next
            }
            print
        }
    ' "${JAIL_TEMPLATE}" > "${dest}"
}

fail2ban_was_active() {
    systemctl is-active --quiet fail2ban
}

rollback_component() {
    trap - ERR
    if [[ "${ROLLBACK_DONE}" -eq 1 ]]; then
        return 0
    fi
    ROLLBACK_DONE=1

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir fail2ban)" || return 1
    fi

    warn "Rolling back fail2ban configuration from ${dir}"
    rollback_dir "${dir}" || return 1

    # shellcheck disable=SC1091
    source "${dir}/manifest.env"
    if [[ "${FAIL2BAN_ACTIVE:-0}" == "1" ]]; then
        systemctl enable --now fail2ban || error "Could not start fail2ban after restore."
        fail2ban-client reload || true
    elif unit_exists fail2ban.service; then
        systemctl disable --now fail2ban || true
    fi

    finish_rollback_pointer fail2ban
    success "fail2ban rollback finished."
}

apply_fail2ban() {
    cat <<EOF
fail2ban will:
  - enable the sshd jail on port ${SSH_PORT}
  - ban an address after 3 failures in 10 minutes
  - keep the ban for 1 hour
  - back up the current jail under ${BACKUP_ROOT}/fail2ban
EOF
    confirm "Apply fail2ban?" || return 1

    if [[ ! -f "${JAIL_TEMPLATE}" ]]; then
        error "Template not found: ${JAIL_TEMPLATE}"
        return 1
    fi

    install_fail2ban_package

    local was_active=0
    if fail2ban_was_active; then
        was_active=1
    fi

    backup_begin fail2ban
    record_kv FAIL2BAN_ACTIVE "${was_active}"
    backup_file "${JAIL_TARGET}"
    backup_file /etc/fail2ban/jail.local
    backup_file "${STATE_FILE}"
    if command -v fail2ban-client >/dev/null 2>&1; then
        save_snapshot fail2ban-status-before.txt fail2ban-client status
    fi

    local action="" tmp
    if [[ "${OS_FAMILY}" == "debian" ]]; then
        action="ufw"
    else
        action="firewallcmd-rich-rules"
    fi
    if [[ ! -f "/etc/fail2ban/action.d/${action}.conf" ]]; then
        warn "fail2ban action ${action} is missing. The package default ban action will be used."
        action=""
    fi
    tmp="$(mktemp)"
    render_jail "${tmp}" "${action}"

    arm_rollback
    mkdir -p -- /etc/fail2ban/jail.d
    install -m 0644 -o root -g root "${tmp}" "${JAIL_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${JAIL_TARGET}"

    systemctl enable --now fail2ban
    if ! fail2ban-client reload; then
        error "fail2ban rejected the jail. Rolling back."
        rollback_component
        exit 1
    fi
    if ! fail2ban-client status sshd >/dev/null 2>&1; then
        error "The sshd jail is not active. Rolling back."
        rollback_component
        exit 1
    fi

    save_state
    disarm_rollback
    success "fail2ban sshd jail is active."
    fail2ban-client status sshd
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

    if [[ "${ACTION}" == "rollback" ]]; then
        confirm "Roll back the latest fail2ban backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_port_default
    validate_port
    apply_fail2ban
}

main "$@"
