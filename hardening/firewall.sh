#!/usr/bin/env bash
# Allow the SSH port, then deny other inbound traffic.
# Debian-family uses ufw. RPM-family uses firewalld.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

usage() {
    cat <<EOF
Usage: bash hardening/firewall.sh [--port N] [--yes]
       bash hardening/firewall.sh --rollback

Debian-family: install ufw, allow the SSH port, default-deny inbound, allow outbound.
RPM-family: install firewalld and allow the SSH port. The default zone already
rejects unsolicited inbound traffic.

Backups: ${BACKUP_ROOT}/firewall/<timestamp>
EOF
}

ufw_is_active() {
    ufw status 2>/dev/null | awk 'NR == 1 && /Status: active/ { found = 1 } END { exit found ? 0 : 1 }'
}

ufw_has_port() {
    local port="$1"
    ufw status | awk -v port="${port}" '$1 == port "/tcp" { found = 1 } END { exit found ? 0 : 1 }'
}

extra_session_port() {
    local current
    current="$(current_ssh_server_port || true)"
    if [[ -n "${current}" && "${current}" != "${SSH_PORT}" ]]; then
        printf '%s' "${current}"
    fi
}

apply_ufw() {
    info "Installing ufw..."
    pkg_try_install ufw

    local was_active=0
    if ufw_is_active; then
        was_active=1
    fi
    record_kv UFW_ACTIVE "${was_active}"
    record_kv FIREWALLD_ACTIVE 0
    save_snapshot ufw-status-before.txt ufw status verbose

    backup_tree /etc/ufw

    local extra
    extra="$(extra_session_port)"
    allow_ufw_port "${SSH_PORT}" "linux-server-bootstrap ssh"
    if [[ -n "${extra}" ]]; then
        allow_ufw_port "${extra}" "linux-server-bootstrap current session"
        warn "This session uses port ${extra}, so that port stays open."
        warn "Reconnect on port ${SSH_PORT}, then run the firewall script again to close port ${extra}."
    fi

    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    success "ufw is active. Inbound traffic is denied except the allowed SSH port."

    if [[ "${SSH_PORT}" != "22" && "${extra}" != "22" ]] && ufw_has_port 22; then
        ufw --force delete allow 22/tcp || warn "Could not delete the ufw rule for 22/tcp."
        info "Removed the ufw allow rule for 22/tcp."
    fi
    ufw status verbose
}

allow_ufw_port() {
    local port="$1"
    local comment="$2"
    if ufw_has_port "${port}"; then
        info "ufw already allows ${port}/tcp"
        return 0
    fi
    ufw allow "${port}/tcp" comment "${comment}"
}

firewalld_allow_port() {
    local port="$1"
    if [[ "${FIREWALLD_WAS_ACTIVE}" -eq 0 ]]; then
        if ! firewall-offline-cmd --query-port="${port}/tcp"; then
            firewall-offline-cmd --add-port="${port}/tcp"
        fi
        return 0
    fi
    if ! firewall-cmd --query-port="${port}/tcp"; then
        firewall-cmd --add-port="${port}/tcp"
    fi
    if ! firewall-cmd --permanent --query-port="${port}/tcp"; then
        firewall-cmd --permanent --add-port="${port}/tcp"
    fi
}

apply_firewalld() {
    info "Installing firewalld..."
    pkg_try_install firewalld

    FIREWALLD_WAS_ACTIVE=0
    if systemctl is-active --quiet firewalld; then
        FIREWALLD_WAS_ACTIVE=1
    fi
    record_kv UFW_ACTIVE 0
    record_kv FIREWALLD_ACTIVE "${FIREWALLD_WAS_ACTIVE}"
    save_snapshot firewalld-before.txt firewall-cmd --list-all
    backup_tree /etc/firewalld

    local extra
    extra="$(extra_session_port)"
    firewalld_allow_port "${SSH_PORT}"
    if [[ -n "${extra}" ]]; then
        firewalld_allow_port "${extra}"
        warn "This session uses port ${extra}, so that port stays open."
        warn "Reconnect on port ${SSH_PORT}, then run the firewall script again to close port ${extra}."
    fi

    if [[ "${SSH_PORT}" == "22" || "${extra}" == "22" ]]; then
        if [[ "${FIREWALLD_WAS_ACTIVE}" -eq 0 ]]; then
            firewall-offline-cmd --add-service=ssh || true
        else
            firewall-cmd --permanent --add-service=ssh || true
        fi
    elif [[ "${FIREWALLD_WAS_ACTIVE}" -eq 0 ]]; then
        firewall-offline-cmd --remove-service=ssh || true
        firewall-offline-cmd --remove-port=22/tcp || true
    else
        firewall-cmd --permanent --remove-service=ssh || true
        firewall-cmd --permanent --remove-port=22/tcp || true
        firewall-cmd --remove-service=ssh || true
        firewall-cmd --remove-port=22/tcp || true
    fi

    if [[ "${FIREWALLD_WAS_ACTIVE}" -eq 0 ]]; then
        systemctl enable --now firewalld
    else
        firewall-cmd --reload
    fi

    success "firewalld allows ${SSH_PORT}/tcp and rejects other new inbound traffic."
    firewall-cmd --list-all
}

restore_firewall_runtime() {
    local dir="$1"
    # shellcheck disable=SC1091
    source "${dir}/manifest.env"

    if [[ "${OS_FAMILY}" == "debian" ]]; then
        if command -v ufw >/dev/null 2>&1; then
            if [[ "${UFW_ACTIVE:-0}" == "1" ]]; then
                ufw --force enable || error "Could not re-enable ufw after restore."
                ufw reload || true
            else
                ufw --force disable || true
            fi
        fi
    else
        if [[ "${FIREWALLD_ACTIVE:-0}" == "1" ]]; then
            systemctl enable --now firewalld || error "Could not start firewalld after restore."
            firewall-cmd --reload || true
        elif unit_exists firewalld.service; then
            systemctl disable --now firewalld || true
        fi
    fi
}

rollback_component() {
    trap - ERR
    if [[ "${ROLLBACK_DONE}" -eq 1 ]]; then
        return 0
    fi
    ROLLBACK_DONE=1

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir firewall)" || return 1
    fi

    warn "Rolling back firewall configuration from ${dir}"
    rollback_dir "${dir}" || return 1
    restore_firewall_runtime "${dir}" || true
    finish_rollback_pointer firewall
    success "Firewall rollback finished."
}

apply_firewall() {
    cat <<EOF
Firewall hardening will:
  - allow TCP ${SSH_PORT}
  - deny other inbound connections
  - keep outbound connections allowed
  - back up the current firewall under ${BACKUP_ROOT}/firewall
EOF
    confirm "Apply firewall hardening?" || return 1

    backup_begin firewall
    backup_file "${STATE_FILE}"
    arm_rollback

    if [[ "${OS_FAMILY}" == "debian" ]]; then
        apply_ufw
    else
        apply_firewalld
    fi

    save_state
    disarm_rollback
    success "Firewall hardening completed."
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
        confirm "Roll back the latest firewall backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_port_default
    validate_port
    apply_firewall
}

main "$@"
