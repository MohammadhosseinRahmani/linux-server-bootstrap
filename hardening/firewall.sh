#!/usr/bin/env bash
# Open the SSH port, deny other inbound traffic, and restore the previous state
# if any step fails.
#
# Everything distribution-specific lives in lib/drivers/. This stage calls the
# drv_fw_* contract only, so adding a family does not touch this file.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

usage() {
    cat <<EOF
Usage: bash hardening/firewall.sh [--port N] [--yes]
       bash hardening/firewall.sh --rollback
       bash hardening/firewall.sh --dry-run

Installs the firewall backend for this distribution, allows the SSH port, and
leaves other inbound traffic denied. The backend is chosen by the loaded driver:
ufw on Debian-family, firewalld on RPM-family and SUSE.

Backups: ${BACKUP_ROOT}/firewall/<timestamp>
EOF
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir firewall)" || return 1
    fi

    warn "Rolling back firewall configuration from ${dir}"
    rollback_dir "${dir}" || return 1
    drv_fw_restore_runtime "${dir}" || true
    finish_rollback_pointer firewall
    success "Firewall rollback finished."
}

apply_firewall() {
    local backend
    backend="$(drv_fw_backend)"
    info "Firewall backend is ${backend}."

    cat <<EOF
Firewall hardening will:
  - allow TCP ${SSH_PORT} through ${backend}
  - deny other inbound connections
  - keep outbound connections allowed
  - back up the current firewall under ${BACKUP_ROOT}/firewall
EOF
    confirm "Apply firewall hardening?" || return 1

    backup_begin firewall
    backup_file "${STATE_FILE}"

    local path
    while read -r path; do
        [[ -z "${path}" ]] && continue
        backup_tree "${path}"
    done < <(drv_fw_backup_paths)

    arm_rollback

    drv_fw_install || return 1
    drv_fw_record_state
    save_snapshot firewall-status-before.txt drv_fw_status_text

    # A live session on another port must not be cut off, so that port stays open
    # and the operator closes it with a second run after reconnecting.
    local extra
    extra="$(extra_session_port)"
    if [[ -n "${extra}" ]]; then
        warn "This session uses port ${extra}, so that port stays open."
        warn "Reconnect on port ${SSH_PORT}, then run the firewall script again to close port ${extra}."
    fi

    drv_fw_apply_port "${SSH_PORT}" "${extra}"
    drv_fw_deny_others
    drv_fw_enable

    save_state
    disarm_rollback
    success "Firewall hardening completed with ${backend}."
    if ! dry_run; then
        drv_fw_status_text || warn "Could not print the ${backend} status."
    fi
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
    detect_init

    if [[ "${ACTION}" == "rollback" ]]; then
        confirm "Roll back the latest firewall backup?" || exit 1
        rollback_component
        exit 0
    fi

    require_init_tools || return 1
    apply_port_default
    validate_port
    apply_firewall
}

main "$@"
