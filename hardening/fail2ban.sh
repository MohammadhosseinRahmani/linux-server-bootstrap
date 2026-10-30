#!/usr/bin/env bash
# Install fail2ban, enable an sshd jail, and roll back if the jail is rejected.
#
# The ban action and any extra repository come from the loaded driver; the log
# backend follows the init system. Adding a distribution does not touch this file.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

JAIL_TEMPLATE="${PROJECT_DIR}/config/fail2ban-sshd.conf"
JAIL_ACTION_DIR="/etc/fail2ban/action.d"

usage() {
    cat <<EOF
Usage: bash hardening/fail2ban.sh [--port N] [--yes]
       bash hardening/fail2ban.sh --rollback
       bash hardening/fail2ban.sh --dry-run

Enables the sshd jail: 3 failures in 10 minutes, 1 hour ban.
The ban action is chosen from the firewall that is actually installed.
Backups: ${BACKUP_ROOT}/fail2ban/<timestamp>
EOF
}

render_jail() {
    local dest="$1"
    local action="$2"
    local backend="$3"
    awk -v port="${SSH_PORT}" -v action="${action}" -v backend="${backend}" '
        {
            gsub("__SSH_PORT__", port)
            gsub("__BAN_BACKEND__", backend)
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

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir fail2ban)" || return 1
    fi

    warn "Rolling back fail2ban configuration from ${dir}"
    rollback_dir "${dir}" || return 1

    # shellcheck disable=SC1091
    source "${dir}/manifest.env"
    if [[ "${FAIL2BAN_ACTIVE:-0}" == "1" ]]; then
        svc_enable_now fail2ban || error "Could not start fail2ban after restore."
        fail2ban-client reload >/dev/null 2>&1 || true
    elif svc_unit_exists fail2ban.service; then
        svc_disable_now fail2ban || true
    fi

    finish_rollback_pointer fail2ban
    success "fail2ban rollback finished."
}

select_ban_action() {
    local action
    action="$(drv_f2b_action)"
    if [[ -z "${action}" ]]; then
        warn "No firewall command is available, so fail2ban keeps its package default ban action."
        printf '\n'
        return 0
    fi
    if [[ ! -f "${JAIL_ACTION_DIR}/${action}.conf" ]]; then
        warn "fail2ban action ${action} is missing. The package default ban action will be used."
        printf '\n'
        return 0
    fi
    printf '%s\n' "${action}"
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

    drv_f2b_prepare_repo || return 1
    drv_pkg_install fail2ban || return 1

    local action backend
    action="$(select_ban_action)"
    backend="$(pick_fail2ban_backend)"
    info "Ban action is ${action:-package default}, log backend is ${backend}."

    local was_active=0
    if svc_is_active fail2ban; then
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

    local tmp
    tmp="$(mktemp)"
    render_jail "${tmp}" "${action}" "${backend}"

    arm_rollback
    run_cmd mkdir -p -- /etc/fail2ban/jail.d
    install_file 0644 "${tmp}" "${JAIL_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${JAIL_TARGET}"

    if dry_run; then
        # The jail file does not exist yet, so reloading or checking the live
        # daemon would describe the untouched host instead of the plan.
        info "Dry run: skipping fail2ban reload and sshd jail proof."
        disarm_rollback
        success "fail2ban hardening plan is complete."
        return 0
    fi

    svc_enable_now fail2ban || return 1
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
    detect_init

    if [[ "${ACTION}" == "rollback" ]]; then
        confirm "Roll back the latest fail2ban backup?" || exit 1
        rollback_component
        exit 0
    fi

    require_init_tools || return 1
    apply_port_default
    validate_port
    apply_fail2ban
}

main "$@"
