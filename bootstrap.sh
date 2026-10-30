#!/usr/bin/env bash
# Run SSH hardening, then the firewall, then fail2ban.
# A failed step stops the run. Earlier steps are left in place and can be
# rolled back on their own, or all together with --rollback.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SKIP_FIREWALL=0
SKIP_FAIL2BAN=0

usage() {
    cat <<EOF
Usage: bash bootstrap.sh --user NAME [--user NAME...] [--port N] [--yes]
       bash bootstrap.sh --rollback

Options:
  --user NAME         Account that may log in with a public key. Repeatable.
  --port N            SSH port. Default: saved port, or 22.
  --yes               Apply without the YES prompt.
  --dry-run           Print what would change without touching the host.
  --skip-firewall     Do not change the firewall.
  --skip-fail2ban     Do not install or change fail2ban.
  --rollback          Restore fail2ban, then the firewall, then SSH.

Supported systems: Debian and Ubuntu family (including non-systemd variants),
RHEL/Rocky/AlmaLinux/Fedora and RPM derivatives, openSUSE Leap and SLES.
Run this on the server as root, after the allowed user has an SSH key.
EOF
}

parse_bootstrap_args() {
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
            --yes|--rollback|--dry-run|-h|--help)
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

run_step() {
    local name="$1"
    shift
    info "Starting ${name}..."
    "$@"
    success "${name} finished."
}

rollback_all() {
    confirm "Roll back fail2ban, the firewall, and SSH?" || return 1
    warn "Rollback order is fail2ban, firewall, then SSH."

    if [[ -L "${BACKUP_ROOT}/fail2ban/latest" ]]; then
        bash "${SCRIPT_DIR}/hardening/fail2ban.sh" --rollback --yes
    else
        warn "No fail2ban backup to restore."
    fi
    if [[ -L "${BACKUP_ROOT}/firewall/latest" ]]; then
        bash "${SCRIPT_DIR}/hardening/firewall.sh" --rollback --yes
    else
        warn "No firewall backup to restore."
    fi
    if [[ -L "${BACKUP_ROOT}/ssh/latest" ]]; then
        bash "${SCRIPT_DIR}/hardening/ssh.sh" --rollback --yes
    else
        warn "No SSH backup to restore."
    fi
    success "Rollback pass finished."
}

apply_all() {
    cat <<EOF
linux-server-bootstrap will:
  - restrict SSH to: ${SSH_ALLOW_USERS[*]}
  - use SSH port: ${SSH_PORT}
  - disable SSH password login and root login
  - deny inbound traffic except the SSH port
  - ban repeated SSH failures with fail2ban
  - store backups in ${BACKUP_ROOT}

Open a second SSH session before you start, and do not close this one
until bash tests/verify.sh succeeds.
EOF
    confirm "Apply the full bootstrap?" || return 1

    local -a users=()
    local user_name
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        users+=(--user "${user_name}")
    done

    # DRY_RUN is not exported, so each stage has to be told to plan only.
    local -a dry_flags=()
    if dry_run; then
        dry_flags=(--dry-run)
        warn "Dry run: no stage will change the host, so verification is skipped."
    fi

    run_step "SSH hardening" \
        bash "${SCRIPT_DIR}/hardening/ssh.sh" --yes "${dry_flags[@]}" --port "${SSH_PORT}" "${users[@]}"

    if [[ "${SKIP_FIREWALL}" -eq 0 ]]; then
        run_step "firewall" \
            bash "${SCRIPT_DIR}/hardening/firewall.sh" --yes "${dry_flags[@]}" --port "${SSH_PORT}"
    else
        warn "Skipping the firewall."
    fi

    if [[ "${SKIP_FAIL2BAN}" -eq 0 ]]; then
        run_step "fail2ban" \
            bash "${SCRIPT_DIR}/hardening/fail2ban.sh" --yes "${dry_flags[@]}" --port "${SSH_PORT}"
    else
        warn "Skipping fail2ban."
    fi

    if dry_run; then
        success "Dry run finished. Nothing was applied."
        return 0
    fi

    local -a verify_args=(--port "${SSH_PORT}" "${users[@]}")
    if [[ "${SKIP_FIREWALL}" -eq 1 ]]; then
        verify_args+=(--skip-firewall)
    fi
    if [[ "${SKIP_FAIL2BAN}" -eq 1 ]]; then
        verify_args+=(--skip-fail2ban)
    fi
    info "Checking the result..."
    bash "${SCRIPT_DIR}/tests/verify.sh" "${verify_args[@]}"
    success "Bootstrap completed."
}

main() {
    parse_bootstrap_args "$@" || {
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
        rollback_all
        exit 0
    fi

    apply_port_default
    validate_port
    require_allow_users
    apply_all
}

main "$@"
