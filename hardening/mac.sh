#!/usr/bin/env bash
# Put the mandatory access control system this family uses into enforcing mode.
#
# Which system that is, and how it is switched, belongs to the driver: EL answers
# to getenforce and /etc/selinux/config, Debian and Ubuntu to AppArmor profiles,
# and SUSE can be either. A Disabled SELinux is deliberately not switched on
# here, because that needs a relabel and a reboot.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

SELINUX_CONFIG="${SELINUX_CONFIG:-/etc/selinux/config}"
APPARMOR_PROFILE_DIR="${APPARMOR_PROFILE_DIR:-/etc/apparmor.d}"
MAC_KIND=""
MAC_PREVIOUS=""
INSTALL_MAC="${INSTALL_MAC:-0}"

usage() {
    cat <<EOF
Usage: bash hardening/mac.sh [--yes] [--dry-run] [--install]
       bash hardening/mac.sh --rollback

Enforces the mandatory access control system detected for this family:
SELinux through setenforce plus ${SELINUX_CONFIG}, or AppArmor through aa-enforce
over ${APPARMOR_PROFILE_DIR}.

--install  install the MAC userspace first when nothing is present. On an EL
           host that still leaves the kernel side to a relabel and reboot, so a
           Disabled SELinux is reported rather than changed.

Backups: ${BACKUP_ROOT}/mac/<timestamp>
EOF
}

parse_mac_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install)
                INSTALL_MAC=1
                shift
                ;;
            --yes|--dry-run|--rollback|-h|--help|--user|--port)
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

backup_mac_paths() {
    case "${MAC_KIND}" in
        selinux)
            backup_file "${SELINUX_CONFIG}"
            ;;
        apparmor)
            backup_tree "${APPARMOR_PROFILE_DIR}"
            ;;
    esac
}

enforce_count_line() {
    aa-status 2>/dev/null | awk '/profiles are in enforce mode/ { print $1; exit }'
}

loaded_count_line() {
    aa-status 2>/dev/null | awk '/profiles are loaded/ { print $1; exit }'
}

verify_mac() {
    case "${MAC_KIND}" in
        selinux)
            local now
            now="$(getenforce 2>/dev/null || true)"
            if [[ "${now}" == "Enforcing" ]]; then
                success "SELinux is enforcing."
                return 0
            fi
            error "SELinux reports ${now:-nothing}, expected Enforcing."
            return 1
            ;;
        apparmor)
            if ! command -v aa-status >/dev/null 2>&1; then
                warn "aa-status is not installed, so the profile modes were not verified."
                return 0
            fi
            local loaded enforce
            loaded="$(loaded_count_line)"
            enforce="$(enforce_count_line)"
            if [[ -z "${loaded}" || -z "${enforce}" ]]; then
                warn "aa-status did not report profile counts, so the modes were not verified."
                return 0
            fi
            if [[ "${enforce}" -eq "${loaded}" ]]; then
                success "All ${loaded} AppArmor profiles are in enforce mode."
                return 0
            fi
            if [[ "${enforce}" -gt 0 ]]; then
                warn "${enforce} of ${loaded} AppArmor profiles enforce; the rest refused to load."
                return 0
            fi
            error "No AppArmor profile is in enforce mode."
            return 1
            ;;
    esac
    error "Unknown mandatory access control system: ${MAC_KIND}"
    return 1
}

restore_previous_mode() {
    if [[ "${MAC_KIND}" != "selinux" || -z "${MAC_PREVIOUS}" ]]; then
        return 0
    fi
    if [[ "${MAC_PREVIOUS}" == "Permissive" ]]; then
        run_cmd setenforce 0
        info "SELinux returned to permissive, as it was before the run."
    fi
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    MAC_KIND="$(drv_mac_name)"
    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir mac)" || return 1
    fi

    warn "Rolling back mandatory access control from ${dir}"
    rollback_dir "${dir}" || return 1
    restore_previous_mode
    finish_rollback_pointer mac
    success "Mandatory access control rollback finished."
    if [[ "${MAC_KIND}" == "selinux" ]]; then
        warn "Restored ${SELINUX_CONFIG}. A label change only applies at boot."
    fi
}

apply_mac() {
    MAC_KIND="$(drv_mac_name)"
    if [[ "${MAC_KIND}" == "none" ]]; then
        if [[ "${INSTALL_MAC}" -eq 0 ]]; then
            error "No mandatory access control system is installed. Pass --install to add it."
            return 1
        fi
        require_pkg_mgr || return 1
        drv_mac_install || return 1
        MAC_KIND="$(drv_mac_name)"
    fi

    if [[ "${MAC_KIND}" == "selinux" ]]; then
        MAC_PREVIOUS="$(getenforce 2>/dev/null || true)"
    fi

    cat <<EOF
Mandatory access control will:
  - enforce the ${MAC_KIND} policy this host uses
  - report ${MAC_PREVIOUS:-n/a} as the mode found before the change
  - back up the policy files it touches under ${BACKUP_ROOT}/mac
EOF
    confirm "Enforce ${MAC_KIND}?" || return 1

    backup_begin mac
    backup_mac_paths
    record_kv MAC_KIND "${MAC_KIND}"
    record_kv MAC_PREVIOUS "${MAC_PREVIOUS:-unknown}"

    arm_rollback
    if ! drv_mac_enforce; then
        if dry_run; then
            warn "Dry run: this host cannot report an enforceable ${MAC_KIND} policy, so nothing was verified."
            disarm_rollback
            return 0
        fi
        error "The policy could not be enforced. Restoring the backup."
        rollback_component
        exit 1
    fi

    if dry_run; then
        info "Dry run: skipping the enforcement proof."
        disarm_rollback
        success "Mandatory access control plan is complete."
        return 0
    fi

    if ! verify_mac; then
        error "The kernel did not confirm enforcement. Restoring the backup."
        rollback_component
        exit 1
    fi

    state_set MAC_KIND "${MAC_KIND}"
    save_state
    disarm_rollback
    success "Mandatory access control hardening completed."
    info "Current status: $(drv_mac_status 2>/dev/null || printf 'unavailable')"
}

main() {
    parse_mac_args "$@" || {
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
        confirm "Roll back the latest mandatory access control backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_mac
}

main "$@"
