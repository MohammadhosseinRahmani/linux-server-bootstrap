#!/usr/bin/env bash
# Turn off the services that speak in cleartext, and nothing else.
#
# The candidate list comes from the driver because the unit names differ, and the
# stage only touches a unit the host actually has. Printer, scanner and file-share
# daemons are convenient rather than dangerous, so they need --include-optional.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

SERVICE_SCOPE="${SERVICE_SCOPE:-cleartext}"
DISABLED_UNITS=()
ENABLED_BEFORE=()

usage() {
    cat <<EOF
Usage: bash hardening/services.sh [--yes] [--dry-run] [--include-optional]
       bash hardening/services.sh --rollback

Disables and, on systemd, masks the legacy units this family is known for:
cleartext remote shells, xinetd-borne services, and old name services. A unit the
host does not have is skipped.

--include-optional  also cover printing, avahi, NFS and rpcbind. These are
                    features, not vulnerabilities, so they are left alone unless
                    asked for.

Backups: ${BACKUP_ROOT}/services/<timestamp>
EOF
}

parse_services_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --include-optional)
                SERVICE_SCOPE="all"
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

collect_present_units() {
    local candidate
    while IFS= read -r candidate; do
        [[ -z "${candidate}" ]] && continue
        if svc_unit_exists "${candidate}"; then
            DISABLED_UNITS+=("${candidate}")
        fi
    done < <(drv_legacy_services "${SERVICE_SCOPE}")
}

record_current_state() {
    local unit state
    # A dry run builds no backup tree, so there is no snapshots directory to append to.
    if dry_run; then
        return 0
    fi
    for unit in "${DISABLED_UNITS[@]}"; do
        state="$(svc_is_enabled "${unit}")"
        printf '%s %s\n' "${unit}" "${state}" >> "${BACKUP_DIR}/snapshots/units.txt"
        if [[ "${state}" == "enabled" ]]; then
            ENABLED_BEFORE+=("${unit}")
        fi
    done
}

disable_units() {
    local unit
    for unit in "${DISABLED_UNITS[@]}"; do
        info "Disabling ${unit}"
        svc_disable_now "${unit}" || warn "Could not disable ${unit}."
        svc_mask "${unit}"
    done
}

verify_units_off() {
    local unit still_on=0
    for unit in "${DISABLED_UNITS[@]}"; do
        if svc_is_active "${unit}"; then
            error "${unit} is still active."
            still_on=$((still_on + 1))
        fi
    done
    if [[ "${still_on}" -gt 0 ]]; then
        return 1
    fi
    success "None of the ${#DISABLED_UNITS[@]} legacy unit(s) is running."
}

restore_units() {
    local dir="$1"
    local record="${dir}/snapshots/units.txt"
    if [[ ! -f "${record}" ]]; then
        warn "No unit state snapshot in ${dir}, so nothing was re-enabled."
        return 0
    fi

    local unit state
    while read -r unit state; do
        [[ -z "${unit}" ]] && continue
        svc_unmask "${unit}"
        if [[ "${state}" == "enabled" ]]; then
            info "Re-enabling ${unit}"
            svc_enable_now "${unit}" || warn "Could not re-enable ${unit}."
        fi
    done < "${record}"
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir services)" || return 1
    fi

    warn "Restoring service states recorded in ${dir}"
    restore_units "${dir}"
    finish_rollback_pointer services
    success "Service rollback finished."
}

plan_text() {
    printf '%s\n' "Service hardening will:"
    if [[ "${#DISABLED_UNITS[@]}" -eq 0 ]]; then
        printf '%s\n' "  - nothing: none of the legacy units is present"
    else
        printf '%s\n' "  - disable and mask: ${DISABLED_UNITS[*]}"
    fi
    printf '%s\n' "  - record which units were enabled so a rollback puts them back"
}

apply_services() {
    collect_present_units
    if [[ "${#DISABLED_UNITS[@]}" -eq 0 ]]; then
        success "No legacy service unit from the ${SERVICE_SCOPE} list is installed."
        return 0
    fi

    plan_text
    confirm "Disable these services?" || return 1

    require_init_tools || return 1

    backup_begin services
    record_current_state
    record_kv SERVICE_SCOPE "${SERVICE_SCOPE}"

    arm_rollback
    disable_units

    if dry_run; then
        info "Dry run: skipping the running-service proof."
        disarm_rollback
        success "Service plan is complete."
        return 0
    fi

    if ! verify_units_off; then
        error "Some services are still running. Restoring the recorded states."
        rollback_component
        exit 1
    fi

    state_set DISABLED_SERVICES "${DISABLED_UNITS[*]}"
    save_state
    disarm_rollback
    success "Service hardening completed."
    if [[ "${SERVICE_SCOPE}" == "cleartext" ]]; then
        info "Pass --include-optional to also consider printing, avahi, NFS and rpcbind."
    fi
}

main() {
    parse_services_args "$@" || {
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
        confirm "Roll back the latest service backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_services
}

main "$@"
