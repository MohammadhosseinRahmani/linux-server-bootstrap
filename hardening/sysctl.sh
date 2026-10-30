#!/usr/bin/env bash
# Load the kernel parameter baseline, prove the running values, and roll back.
#
# The template is trimmed to the keys this kernel actually exposes, because a
# minimal image, a container with a read-only /proc/sys, and a full server do
# not present the same parameter set. Values are read back from /proc/sys after
# the load, so a parameter that was silently ignored fails the run instead of
# reporting success.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

SYSCTL_SOURCE="${PROJECT_DIR}/config/sysctl.conf"
SYSCTL_TARGET=""
SYSCTL_KEYS=()
SYSCTL_VALUES=()
DISABLE_ROUTING="${DISABLE_ROUTING:-0}"

# A host that routes today is usually a router on purpose. Turning that off over
# SSH can strand every machine behind it, so it needs an explicit opt-in.
ROUTING_KEYS=(net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding)

usage() {
    cat <<EOF
Usage: bash hardening/sysctl.sh [--yes] [--dry-run] [--disable-routing]
       bash hardening/sysctl.sh --rollback

Installs ${SYSCTL_SOURCE} into the sysctl drop-in directory the driver picks for
this family and loads it with sysctl -p.

Keys this kernel does not expose are dropped from the file rather than written
and ignored. Routing keys are only switched off with --disable-routing.

Backups: ${BACKUP_ROOT}/sysctl/<timestamp>
EOF
}

parse_sysctl_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --disable-routing)
                DISABLE_ROUTING=1
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

key_is_routing() {
    local key="$1" item
    for item in "${ROUTING_KEYS[@]}"; do
        if [[ "${key}" == "${item}" ]]; then
            return 0
        fi
    done
    return 1
}

proc_path_for() {
    local key="$1"
    printf '/proc/sys/%s\n' "${key//./\/}"
}

live_value() {
    local path
    path="$(proc_path_for "$1")"
    [[ -r "${path}" ]] || return 1
    awk '{ print $1; exit }' "${path}"
}

# Reads the template and keeps only the lines this host can accept.
collect_supported_keys() {
    if [[ ! -f "${SYSCTL_SOURCE}" ]]; then
        error "Template not found: ${SYSCTL_SOURCE}"
        return 1
    fi

    local line key value path current skipped_routing=0 unknown=0
    while IFS= read -r line; do
        [[ "${line}" =~ ^([a-zA-Z0-9_.]+)[[:space:]]*=[[:space:]]*([0-9a-zA-Z_-]+)[[:space:]]*$ ]] || continue
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        path="$(proc_path_for "${key}")"

        if [[ ! -e "${path}" ]]; then
            unknown=$((unknown + 1))
            continue
        fi
        if key_is_routing "${key}" && [[ "${DISABLE_ROUTING}" -eq 0 ]]; then
            current="$(live_value "${key}" || true)"
            if [[ -n "${current}" && "${current}" != "0" ]]; then
                skipped_routing=$((skipped_routing + 1))
                continue
            fi
        fi

        SYSCTL_KEYS+=("${key}")
        SYSCTL_VALUES+=("${value}")
    done < "${SYSCTL_SOURCE}"

    if [[ "${#SYSCTL_KEYS[@]}" -eq 0 ]]; then
        error "The template produced no parameters for this host."
        return 1
    fi

    if [[ "${unknown}" -gt 0 ]]; then
        info "Skipped ${unknown} key(s) this kernel does not expose."
    fi
    if [[ "${skipped_routing}" -gt 0 ]]; then
        warn "Left ${skipped_routing} routing key(s) alone because this host forwards. Use --disable-routing to override."
    fi
}

write_target() {
    local tmp index
    tmp="$(mktemp)"
    {
        printf '%s\n' "# Installed by linux-server-bootstrap hardening/sysctl.sh"
        for index in "${!SYSCTL_KEYS[@]}"; do
            printf '%s = %s\n' "${SYSCTL_KEYS["${index}"]}" "${SYSCTL_VALUES["${index}"]}"
        done
    } > "${tmp}"

    run_cmd mkdir -p -- "$(drv_sysctl_dir)"
    install_file 0644 "${tmp}" "${SYSCTL_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${SYSCTL_TARGET}"
}

# The values the kernel holds right now are the only correct rollback target.
snapshot_live_values() {
    local index key value path
    for index in "${!SYSCTL_KEYS[@]}"; do
        key="${SYSCTL_KEYS["${index}"]}"
        path="$(proc_path_for "${key}")"
        if [[ ! -e "${path}" ]]; then
            continue
        fi
        value="$(live_value "${key}" || true)"
        if [[ -z "${value}" ]]; then
            continue
        fi
        printf '%s %s\n' "${key}" "${value}" >> "${BACKUP_DIR}/snapshots/values.txt"
    done
}

load_parameters() {
    info "Loading kernel parameters..."
    if ! run_cmd sysctl -p "${SYSCTL_TARGET}"; then
        error "sysctl refused the parameters."
        return 1
    fi
}

verify_live_values() {
    local index key want have
    local -a mismatched=()
    for index in "${!SYSCTL_KEYS[@]}"; do
        key="${SYSCTL_KEYS["${index}"]}"
        want="${SYSCTL_VALUES["${index}"]}"
        have="$(live_value "${key}" || true)"
        if [[ "${have}" != "${want}" ]]; then
            mismatched+=("${key}=${have:-unreadable} (want ${want})")
        fi
    done

    if [[ "${#mismatched[@]}" -gt 0 ]]; then
        local entry
        error "The kernel did not accept these parameters:"
        for entry in "${mismatched[@]}"; do
            error "  ${entry}"
        done
        return 1
    fi
    success "All ${#SYSCTL_KEYS[@]} kernel parameters are live."
}

restore_live_values() {
    local dir="$1"
    local record="${dir}/snapshots/values.txt"
    if [[ ! -f "${record}" ]]; then
        info "No live values were recorded in ${dir}, so the kernel was left as it is."
        return 0
    fi

    local key value
    while read -r key value; do
        [[ -z "${key}" ]] && continue
        if run_cmd sysctl -qw "${key}=${value}"; then
            info "Restored ${key}=${value}"
        else
            warn "Could not restore ${key}."
        fi
    done < "${record}"
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir sysctl)" || return 1
    fi

    warn "Rolling back kernel parameters from ${dir}"
    rollback_dir "${dir}" || return 1
    restore_live_values "${dir}"
    finish_rollback_pointer sysctl
    success "Kernel parameter rollback finished."
}

apply_sysctl() {
    SYSCTL_TARGET="$(drv_sysctl_file)"
    collect_supported_keys || return 1

    cat <<EOF
Kernel hardening will:
  - install ${#SYSCTL_KEYS[@]} parameters into ${SYSCTL_TARGET}
  - load them with sysctl -p
  - read every value back before reporting success
  - back up the previous file and the previous live values under ${BACKUP_ROOT}/sysctl
EOF
    confirm "Apply the kernel parameter baseline?" || return 1

    require_command sysctl || return 1

    backup_begin sysctl
    backup_file "${SYSCTL_TARGET}"
    snapshot_live_values
    record_kv SYSCTL_TARGET "${SYSCTL_TARGET}"

    arm_rollback
    write_target
    if dry_run; then
        info "Dry run: skipping the load and the live-value proof."
        disarm_rollback
        success "Kernel parameter plan is complete."
        return 0
    fi

    if ! load_parameters; then
        error "Kernel parameter load failed. Restoring the backup."
        rollback_component
        exit 1
    fi
    if ! verify_live_values; then
        error "Kernel parameters did not take effect. Restoring the backup."
        rollback_component
        exit 1
    fi

    state_set SYSCTL_BASELINE "${#SYSCTL_KEYS[@]}"
    save_state
    disarm_rollback
    success "Kernel parameter baseline completed."
}

main() {
    parse_sysctl_args "$@" || {
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
        confirm "Roll back the latest kernel parameter backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_sysctl
}

main "$@"
