#!/usr/bin/env bash
# Base operating system setup: updates, clock, locale, hostname, time sync and
# automatic patching. Every action is opt-in, so a fresh image can be prepared with
# one command and an existing server can be left alone.
#
# All package and service work goes through the loaded driver, which is what makes
# the same stage valid on apt, RPM and SUSE hosts.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

DO_UPDATES=0
TIMEZONE=""
LOCALE=""
HOSTNAME_WANTED=""
DO_TIMESYNC=0
DO_AUTOUPDATES=0
TIMESYNC_UNIT=""

usage() {
    cat <<EOF
Usage: bash setup/base.sh [options] [--yes]
       bash setup/base.sh --rollback

Options (each one is opt-in):
  --updates            Apply the distribution's package upgrades.
  --timezone ZONE      Set the clock zone, for example UTC or Europe/Berlin.
  --locale LANG        Set the system locale, for example C.UTF-8 or en_US.UTF-8.
  --hostname NAME      Set the static hostname.
  --timesync           Install and enable the chrony service for this family.
  --autoupdates        Enable unattended security updates for this family.

Backups: ${BACKUP_ROOT}/base/<timestamp>
EOF
}

parse_base_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --updates)
                DO_UPDATES=1
                shift
                ;;
            --timesync)
                DO_TIMESYNC=1
                shift
                ;;
            --autoupdates)
                DO_AUTOUPDATES=1
                shift
                ;;
            --timezone|--locale|--hostname)
                if [[ $# -lt 2 ]]; then
                    error "$1 requires a value."
                    return 2
                fi
                case "$1" in
                    --timezone) TIMEZONE="$2" ;;
                    --locale) LOCALE="$2" ;;
                    --hostname) HOSTNAME_WANTED="$2" ;;
                esac
                shift 2
                ;;
            --yes|--dry-run|--rollback)
                parse_standard_args "$1" || return 2
                shift
                ;;
            -h|--help)
                SHOW_HELP=1
                shift
                ;;
            *)
                error "Unknown argument: $1"
                return 2
                ;;
        esac
    done
}

validate_requested() {
    if [[ -n "${TIMEZONE}" && ! "${TIMEZONE}" =~ ^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$ ]]; then
        error "Timezone must be a zone name such as UTC or Europe/Berlin. Got: ${TIMEZONE}"
        return 1
    fi
    if [[ -n "${LOCALE}" && ! "${LOCALE}" =~ ^[A-Za-z0-9._@-]+$ ]]; then
        error "Locale must look like C.UTF-8 or en_US.UTF-8. Got: ${LOCALE}"
        return 1
    fi
    if [[ -n "${HOSTNAME_WANTED}" && ! "${HOSTNAME_WANTED}" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
        error "Invalid hostname: ${HOSTNAME_WANTED}"
        return 1
    fi
}

timezone_is_current() {
    local want="$1" current=""
    current="$(readlink -f "${LOCALTIME_FILE}" 2>/dev/null | sed 's|.*/zoneinfo/||' || true)"
    if [[ -f "${TIMEZONE_NAME_FILE}" ]]; then
        current="$(head -n 1 "${TIMEZONE_NAME_FILE}")"
    fi
    [[ "${current}" == "${want}" ]]
}

hostname_is_current() {
    [[ "$(hostname 2>/dev/null || true)" == "${HOSTNAME_WANTED}" ]] \
        && grep -Fxq "${HOSTNAME_WANTED}" /etc/hostname 2>/dev/null
}

apply_updates() {
    info "Applying package upgrades..."
    drv_updates_apply
}

apply_timezone() {
    if timezone_is_current "${TIMEZONE}"; then
        info "The clock already uses ${TIMEZONE}."
        return 0
    fi
    drv_timezone_apply "${TIMEZONE}"
}

apply_locale() {
    drv_locale_apply "${LOCALE}"
}

apply_hostname() {
    if hostname_is_current; then
        info "The hostname is already ${HOSTNAME_WANTED}."
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "${HOSTNAME_WANTED}" > "${tmp}"
    install_file 0644 "${tmp}" /etc/hostname
    rm -f -- "${tmp}"
    run_cmd hostname -F /etc/hostname
    if ! getent hosts "${HOSTNAME_WANTED}" >/dev/null 2>&1; then
        # sudo and some daemons fail when the static hostname does not resolve.
        warn "After this change add a line to /etc/hosts, for example:"
        warn "  127.0.0.1 ${HOSTNAME_WANTED}"
    fi
}

apply_timesync() {
    local pkg
    pkg="$(drv_timesync_pkg)"
    drv_pkg_install "${pkg}" || return 1
    TIMESYNC_UNIT="$(drv_timesync_unit)"
    svc_enable_now "${TIMESYNC_UNIT}" || return 1
    if ! dry_run && ! svc_is_active "${TIMESYNC_UNIT}"; then
        warn "${pkg} was enabled but is not running; check systemctl status ${TIMESYNC_UNIT}"
    fi
}

apply_autoupdates() {
    drv_unattended_setup
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir base)" || return 1
    fi

    warn "Rolling back base setup from ${dir}"
    rollback_dir "${dir}" || return 1

    # The files are back, so the running clock and name have to follow them.
    if [[ -f /etc/hostname ]]; then
        run_cmd hostname -F /etc/hostname || true
    fi
    if [[ "${OS_FAMILY}" == "debian" ]] && [[ -f /etc/timezone ]] \
        && command -v dpkg-reconfigure >/dev/null 2>&1; then
        run_cmd dpkg-reconfigure -f noninteractive tzdata || true
    fi

    finish_rollback_pointer base
    success "base rollback finished."
    warn "Time sync and unattended updates stay installed; disable their services if you"
    warn "want them stopped as well."
}

plan_text() {
    cat <<EOF
Base setup will:
EOF
    if [[ "${DO_UPDATES}" -eq 1 ]]; then
        printf '  - apply package upgrades with %s\n' "${PKG_MGR}"
    fi
    if [[ -n "${HOSTNAME_WANTED}" ]]; then
        printf '  - set the hostname to %s\n' "${HOSTNAME_WANTED}"
    fi
    if [[ -n "${TIMEZONE}" ]]; then
        printf '  - set the timezone to %s\n' "${TIMEZONE}"
    fi
    if [[ -n "${LOCALE}" ]]; then
        printf '  - set the locale to %s\n' "${LOCALE}"
    fi
    if [[ "${DO_TIMESYNC}" -eq 1 ]]; then
        printf '  - install and enable %s (%s)\n' "$(drv_timesync_pkg)" "$(drv_timesync_unit)"
    fi
    if [[ "${DO_AUTOUPDATES}" -eq 1 ]]; then
        printf '  - enable unattended updates for this family\n'
    fi
    printf '  - back up what it replaces under %s/base\n' "${BACKUP_ROOT}"
}

apply_base() {
    plan_text
    confirm "Apply base setup?" || return 1

    backup_begin base
    backup_file /etc/hostname
    backup_file "$(drv_timezone_file)"
    while IFS= read -r path; do
        [[ -n "${path}" ]] || continue
        backup_file "${path}"
    done < <(drv_locale_files)
    backup_file "${STATE_FILE}"

    arm_rollback

    if [[ "${DO_UPDATES}" -eq 1 ]]; then
        apply_updates
        state_set UPDATES_APPLIED 1
    fi
    if [[ -n "${HOSTNAME_WANTED}" ]]; then
        apply_hostname
        state_set HOSTNAME "${HOSTNAME_WANTED}"
    fi
    if [[ -n "${TIMEZONE}" ]]; then
        apply_timezone
        state_set TIMEZONE "${TIMEZONE}"
    fi
    if [[ -n "${LOCALE}" ]]; then
        apply_locale
        state_set LOCALE "${LOCALE}"
    fi
    if [[ "${DO_TIMESYNC}" -eq 1 ]]; then
        apply_timesync
        state_set TIMESYNC "${TIMESYNC_UNIT}"
    fi
    if [[ "${DO_AUTOUPDATES}" -eq 1 ]]; then
        apply_autoupdates
        state_set AUTOUPDATES 1
    fi

    save_state
    disarm_rollback
    success "Base setup completed."
    if ! dry_run; then
        printf '  hostname: %s\n  timezone: %s\n' "$(hostname)" "$(date '+%Z %z')"
    fi
}

main() {
    parse_base_args "$@" || {
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
        confirm "Roll back the latest base setup backup?" || exit 1
        rollback_component
        exit 0
    fi

    require_pkg_mgr || return 1
    require_init_tools || return 1
    validate_requested || return 1

    if [[ "${DO_UPDATES}" -eq 0 && "${DO_TIMESYNC}" -eq 0 && "${DO_AUTOUPDATES}" -eq 0 \
        && -z "${TIMEZONE}" && -z "${LOCALE}" && -z "${HOSTNAME_WANTED}" ]]; then
        error "Nothing to do. Pass at least one of --updates, --timezone, --locale,"
        error "--hostname, --timesync or --autoupdates."
        exit 2
    fi

    apply_base
}

main "$@"
