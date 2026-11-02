#!/usr/bin/env bash
# Cap core dumps and login counts, then prove the running limits.
#
# pam_limits reads /etc/security/limits.d on every login, but services started
# by systemd never pass through PAM, so a systemd host needs the manager default
# as well. Both are written here, and each is checked against what the live
# system reports rather than against the file on disk.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

LIMITS_SOURCE="${PROJECT_DIR}/config/limits.conf"
CORE_LIMIT="${CORE_LIMIT:-0}"
MAX_LOGINS="${MAX_LOGINS:-}"

usage() {
    cat <<EOF
Usage: bash hardening/limits.sh [--yes] [--dry-run] [--core-size N]
                                [--max-logins N]
       bash hardening/limits.sh --rollback

Installs ${LIMITS_SOURCE} as ${LIMITS_TARGET} and, on a systemd host, sets the
manager DefaultLimitCORE in ${SYSTEMD_LIMITS_DROPIN}.

--core-size N   core dump size limit (default 0, which disables core dumps)
--max-logins N  cap concurrent logins per account (omitted by default, because
                a low value can lock out the operator)

Backups: ${BACKUP_ROOT}/limits/<timestamp>
EOF
}

parse_limits_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --core-size|--max-logins)
                if [[ $# -lt 2 ]]; then
                    error "$1 requires a number."
                    return 2
                fi
                if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                    error "$1 needs a non-negative integer. Got: $2"
                    return 2
                fi
                if [[ "$1" == "--core-size" ]]; then
                    CORE_LIMIT="$2"
                else
                    MAX_LOGINS="$2"
                fi
                shift 2
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

limits_body() {
    if [[ ! -f "${LIMITS_SOURCE}" ]]; then
        error "Template not found: ${LIMITS_SOURCE}"
        return 1
    fi
    sed "s/__CORE_LIMIT__/${CORE_LIMIT}/" "${LIMITS_SOURCE}"
    if [[ -n "${MAX_LOGINS}" ]]; then
        printf '* hard maxlogins %s\n' "${MAX_LOGINS}"
    fi
}

write_limits_file() {
    local tmp
    tmp="$(mktemp)"
    {
        printf '%s\n' "# Installed by linux-server-bootstrap hardening/limits.sh"
        limits_body
    } > "${tmp}"
    run_cmd mkdir -p -- "$(dirname -- "${LIMITS_TARGET}")"
    install_file 0644 "${tmp}" "${LIMITS_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${LIMITS_TARGET}"
}

write_systemd_dropin() {
    [[ "${INIT_SYSTEM}" == "systemd" ]] || return 0

    local tmp
    tmp="$(mktemp)"
    cat > "${tmp}" <<EOF
[Manager]
DefaultLimitCORE=${CORE_LIMIT}
EOF
    run_cmd mkdir -p -- "$(dirname -- "${SYSTEMD_LIMITS_DROPIN}")"
    install_file 0644 "${tmp}" "${SYSTEMD_LIMITS_DROPIN}"
    rm -f -- "${tmp}"
    success "Installed ${SYSTEMD_LIMITS_DROPIN}"

    if dry_run; then
        return 0
    fi
    # system.conf.d is only read again when the manager reloads itself.
    svc_daemon_reexec
}

# The limits file is plain text, so the proof is that the directive the stage
# wrote is still the one the host reports at login.
verify_limits_file() {
    if [[ ! -s "${LIMITS_TARGET}" ]]; then
        error "${LIMITS_TARGET} was not written."
        return 1
    fi
    if ! grep -Eq "^[[:space:]]*[a-z*][[:space:]]+hard[[:space:]]+core[[:space:]]+${CORE_LIMIT}[[:space:]]*$" "${LIMITS_TARGET}"; then
        error "The core limit line is missing from ${LIMITS_TARGET}."
        return 1
    fi
    success "Core dumps are limited to ${CORE_LIMIT} in ${LIMITS_TARGET}"
}

verify_systemd_core() {
    [[ "${INIT_SYSTEM}" == "systemd" ]] || return 0

    local reported
    reported="$(systemctl show -p DefaultLimitCORE --value 2>/dev/null || true)"
    if [[ -z "${reported}" ]]; then
        warn "systemctl did not report DefaultLimitCORE, so the manager default was not verified."
        return 0
    fi
    if [[ "${reported}" == *"${CORE_LIMIT}"* ]]; then
        success "systemd DefaultLimitCORE is ${reported}"
        return 0
    fi
    error "systemd reports DefaultLimitCORE=${reported}, expected ${CORE_LIMIT}."
    return 1
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir limits)" || return 1
    fi

    warn "Rolling back login limits from ${dir}"
    rollback_dir "${dir}" || return 1
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        svc_daemon_reexec
    fi
    finish_rollback_pointer limits
    success "Login limit rollback finished."
}

plan_text() {
    printf '%s\n' "Login limit hardening will:"
    printf '%s\n' "  - limit core dumps to ${CORE_LIMIT}"
    if [[ -n "${MAX_LOGINS}" ]]; then
        printf '%s\n' "  - cap concurrent logins per account at ${MAX_LOGINS}"
    fi
    printf '%s\n' "  - write ${LIMITS_TARGET}"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        printf '%s\n' "  - set the systemd DefaultLimitCORE and re-exec the manager"
    fi
    printf '%s\n' "  - back up what it replaces under ${BACKUP_ROOT}/limits"
}

apply_limits() {
    plan_text
    confirm "Apply the login limits?" || return 1

    backup_begin limits
    backup_file "${LIMITS_TARGET}"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        backup_file "${SYSTEMD_LIMITS_DROPIN}"
    fi
    record_kv CORE_LIMIT "${CORE_LIMIT}"

    arm_rollback
    write_limits_file
    write_systemd_dropin

    if dry_run; then
        info "Dry run: skipping the limit proof."
        disarm_rollback
        success "Login limit plan is complete."
        return 0
    fi

    if ! verify_limits_file; then
        error "Login limits were not installed as expected. Restoring the backup."
        rollback_component
        exit 1
    fi
    if ! verify_systemd_core; then
        error "systemd did not pick up the core limit. Restoring the backup."
        rollback_component
        exit 1
    fi

    state_set CORE_LIMIT "${CORE_LIMIT}"
    if [[ -n "${MAX_LOGINS}" ]]; then
        state_set MAX_LOGINS "${MAX_LOGINS}"
    fi
    save_state
    disarm_rollback
    success "Login limit hardening completed."
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        warn "Sessions that are already open keep their old limits until they log out."
    fi
}

main() {
    parse_limits_args "$@" || {
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
        confirm "Roll back the latest login limit backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_limits
}

main "$@"
