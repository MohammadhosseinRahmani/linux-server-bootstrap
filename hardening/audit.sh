#!/usr/bin/env bash
# Install the audit rule baseline, load it, and prove the kernel accepted it.
#
# The rules are written into rules.d so every family rebuilds one merged file its
# own way, and the run refuses to report success unless auditctl lists the rules
# back. Whatever the host had loaded before is captured first, because the
# baseline starts with -D and a rollback has to put those rules back.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

AUDIT_SOURCE="${PROJECT_DIR}/config/audit.rules"
AUDIT_TARGET=""
AUDITCTL_ABSENT=0
WATCH_PRIVILEGED="${WATCH_PRIVILEGED:-0}"
MAKE_IMMUTABLE="${MAKE_IMMUTABLE:-0}"

usage() {
    cat <<EOF
Usage: bash hardening/audit.sh [--yes] [--dry-run] [--watch-privileged]
                               [--immutable]
       bash hardening/audit.sh --rollback

Writes ${AUDIT_SOURCE} into the rules.d directory the driver chooses, installs
the audit package when it is missing, and loads the rules with augenrules.

--watch-privileged  add a watch for every setuid and setgid binary found on the
                    local filesystems.
--immutable         finish the ruleset with -e 2. The rules then cannot be
                    changed until the next reboot, which also blocks this
                    project's rollback, so it is opt-in.

Backups: ${BACKUP_ROOT}/audit/<timestamp>
EOF
}

parse_audit_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --watch-privileged)
                WATCH_PRIVILEGED=1
                shift
                ;;
            --immutable)
                MAKE_IMMUTABLE=1
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

# audit 3.0 introduced the unset keyword; older parsers only take the numeric
# form, and a rule they reject would abort the whole load.
pick_auid_unset() {
    local line major
    line="$(auditctl -v 2>/dev/null || true)"
    major="$(printf '%s\n' "${line}" | sed -n 's/.*version \([0-9]\+\).*/\1/p')"
    if [[ -n "${major}" ]] && (( major >= 3 )); then
        printf 'unset\n'
    else
        printf '4294967295\n'
    fi
}

host_has_32bit_abi() {
    case "$(uname -m 2>/dev/null || printf unknown)" in
        x86_64|i386|i586|i686) return 0 ;;
        *) return 1 ;;
    esac
}

render_rules() {
    if [[ ! -f "${AUDIT_SOURCE}" ]]; then
        error "Rule template not found: ${AUDIT_SOURCE}"
        return 1
    fi

    local auid_unset
    auid_unset="$(pick_auid_unset)"
    if host_has_32bit_abi; then
        sed -e "s/__AUID_UNSET__/${auid_unset}/g" "${AUDIT_SOURCE}"
    else
        info "This kernel exposes no 32-bit syscall ABI, so arch=b32 rules are dropped."
        sed -e "s/__AUID_UNSET__/${auid_unset}/g" "${AUDIT_SOURCE}" | grep -v 'arch=b32'
    fi

    if [[ "${WATCH_PRIVILEGED}" -eq 1 ]]; then
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
            | while IFS= read -r path; do
                printf -- '-w %s -p wa -k privileged\n' "${path}"
            done
    fi

    if [[ "${MAKE_IMMUTABLE}" -eq 1 ]]; then
        printf -- '-e 2\n'
    fi
}

install_rules_file() {
    local tmp
    tmp="$(mktemp)"
    render_rules > "${tmp}" || {
        rm -f -- "${tmp}"
        return 1
    }

    run_cmd mkdir -p -- "$(dirname -- "${AUDIT_TARGET}")"
    install_file 0644 "${tmp}" "${AUDIT_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${AUDIT_TARGET}"
}

# auditctl is the only interface all three families agree on for reading back
# what the kernel holds.
verify_loaded_rules() {
    local listed
    listed="$(auditctl -l 2>/dev/null || true)"
    if [[ -z "${listed}" ]]; then
        error "auditctl lists no rules, so nothing was loaded."
        return 1
    fi
    if ! grep -q 'identity' <<< "${listed}"; then
        error "The identity watch is not in the loaded ruleset."
        return 1
    fi
    success "auditctl reports $(printf '%s\n' "${listed}" | grep -c '^-') rule(s) loaded."
}

restore_previous_rules() {
    local dir="$1"
    local record="${dir}/snapshots/previous.rules"
    if [[ ! -f "${record}" ]]; then
        warn "No previous rule snapshot in ${dir}, so the loaded rules were left alone."
        return 0
    fi
    if ! command -v auditctl >/dev/null 2>&1; then
        return 0
    fi

    # A rules file cannot restore the kernel's rule ordering exactly, but the
    # snapshot is the rules the host had, so loading it after -D is the closest
    # a rollback can honestly get.
    local tmp
    tmp="$(mktemp)"
    {
        printf -- '-D\n'
        grep -v '^-D$' "${record}" || true
    } > "${tmp}"
    if run_cmd auditctl -R "${tmp}"; then
        info "Reloaded the rules the host had before."
    else
        warn "auditctl refused the previous rules. Check ${record}."
    fi
    rm -f -- "${tmp}"
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    AUDIT_TARGET="$(drv_audit_rules_file)"
    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir audit)" || return 1
    fi

    if grep -q 'IMMUTABLE=1' "${dir}/manifest.env" 2>/dev/null; then
        error "The rules were loaded with -e 2, so they cannot be removed until the next reboot."
        error "Restore ${dir}/files${AUDIT_TARGET} manually after rebooting."
        return 1
    fi

    warn "Rolling back audit rules from ${dir}"
    rollback_dir "${dir}" || return 1
    restore_previous_rules "${dir}"
    finish_rollback_pointer audit
    success "Audit rollback finished."
}

ensure_audit_service() {
    if ! svc_unit_exists auditd; then
        error "auditd is not available as a service on this host."
        return 1
    fi
    svc_enable_now auditd || return 1
}

plan_text() {
    printf '%s\n' "Audit hardening will:"
    printf '%s\n' "  - install the rule baseline into ${AUDIT_TARGET}"
    if command -v augenrules >/dev/null 2>&1; then
        printf '%s\n' "  - load it with augenrules --load"
    else
        printf '%s\n' "  - load it with auditctl -R"
    fi
    if [[ "${WATCH_PRIVILEGED}" -eq 1 ]]; then
        printf '%s\n' "  - watch every setuid and setgid binary"
    fi
    if [[ "${MAKE_IMMUTABLE}" -eq 1 ]]; then
        printf '%s\n' "  - lock the ruleset until the next reboot (-e 2)"
    fi
    printf '%s\n' "  - keep a copy of the rules this host currently has"
}

apply_audit() {
    AUDIT_TARGET="$(drv_audit_rules_file)"

    plan_text
    confirm "Apply the audit rule baseline?" || return 1

    if ! command -v auditctl >/dev/null 2>&1; then
        info "auditctl is missing, so the audit package is installed first."
        require_pkg_mgr || return 1
        drv_pkg_install "$(drv_audit_pkg)" || return 1
        if ! command -v auditctl >/dev/null 2>&1; then
            if ! dry_run; then
                error "auditctl is still missing, so the rules cannot be loaded or read back."
                return 1
            fi
            # A dry run only prints the install, so the command genuinely stays away.
            AUDITCTL_ABSENT=1
            warn "Dry run: the install was simulated, so auditctl is still absent and the load is unproven."
        fi
    fi

    backup_begin audit
    backup_file "${AUDIT_TARGET}"
    if [[ "${AUDITCTL_ABSENT}" -eq 0 ]]; then
        save_snapshot previous.rules auditctl -l
    fi
    record_kv IMMUTABLE "${MAKE_IMMUTABLE}"

    arm_rollback
    install_rules_file

    if dry_run; then
        info "Dry run: skipping the load and the loaded-rule proof."
        disarm_rollback
        success "Audit rule plan is complete."
        return 0
    fi

    ensure_audit_service || {
        error "auditd could not be started. Restoring the backup."
        rollback_component
        exit 1
    }
    if ! drv_audit_apply; then
        error "The rule load failed. Restoring the backup."
        rollback_component
        exit 1
    fi
    if ! verify_loaded_rules; then
        error "The kernel did not accept the rules. Restoring the backup."
        rollback_component
        exit 1
    fi

    state_set AUDIT_RULES_FILE "${AUDIT_TARGET}"
    save_state
    disarm_rollback
    success "Audit rule baseline completed."
    if [[ "${MAKE_IMMUTABLE}" -eq 1 ]]; then
        warn "The ruleset is immutable. A reboot is needed before it can be changed again."
    fi
}

main() {
    parse_audit_args "$@" || {
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
        confirm "Roll back the latest audit backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_audit
}

main "$@"
