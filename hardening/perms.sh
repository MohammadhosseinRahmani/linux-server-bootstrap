#!/usr/bin/env bash
# Tighten the permissions of the files that hold credentials and schedules.
#
# Ownership of /etc/shadow is not the same on every family: Debian and SUSE give
# it to the shadow group so tools can read it through a helper, while EL keeps it
# root-only. Both answers are correct, so the stage reads the group the host
# already uses and normalises the mode to it instead of forcing one family's
# layout on another.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

FIX_WORLD_WRITABLE="${FIX_WORLD_WRITABLE:-0}"
SCAN_ROOTS=("/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin" "/boot")
PERM_PATHS=()
PERM_MODES=()
PERM_OWNERS=()

usage() {
    cat <<EOF
Usage: bash hardening/perms.sh [--yes] [--dry-run] [--fix-world-writable]
       bash hardening/perms.sh --rollback

Sets the expected mode and owner on account files, privileged binaries, cron
schedules and SSH host keys that already exist. Missing paths are skipped, so a
minimal image is not asked to own files it does not have.

--fix-world-writable  remove the world-writable bit from files and add the sticky
                      bit to world-writable directories under /etc, /bin, /sbin,
                      /usr and /boot. Without it the scan only reports.

Backups: ${BACKUP_ROOT}/perms/<timestamp>
EOF
}

parse_perms_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fix-world-writable)
                FIX_WORLD_WRITABLE=1
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

remember_perm() {
    PERM_PATHS+=("$1")
    PERM_MODES+=("$2")
    PERM_OWNERS+=("$3")
}

build_expected_perms() {
    local shadow_group shadow_mode entry path rest mode owner
    read -r shadow_group shadow_mode <<< "$(shadow_ownership)"

    for entry in \
        "/etc/passwd 0644 root:root" \
        "/etc/group 0644 root:root" \
        "/etc/passwd- 0644 root:root" \
        "/etc/group- 0644 root:root" \
        "/etc/hosts 0644 root:root" \
        "/etc/host.conf 0644 root:root" \
        "/etc/resolv.conf 0644 root:root" \
        "/etc/issue 0644 root:root" \
        "/etc/issue.net 0644 root:root" \
        "/etc/services 0644 root:root" \
        "/etc/sysctl.conf 0644 root:root" \
        "/etc/login.defs 0644 root:root" \
        "/etc/profile 0644 root:root" \
        "/etc/bash.bashrc 0644 root:root" \
        "/etc/shadow ${shadow_mode} root:${shadow_group}" \
        "/etc/gshadow ${shadow_mode} root:${shadow_group}" \
        "/etc/shadow- ${shadow_mode} root:${shadow_group}" \
        "/etc/gshadow- ${shadow_mode} root:${shadow_group}" \
        "/etc/security/opasswd 0600 root:${shadow_group}" \
        "/etc/crontab 0600 root:root" \
        "/etc/cron.d 0700 root:root" \
        "/etc/cron.hourly 0700 root:root" \
        "/etc/cron.daily 0700 root:root" \
        "/etc/cron.weekly 0700 root:root" \
        "/etc/cron.monthly 0700 root:root" \
        "/etc/cron.allow 0600 root:root" \
        "/etc/at.allow 0600 root:root" \
        "/etc/ssh/sshd_config 0600 root:root" \
        "/etc/ssh/ssh_config 0644 root:root" \
        "/etc/sudoers 0440 root:root" \
        "/etc/sysctl.d 0755 root:root" \
        "/etc/security/limits.d 0755 root:root"; do
        path="${entry%% *}"
        [[ -e "${path}" ]] || continue
        rest="${entry#* }"
        mode="${rest%% *}"
        owner="${rest##* }"
        remember_perm "${path}" "${mode}" "${owner}"
    done

    # A key without its public half is not unusual on a container image, so the
    # pair is taken from what is actually on disk.
    for path in /etc/ssh/ssh_host_*_key; do
        [[ -f "${path}" ]] || continue
        remember_perm "${path}" "0600 root:root"
    done
}

apply_perms() {
    local index path
    for index in "${!PERM_PATHS[@]}"; do
        path="${PERM_PATHS["${index}"]}"
        run_cmd chmod -- "${PERM_MODES["${index}"]}" "${path}"
        run_cmd chown -- "${PERM_OWNERS["${index}"]}" "${path}"
    done
}

verify_perms() {
    local index path want_mode want_owner have_mode have_owner bad=0
    for index in "${!PERM_PATHS[@]}"; do
        path="${PERM_PATHS["${index}"]}"
        want_mode="${PERM_MODES["${index}"]}"
        want_owner="${PERM_OWNERS["${index}"]}"
        have_mode="$(stat -c '%a' "${path}" 2>/dev/null || true)"
        have_owner="$(stat -c '%U:%G' "${path}" 2>/dev/null || true)"
        if [[ "${have_mode}" != "${want_mode#0}" && "${have_mode}" != "${want_mode}" ]] \
            || [[ "${have_owner}" != "${want_owner}" ]]; then
            error "${path} still has mode ${have_mode:-unreadable} owner ${have_owner:-unreadable}"
            bad=$((bad + 1))
        fi
    done
    if [[ "${bad}" -gt 0 ]]; then
        return 1
    fi
    success "${#PERM_PATHS[@]} path(s) carry the expected permissions."
}

world_writable_scan() {
    local root files dirs
    local -a existing=()
    for root in "${SCAN_ROOTS[@]}"; do
        [[ -d "${root}" ]] && existing+=("${root}")
    done
    if [[ "${#existing[@]}" -eq 0 ]]; then
        return 0
    fi

    files="$(find "${existing[@]}" -xdev -type f -perm -0002 2>/dev/null || true)"
    dirs="$(find "${existing[@]}" -xdev -type d -perm -0002 2>/dev/null || true)"

    if [[ -n "${files}" ]]; then
        warn "World-writable files ($(printf '%s\n' "${files}" | wc -l | tr -d ' ')):"
        printf '%s\n' "${files}" | head -n 20 | sed 's/^/  /'
    else
        info "No world-writable files."
    fi
    if [[ -n "${dirs}" ]]; then
        warn "World-writable directories without a sticky bit ($(printf '%s\n' "${dirs}" | wc -l | tr -d ' ')):"
        printf '%s\n' "${dirs}" | head -n 20 | sed 's/^/  /'
    fi

    save_snapshot world-writable.txt printf 'files:\n%s\ndirs:\n%s\n' "${files}" "${dirs}"
}

world_writable_fix() {
    local root
    local -a existing=()
    for root in "${SCAN_ROOTS[@]}"; do
        [[ -d "${root}" ]] && existing+=("${root}")
    done
    [[ "${#existing[@]}" -gt 0 ]] || return 0

    info "Removing the world-writable bit from files..."
    run_cmd find "${existing[@]}" -xdev -type f -perm -0002 -exec chmod o-w {} +
    info "Adding the sticky bit to world-writable directories..."
    run_cmd find "${existing[@]}" -xdev -type d -perm -0002 -exec chmod +t {} +
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir perms)" || return 1
    fi

    warn "Restoring recorded permissions from ${dir}"
    restore_recorded_modes "${dir}"
    finish_rollback_pointer perms
    success "Permission rollback finished."
}

plan_text() {
    printf '%s\n' "Permission hardening will:"
    printf '%s\n' "  - set the mode and owner of ${#PERM_PATHS[@]} existing path(s)"
    printf '%s\n' "  - scan for world-writable files and report them"
    if [[ "${FIX_WORLD_WRITABLE}" -eq 1 ]]; then
        printf '%s\n' "  - clear the world-writable bit and add sticky bits to directories"
    fi
    printf '%s\n' "  - record the current modes so a rollback restores permissions, not contents"
}

apply_perms_stage() {
    build_expected_perms
    if [[ "${#PERM_PATHS[@]}" -eq 0 ]]; then
        error "None of the expected files exist on this host."
        return 1
    fi

    plan_text
    confirm "Apply the permission baseline?" || return 1

    backup_begin perms
    record_modes "${PERM_PATHS[@]}"
    world_writable_scan

    arm_rollback
    apply_perms
    if [[ "${FIX_WORLD_WRITABLE}" -eq 1 ]]; then
        world_writable_fix
    fi

    if dry_run; then
        info "Dry run: skipping the permission proof."
        disarm_rollback
        success "Permission plan is complete."
        return 0
    fi

    if ! verify_perms; then
        error "Permissions could not be set as expected. Restoring the recorded modes."
        rollback_component
        exit 1
    fi

    state_set PERM_PATHS "${#PERM_PATHS[@]}"
    save_state
    disarm_rollback
    success "Permission hardening completed."
}

main() {
    parse_perms_args "$@" || {
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
        confirm "Roll back the latest permission backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_perms_stage
}

main "$@"
