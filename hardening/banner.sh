#!/usr/bin/env bash
# Install the legal-warning banner on the consoles, the network logins, and SSH.
#
# /etc/motd is a symlink to a dynamically generated file on Debian and Ubuntu, so
# writing through it would be overwritten at the next login. The stage says so
# instead of pretending it worked, and points sshd's Banner at the .net copy,
# which is read for every SSH session regardless of motd.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

BANNER_SOURCE="${PROJECT_DIR}/config/banner.txt"
BANNER_FILES=("/etc/issue" "/etc/issue.net")
BANNER_HOSTNAME=""

usage() {
    cat <<EOF
Usage: bash hardening/banner.sh [--yes] [--dry-run]
       bash hardening/banner.sh --rollback

Replaces the text in /etc/issue and /etc/issue.net with ${BANNER_SOURCE} and,
when this sshd build reads ${SSH_CONFIG_DIR}, adds a drop-in that sets
Banner to /etc/issue.net.

/etc/motd is only touched when it is a real file, never when it is a symlink to
a generated message of the day.

Backups: ${BACKUP_ROOT}/banner/<timestamp>
EOF
}

parse_banner_args() {
    parse_standard_args "$@"
}

render_banner() {
    if [[ ! -f "${BANNER_SOURCE}" ]]; then
        error "Banner template not found: ${BANNER_SOURCE}"
        return 1
    fi
    sed "s/__HOSTNAME__/${BANNER_HOSTNAME}/g" "${BANNER_SOURCE}"
}

write_banner_files() {
    local tmp path
    tmp="$(mktemp)"
    render_banner > "${tmp}" || {
        rm -f -- "${tmp}"
        return 1
    }

    for path in "${BANNER_FILES[@]}"; do
        if [[ -L "${path}" ]]; then
            warn "${path} is a symlink, so it was left alone."
            continue
        fi
        install_file 0644 "${tmp}" "${path}"
    done

    if [[ -L /etc/motd ]]; then
        info "/etc/motd is generated dynamically on this host, so the banner is not installed there."
    else
        install_file 0644 "${tmp}" /etc/motd
    fi
    rm -f -- "${tmp}"
}

# sshd reads the banner file per connection, so there is no daemon to restart, but
# a bad drop-in still breaks every login. sshd -t is the only honest proof.
install_ssh_banner() {
    if ! command -v sshd >/dev/null 2>&1; then
        warn "sshd is not installed, so no SSH banner drop-in was written."
        return 0
    fi
    if ! sshd_supports_include; then
        warn "This sshd build predates Include; add Banner /etc/issue.net to ${SSH_MAIN_CONFIG} yourself."
        return 0
    fi
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "${SSH_MAIN_CONFIG}" 2>/dev/null; then
        warn "${SSH_MAIN_CONFIG} does not include ${SSH_CONFIG_DIR}, so no SSH banner drop-in was written."
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    printf 'Banner /etc/issue.net\n' > "${tmp}"
    run_cmd mkdir -p -- "${SSH_CONFIG_DIR}"
    install_file 0644 "${tmp}" "${SSH_BANNER_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${SSH_BANNER_TARGET}"

    if dry_run; then
        return 0
    fi
    if ! sshd -t; then
        error "sshd -t rejected the configuration after the banner drop-in was installed."
        return 1
    fi
}

verify_banners() {
    local path missing=0
    for path in "${BANNER_FILES[@]}"; do
        [[ -L "${path}" ]] && continue
        if ! grep -q 'Unauthorized access' "${path}" 2>/dev/null; then
            error "${path} does not carry the banner."
            missing=$((missing + 1))
        fi
    done
    if [[ "${missing}" -gt 0 ]]; then
        return 1
    fi
    success "The banner is installed on the paths this host reads."
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir banner)" || return 1
    fi

    warn "Rolling back the banner from ${dir}"
    rollback_dir "${dir}" || return 1
    if ! dry_run && command -v sshd >/dev/null 2>&1; then
        sshd -t || error "The restored SSH configuration does not validate."
    fi
    finish_rollback_pointer banner
    success "Banner rollback finished."
}

apply_banner() {
    BANNER_HOSTNAME="$(hostname 2>/dev/null || printf 'this host')"

    cat <<EOF
Banner hardening will:
  - replace /etc/issue and /etc/issue.net for ${BANNER_HOSTNAME}
  - set sshd Banner to /etc/issue.net when the drop-in directory is read
  - back up every file it replaces under ${BACKUP_ROOT}/banner
EOF
    confirm "Install the legal warning banner?" || return 1

    backup_begin banner
    local path
    for path in "${BANNER_FILES[@]}" /etc/motd "${SSH_BANNER_TARGET}"; do
        backup_file "${path}"
    done

    arm_rollback
    write_banner_files
    if ! install_ssh_banner; then
        error "The SSH banner was not accepted. Restoring the backup."
        rollback_component
        exit 1
    fi

    if dry_run; then
        info "Dry run: skipping the banner proof."
        disarm_rollback
        success "Banner plan is complete."
        return 0
    fi

    if ! verify_banners; then
        error "The banner was not written as expected. Restoring the backup."
        rollback_component
        exit 1
    fi

    state_set BANNER_INSTALLED 1
    save_state
    disarm_rollback
    success "Banner hardening completed."
}

main() {
    parse_banner_args "$@" || {
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
        confirm "Roll back the latest banner backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_banner
}

main "$@"
