#!/usr/bin/env bash
# Apply the SSH policy, validate it, reload sshd, and roll back on failure.
#
# Distribution-specific behaviour comes from the loaded driver: the unit name,
# whether ssh.socket carries the port, and the fail2ban action. The rendering
# method is chosen by probing sshd itself, because a policy that silently does
# not load is worse than no policy.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

SSH_CONFIG_SOURCE="${PROJECT_DIR}/config/sshd_config.conf"
SSH_DROPIN_STYLE="dropin"
SSH_UNIT="${SSH_UNIT:-}"

usage() {
    cat <<EOF
Usage: bash hardening/ssh.sh --user NAME [--user NAME...] [--port N] [--yes]
       bash hardening/ssh.sh --rollback
       bash hardening/ssh.sh --dry-run

Restricts SSH to the listed accounts, disables password and root login, and
reloads SSH. Every --user account must already exist and must have a public key
in ~/.ssh/authorized_keys.

Policy is installed as ${SSH_CONFIG_TARGET} when sshd supports Include, and as a
marked block inside ${SSH_MAIN_CONFIG} on older builds.

Backups: ${BACKUP_ROOT}/ssh/<timestamp>
EOF
}

# OpenSSH reads Include from 7.3 onward. Anything older needs the managed block.
sshd_supports_include() {
    local version_line major minor
    version_line="$(ssh -V 2>&1 || true)"
    if [[ "${version_line}" =~ OpenSSH_([0-9]+)\.([0-9]+) ]]; then
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
        if (( major > 7 )) || (( major == 7 && minor >= 3 )); then
            return 0
        fi
        return 1
    fi
    warn "Could not parse the sshd version from '${version_line}'. Assuming Include is supported."
    return 0
}

detect_ssh_unit() {
    SSH_UNIT="$(drv_ssh_unit)" || return 1
    printf '%s\n' "${SSH_UNIT}"
}

user_has_authorized_key() {
    local user_name="$1"
    local home keys
    home="$(getent passwd "${user_name}" | awk -F: '{print $6}')"
    keys="${home}/.ssh/authorized_keys"
    if [[ ! -s "${keys}" ]]; then
        error "No public key file at ${keys}"
        error "Install a key for ${user_name} before disabling password login."
        return 1
    fi
    if ! grep -Eq '(^|[[:space:]])(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-) ' "${keys}"; then
        error "No SSH public key line found in ${keys}"
        return 1
    fi
    success "Found a public key for ${user_name}"
}

guard_lockout() {
    local invoker="${SUDO_USER:-}"
    if [[ -z "${invoker}" ]]; then
        invoker="$(logname 2>/dev/null || true)"
    fi

    local user_name found=0
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        if [[ "${user_name}" == "${invoker}" ]]; then
            found=1
        fi
    done

    if [[ "${found}" -eq 1 ]]; then
        return 0
    fi

    if [[ "${ASSUME_YES}" -eq 1 ]]; then
        warn "The current account (${invoker:-unknown}) is not in the SSH allow list."
        warn "Continuing because --yes was given."
        return 0
    fi

    error "The current account (${invoker:-unknown}) would lose SSH access."
    error "Pass --user for the account you are using, or pass --yes if you mean to switch accounts."
    return 1
}

supported_list() {
    local kind="$1"
    shift
    local available item picked=()
    available="$(ssh -Q "${kind}" 2>/dev/null || true)"
    [[ -n "${available}" ]] || return 0

    for item in "$@"; do
        if grep -qx -- "${item}" <<< "${available}"; then
            picked+=("${item}")
        fi
    done

    if ((${#picked[@]} > 0)); then
        local IFS=','
        printf '%s' "${picked[*]}"
    fi
}

sshd_has_keyword() {
    local keyword="$1"
    local lower
    lower="$(printf '%s' "${keyword}" | tr '[:upper:]' '[:lower:]')"
    sshd -T 2>/dev/null | grep -qi "^${lower} "
}

append_supported_settings() {
    local dest="$1"

    if sshd_has_keyword KbdInteractiveAuthentication; then
        printf 'KbdInteractiveAuthentication no\n' >> "${dest}"
    elif sshd_has_keyword ChallengeResponseAuthentication; then
        printf 'ChallengeResponseAuthentication no\n' >> "${dest}"
    fi

    if sshd_has_keyword AllowStreamLocalForwarding; then
        printf 'AllowStreamLocalForwarding no\n' >> "${dest}"
    fi
    if sshd_has_keyword Compression; then
        printf 'Compression no\n' >> "${dest}"
    fi

    local ciphers macs kex
    ciphers="$(supported_list cipher \
        chacha20-poly1305@openssh.com \
        aes256-gcm@openssh.com \
        aes128-gcm@openssh.com \
        aes256-ctr \
        aes192-ctr \
        aes128-ctr)"
    macs="$(supported_list mac \
        hmac-sha2-256-etm@openssh.com \
        hmac-sha2-512-etm@openssh.com \
        umac-128-etm@openssh.com)"
    kex="$(supported_list kex \
        curve25519-sha256 \
        curve25519-sha256@libssh.org \
        diffie-hellman-group16-sha512 \
        diffie-hellman-group18-sha512 \
        diffie-hellman-group-exchange-sha256)"

    if [[ -n "${ciphers}" ]]; then
        printf 'Ciphers %s\n' "${ciphers}" >> "${dest}"
    fi
    if [[ -n "${macs}" ]]; then
        printf 'MACs %s\n' "${macs}" >> "${dest}"
    fi
    if [[ -n "${kex}" ]]; then
        printf 'KexAlgorithms %s\n' "${kex}" >> "${dest}"
    fi
}

render_dropin() {
    local dest="$1"
    local users="${SSH_ALLOW_USERS[*]}"
    sed \
        -e "s/__SSH_PORT__/${SSH_PORT}/g" \
        -e "s/__SSH_ALLOW_USER__/${users}/g" \
        "${SSH_CONFIG_SOURCE}" > "${dest}"
    append_supported_settings "${dest}"
}

ensure_sshd_include() {
    if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "${SSH_MAIN_CONFIG}"; then
        info "sshd_config already includes sshd_config.d"
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    {
        printf '%s\n' "${SSH_INCLUDE_LINE}"
        cat -- "${SSH_MAIN_CONFIG}"
    } > "${tmp}"
    install_file 0644 "${tmp}" "${SSH_MAIN_CONFIG}"
    rm -f -- "${tmp}"
    info "Added an Include directive to the top of ${SSH_MAIN_CONFIG}"
}

install_dropin() {
    local tmp
    tmp="$(mktemp)"
    render_dropin "${tmp}"
    run_cmd mkdir -p -- "${SSH_CONFIG_DIR}"
    install_file 0644 "${tmp}" "${SSH_CONFIG_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${SSH_CONFIG_TARGET}"
}

# Older sshd builds never read sshd_config.d, so the same policy is written into
# the main file between markers that a later run replaces instead of stacking.
install_managed_block() {
    local tmp block
    tmp="$(mktemp)"
    block="$(mktemp)"
    render_dropin "${block}"

    awk -v begin="${SSH_BLOCK_BEGIN}" -v end="${SSH_BLOCK_END}" '
        $0 == begin { skipping = 1; next }
        $0 == end { skipping = 0; next }
        !skipping { print }
    ' "${SSH_MAIN_CONFIG}" > "${tmp}"

    {
        printf '%s\n' "${SSH_BLOCK_BEGIN}"
        cat -- "${block}"
        printf '%s\n' "${SSH_BLOCK_END}"
    } >> "${tmp}"

    install_file 0644 "${tmp}" "${SSH_MAIN_CONFIG}"
    rm -f -- "${tmp}" "${block}"
    success "Updated the ${SSH_BLOCK_BEGIN} block in ${SSH_MAIN_CONFIG}"
}

configure_socket_port() {
    # Returns 0 when the driver moved the port into a socket unit.
    local dropin
    if dropin="$(drv_ssh_socket_setup "${SSH_PORT}")"; then
        if dry_run; then
            return 0
        fi
        if [[ -n "${SSH_CONNECTION:-}" ]]; then
            warn "ssh.socket was not restarted, so the current session stays up."
            warn "After a second session works on port ${SSH_PORT}, run: systemctl restart ssh.socket"
        else
            info "No SSH session is attached. Restarting ssh.socket."
            svc_restart ssh.socket
        fi
        return 0
    fi
    return 1
}

validate_config() {
    info "Validating SSH configuration..."
    if sshd -t; then
        success "SSH configuration is valid."
        return 0
    fi
    error "sshd -t failed."
    return 1
}

reload_ssh() {
    info "Reloading ${SSH_UNIT}.service..."
    if svc_is_active "${SSH_UNIT}.service"; then
        if svc_reload "${SSH_UNIT}.service"; then
            success "SSH service reloaded."
            return 0
        fi
        error "Failed to reload ${SSH_UNIT}.service"
        return 1
    fi
    if svc_is_active "${SSH_UNIT}.socket"; then
        success "${SSH_UNIT}.socket is active. The next connection reads the new configuration."
        return 0
    fi
    if svc_enable_now "${SSH_UNIT}.service"; then
        success "Started ${SSH_UNIT}.service"
        return 0
    fi
    error "Failed to start ${SSH_UNIT}.service"
    return 1
}

reload_restored_ssh() {
    svc_daemon_reload
    if ! command -v sshd >/dev/null 2>&1; then
        return 0
    fi
    if ! sshd -t; then
        error "Restored SSH configuration is still invalid. Do not disconnect."
        return 1
    fi
    if [[ -z "${SSH_UNIT}" ]]; then
        detect_ssh_unit || true
    fi
    if [[ -n "${SSH_UNIT}" ]]; then
        reload_ssh || error "Files were restored, but the SSH service did not reload."
    fi
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir ssh)" || return 1
    fi

    warn "Rolling back SSH configuration from ${dir}"
    rollback_dir "${dir}" || return 1
    finish_rollback_pointer ssh
    reload_restored_ssh || true
    success "SSH rollback finished."
}

check_prerequisites() {
    if ! command -v sshd >/dev/null 2>&1; then
        info "Installing openssh-server..."
        drv_pkg_install openssh-server || return 1
    fi
    if ! command -v sshd >/dev/null 2>&1; then
        error "sshd is still not installed."
        return 1
    fi
    if [[ ! -f "${SSH_CONFIG_SOURCE}" ]]; then
        error "Template not found: ${SSH_CONFIG_SOURCE}"
        return 1
    fi
    if [[ ! -f "${SSH_MAIN_CONFIG}" ]]; then
        error "Main SSH config not found: ${SSH_MAIN_CONFIG}"
        return 1
    fi
}

apply_ssh() {
    local user_name
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        user_has_authorized_key "${user_name}" || return 1
    done
    guard_lockout || return 1

    if sshd_supports_include; then
        SSH_DROPIN_STYLE="dropin"
    else
        SSH_DROPIN_STYLE="managed_block"
        warn "This sshd build predates Include, so the policy goes into ${SSH_MAIN_CONFIG} instead."
    fi

    cat <<EOF
SSH hardening will:
  - allow only: ${SSH_ALLOW_USERS[*]}
  - listen on port: ${SSH_PORT}
  - disable password login and root login
  - install the policy as a ${SSH_DROPIN_STYLE}
  - back up changed files under ${BACKUP_ROOT}/ssh
EOF
    confirm "Apply SSH hardening?" || return 1

    detect_ssh_unit || return 1
    info "SSH service is ${SSH_UNIT}.service"
    check_prerequisites || return 1

    backup_begin ssh
    backup_file "${SSH_MAIN_CONFIG}"
    backup_file "${SSH_CONFIG_TARGET}"
    if [[ -n "${SSH_SOCKET_DROPIN:-}" ]]; then
        backup_file "${SSH_SOCKET_DROPIN}"
    fi
    backup_file "${STATE_FILE}"

    arm_rollback
    if [[ "${SSH_DROPIN_STYLE}" == "dropin" ]]; then
        ensure_sshd_include
        install_dropin
    else
        install_managed_block
    fi
    configure_socket_port || true

    if dry_run; then
        # Nothing was written, so there is no configuration to validate or
        # daemon to reload. Validating the untouched host would be misleading.
        info "Dry run: skipping sshd validation, reload, and effective-port proof."
        disarm_rollback
        success "SSH hardening plan is complete."
        return 0
    fi

    if ! validate_config; then
        error "SSH hardening aborted."
        rollback_component
        exit 1
    fi

    if ! reload_ssh; then
        error "SSH reload failed. Restoring the backup."
        rollback_component
        exit 1
    fi

    # Confirm the loaded daemon really carries the policy, not just the files.
    if ! sshd -T 2>/dev/null | grep -Eiq "^port ${SSH_PORT}$"; then
        error "sshd -T does not report port ${SSH_PORT}. Restoring the backup."
        rollback_component
        exit 1
    fi

    save_state
    disarm_rollback
    success "SSH hardening completed."
    if [[ "${SSH_PORT}" != "22" ]]; then
        warn "Open a second session on port ${SSH_PORT} before closing this one."
    fi
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
        confirm "Roll back the latest SSH backup?" || exit 1
        detect_ssh_unit || true
        rollback_component
        exit 0
    fi

    require_init_tools || return 1
    apply_port_default
    validate_port
    require_allow_users
    apply_ssh
}

main "$@"
