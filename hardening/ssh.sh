#!/usr/bin/env bash
# Apply the SSH drop-in, validate it, reload sshd, and roll back on failure.
# Supports Debian-family and RPM-family servers.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

SSH_CONFIG_SOURCE="${PROJECT_DIR}/config/sshd_config.conf"
SSH_MAIN_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSH_CONFIG_TARGET="${SSH_CONFIG_DIR}/00-linux-server-bootstrap.conf"
SSH_SOCKET_DROPIN="/etc/systemd/system/ssh.socket.d/00-linux-server-bootstrap.conf"
SSH_UNIT=""

usage() {
    cat <<EOF
Usage: bash hardening/ssh.sh --user NAME [--user NAME...] [--port N] [--yes]
       bash hardening/ssh.sh --rollback

Installs ${SSH_CONFIG_TARGET} and reloads SSH.
Password login and root login are disabled. Every --user account must
already exist and must have a public key in ~/.ssh/authorized_keys.

Backups: ${BACKUP_ROOT}/ssh/<timestamp>
EOF
}

detect_ssh_unit() {
    if systemctl is-active --quiet ssh 2>/dev/null && unit_exists ssh.service; then
        SSH_UNIT="ssh"
        return 0
    fi
    if systemctl is-active --quiet sshd 2>/dev/null && unit_exists sshd.service; then
        SSH_UNIT="sshd"
        return 0
    fi
    if unit_exists ssh.service; then
        SSH_UNIT="ssh"
        return 0
    fi
    if unit_exists sshd.service; then
        SSH_UNIT="sshd"
        return 0
    fi
    error "Could not find ssh.service or sshd.service."
    return 1
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
    local include_line='Include /etc/ssh/sshd_config.d/*.conf'
    if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "${SSH_MAIN_CONFIG}"; then
        info "sshd_config already includes sshd_config.d"
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    {
        printf '%s\n' "${include_line}"
        cat -- "${SSH_MAIN_CONFIG}"
    } > "${tmp}"
    install -m 0644 -o root -g root "${tmp}" "${SSH_MAIN_CONFIG}"
    rm -f -- "${tmp}"
    info "Added an Include directive to the top of ${SSH_MAIN_CONFIG}"
}

install_dropin() {
    local tmp
    tmp="$(mktemp)"
    render_dropin "${tmp}"
    mkdir -p -- "${SSH_CONFIG_DIR}"
    install -m 0644 -o root -g root "${tmp}" "${SSH_CONFIG_TARGET}"
    rm -f -- "${tmp}"
    success "Installed ${SSH_CONFIG_TARGET}"
}

configure_debian_socket() {
    if [[ "${OS_FAMILY}" != "debian" ]]; then
        return 0
    fi
    if ! unit_exists ssh.socket socket; then
        return 0
    fi

    mkdir -p -- "$(dirname -- "${SSH_SOCKET_DROPIN}")"
    cat > "${SSH_SOCKET_DROPIN}" <<EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
    chmod 0644 "${SSH_SOCKET_DROPIN}"
    systemctl daemon-reload

    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        warn "ssh.socket was not restarted, so the current session stays up."
        warn "After a second session works on port ${SSH_PORT}, run: systemctl restart ssh.socket"
        return 0
    fi

    info "No SSH session is attached. Restarting ssh.socket."
    systemctl restart ssh.socket
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
    if systemctl is-active --quiet "${SSH_UNIT}"; then
        if systemctl reload "${SSH_UNIT}"; then
            success "SSH service reloaded."
            return 0
        fi
        error "Failed to reload ${SSH_UNIT}.service"
        return 1
    fi
    if systemctl is-active --quiet "${SSH_UNIT}.socket"; then
        success "${SSH_UNIT}.socket is active. The next connection reads the new configuration."
        return 0
    fi
    if systemctl enable --now "${SSH_UNIT}"; then
        success "Started ${SSH_UNIT}.service"
        return 0
    fi
    error "Failed to start ${SSH_UNIT}.service"
    return 1
}

reload_restored_ssh() {
    systemctl daemon-reload || true
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
    if [[ "${ROLLBACK_DONE}" -eq 1 ]]; then
        return 0
    fi
    ROLLBACK_DONE=1

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
        pkg_try_install openssh-server
    fi
    if ! command -v sshd >/dev/null 2>&1; then
        error "sshd is still not installed."
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        error "systemctl is required."
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

    cat <<EOF
SSH hardening will:
  - allow only: ${SSH_ALLOW_USERS[*]}
  - listen on port: ${SSH_PORT}
  - disable password login and root login
  - back up changed files under ${BACKUP_ROOT}/ssh
EOF
    confirm "Apply SSH hardening?" || return 1

    detect_ssh_unit
    info "SSH service is ${SSH_UNIT}.service"
    check_prerequisites

    backup_begin ssh
    backup_file "${SSH_MAIN_CONFIG}"
    backup_file "${SSH_CONFIG_TARGET}"
    backup_file "${SSH_SOCKET_DROPIN}"
    backup_file "${STATE_FILE}"

    arm_rollback
    ensure_sshd_include
    install_dropin
    configure_debian_socket

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

    save_state
    disarm_rollback
    success "SSH hardening completed."
    if [[ "${SSH_PORT}" != "22" && "${OS_FAMILY}" == "debian" ]]; then
        warn "If ssh.socket is enabled, restart it from another session: systemctl restart ssh.socket"
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

    if [[ "${ACTION}" == "rollback" ]]; then
        confirm "Roll back the latest SSH backup?" || exit 1
        detect_ssh_unit || true
        rollback_component
        exit 0
    fi

    apply_port_default
    validate_port
    require_allow_users
    apply_ssh
}

main "$@"
