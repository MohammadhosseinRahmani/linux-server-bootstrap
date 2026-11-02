#!/usr/bin/env bash
# Create or prepare the administrative accounts that SSH will allow.
#
# A key is mandatory: the SSH stage disables password login, so an account without a
# public key would lock the operator out. Sudo is granted through a drop-in file that
# visudo validates before it is installed.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

GRANT_SUDO=0
KEY_FILES=()
EXTRA_GROUPS=""

usage() {
    cat <<EOF
Usage: bash setup/users.sh --user NAME [--user NAME...] [options] [--yes]
       bash setup/users.sh --rollback

Options:
  --user NAME       Account to create or prepare. Repeatable.
  --key FILE        Public key file to install. Repeatable.
  --sudo            Grant sudo through /etc/sudoers.d (password required).
  --groups G1,G2    Additional groups for the account.

--rollback restores the key files and sudo drop-ins only. Accounts are never
deleted, because deleting a user also removes the files it owns.

Backups: ${BACKUP_ROOT}/users/<timestamp>
EOF
}

parse_users_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user|--key)
                if [[ $# -lt 2 ]]; then
                    error "$1 requires a value."
                    return 2
                fi
                if [[ "$1" == "--user" ]]; then
                    parse_standard_args --user "$2" || return 2
                else
                    KEY_FILES+=("$2")
                fi
                shift 2
                ;;
            --groups)
                if [[ $# -lt 2 ]]; then
                    error "--groups requires a comma separated list."
                    return 2
                fi
                EXTRA_GROUPS="$2"
                shift 2
                ;;
            --sudo)
                GRANT_SUDO=1
                shift
                ;;
            --yes|--dry-run|--rollback|-h|--help)
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

validate_inputs() {
    if ((${#SSH_ALLOW_USERS[@]} == 0)); then
        error "Pass at least one --user."
        return 1
    fi

    local user_name group
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        if [[ "${user_name}" == "root" ]]; then
            error "Do not prepare root; the SSH stage disables root login."
            return 1
        fi
        if [[ ! "${user_name}" =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]]; then
            error "Invalid username: ${user_name}"
            return 1
        fi
    done

    if [[ -n "${EXTRA_GROUPS}" ]]; then
        # Group names are regex-validated above, so splitting on commas is safe.
        # shellcheck disable=SC2206
        for group in ${EXTRA_GROUPS//,/ }; do
            if [[ ! "${group}" =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]]; then
                error "Invalid group name: ${group}"
                return 1
            fi
        done
    fi

    local file
    if ((${#KEY_FILES[@]} > 0)); then
        for file in "${KEY_FILES[@]}"; do
            if [[ ! -r "${file}" ]]; then
                error "Key file is not readable: ${file}"
                return 1
            fi
            validate_public_key_file "${file}" || return 1
        done
    fi
}

validate_public_key_file() {
    local file="$1" line number=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        number=$((number + 1))
        case "${line}" in
            ''|'#'*) continue ;;
        esac
        if ! grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-)[[:space:]]' <<< "${line}"; then
            error "${file} line ${number} is not an SSH public key."
            return 1
        fi
    done < "${file}"
    if [[ "${number}" -eq 0 ]]; then
        error "${file} is empty."
        return 1
    fi
}

user_exists() {
    id "$1" >/dev/null 2>&1
}

user_home() {
    getent passwd "$1" | awk -F: '{ print $6 }'
}

create_user() {
    local user_name="$1"
    if user_exists "${user_name}"; then
        info "Account ${user_name} already exists."
        return 0
    fi
    require_command useradd || return 1
    run_cmd useradd -m -s /bin/bash -- "${user_name}"
    success "Created account ${user_name}."
    warn "${user_name} has no password, which is intended: log in with the key."
}

apply_groups() {
    local user_name="$1"
    if [[ -z "${EXTRA_GROUPS}" ]]; then
        return 0
    fi
    local group
    for group in ${EXTRA_GROUPS//,/ }; do
        if ! getent group "${group}" >/dev/null 2>&1; then
            warn "Group ${group} does not exist, so it was skipped for ${user_name}."
            continue
        fi
        run_cmd usermod -aG "${group}" -- "${user_name}"
    done
}

install_keys() {
    local user_name="$1"
    if ((${#KEY_FILES[@]} == 0)); then
        return 0
    fi

    local home ssh_dir keys_file file added=0 primary_group
    # A brand new account has no passwd entry yet, so the lookup is allowed to fail.
    home="$(user_home "${user_name}" || true)"
    if [[ -z "${home}" ]] && dry_run; then
        # The account does not exist yet, so show the plan against the home
        # directory that useradd -m is about to create.
        home="/home/${user_name}"
    fi
    if [[ -z "${home}" ]]; then
        error "Could not find the home directory of ${user_name}."
        return 1
    fi
    ssh_dir="${home}/.ssh"
    keys_file="${ssh_dir}/authorized_keys"
    primary_group="$(id -gn "${user_name}" 2>/dev/null || printf '%s' "${user_name}")"

    run_cmd mkdir -p -- "${ssh_dir}"
    run_cmd chmod 0700 -- "${ssh_dir}"
    run_cmd chown "${user_name}:${primary_group}" -- "${ssh_dir}"

    local tmp
    tmp="$(mktemp)"
    if [[ -f "${keys_file}" ]]; then
        cat -- "${keys_file}" > "${tmp}"
    fi

    for file in "${KEY_FILES[@]}"; do
        local line
        while IFS= read -r line || [[ -n "${line}" ]]; do
            case "${line}" in
                ''|'#'*) continue ;;
            esac
            if grep -Fxq -- "${line}" "${tmp}"; then
                info "Key is already authorized for ${user_name}."
                continue
            fi
            printf '%s\n' "${line}" >> "${tmp}"
            added=$((added + 1))
        done < "${file}"
    done

    if [[ "${added}" -eq 0 ]]; then
        rm -f -- "${tmp}"
        info "No new keys for ${user_name}."
        return 0
    fi

    install_file 0600 "${tmp}" "${keys_file}"
    rm -f -- "${tmp}"
    run_cmd chown "${user_name}:${primary_group}" -- "${keys_file}"
    run_cmd chmod 0600 -- "${keys_file}"
    success "Installed ${added} key(s) for ${user_name}."
}

grant_sudo() {
    local user_name="$1"
    local dropin="/etc/sudoers.d/99-linux-server-bootstrap-${user_name}"

    if ! dry_run && ! command -v sudo >/dev/null 2>&1; then
        info "Installing sudo..."
        drv_pkg_install sudo || return 1
    fi

    local tmp
    tmp="$(mktemp)"
    printf '%s ALL=(ALL:ALL) ALL\n' "${user_name}" > "${tmp}"

    if ! dry_run && command -v visudo >/dev/null 2>&1; then
        if ! visudo -c -f "${tmp}" >/dev/null 2>&1; then
            error "visudo rejected the sudoers drop-in for ${user_name}."
            rm -f -- "${tmp}"
            return 1
        fi
    fi

    # A minimal image can ship without sudo at all, which the install above exists to
    # fix. Under --dry-run that install is only simulated, so a missing directory says
    # nothing about the real run and must not abort the plan.
    if ! dry_run && [[ ! -d /etc/sudoers.d ]]; then
        error "/etc/sudoers.d does not exist, so sudo cannot be granted safely."
        rm -f -- "${tmp}"
        return 1
    fi
    install_file 0440 "${tmp}" "${dropin}"
    rm -f -- "${tmp}"
    success "Granted sudo to ${user_name} through ${dropin}"
}

check_key_present() {
    local user_name="$1" home keys
    home="$(user_home "${user_name}")"
    keys="${home}/.ssh/authorized_keys"
    if [[ -s "${keys}" ]]; then
        return 0
    fi
    error "${user_name} has no key at ${keys}."
    error "Pass --key FILE, otherwise the SSH stage will lock you out."
    return 1
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir users)" || return 1
    fi

    warn "Rolling back user files from ${dir}"
    warn "Accounts are left in place; only keys and sudo drop-ins are restored."
    rollback_dir "${dir}" || return 1
    finish_rollback_pointer users
    success "users rollback finished."
}

apply_users() {
    cat <<EOF
User setup will:
  - prepare: ${SSH_ALLOW_USERS[*]}
  - install ${#KEY_FILES[@]} key file(s)
EOF
    if [[ "${GRANT_SUDO}" -eq 1 ]]; then
        printf '  - grant sudo through /etc/sudoers.d\n'
    fi
    if [[ -n "${EXTRA_GROUPS}" ]]; then
        printf '  - add the accounts to: %s\n' "${EXTRA_GROUPS}"
    fi
    printf '  - back up the files it replaces under %s/users\n' "${BACKUP_ROOT}"
    confirm "Apply user setup?" || return 1

    backup_begin users

    local user_name home
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        home="$(user_home "${user_name}" 2>/dev/null || true)"
        if [[ -n "${home}" ]]; then
            backup_file "${home}/.ssh/authorized_keys"
        fi
        backup_file "/etc/sudoers.d/99-linux-server-bootstrap-${user_name}"
    done
    backup_file "${STATE_FILE}"

    arm_rollback

    local -a sudo_users=()
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        create_user "${user_name}" || return 1
        apply_groups "${user_name}"
        install_keys "${user_name}"
        if [[ "${GRANT_SUDO}" -eq 1 ]]; then
            grant_sudo "${user_name}" || return 1
            sudo_users+=("${user_name}")
        fi
    done

    if ! dry_run; then
        for user_name in "${SSH_ALLOW_USERS[@]}"; do
            check_key_present "${user_name}" || return 1
        done
    fi

    state_set ADMIN_USERS "${SSH_ALLOW_USERS[*]}"
    # Only the accounts this pass actually got a sudoers file for, so the verifier
    # does not report a missing drop-in for a run that never passed --sudo.
    if [[ "${#sudo_users[@]}" -gt 0 ]]; then
        state_set SUDO_USERS "${sudo_users[*]}"
    fi
    save_state
    disarm_rollback
    success "User setup completed."
    printf '  Next: bash hardening/ssh.sh --user %s ... restricts SSH to these accounts.\n' \
        "${SSH_ALLOW_USERS[0]}"
}

main() {
    parse_users_args "$@" || {
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
        confirm "Roll back the latest user setup backup?" || exit 1
        rollback_component
        exit 0
    fi

    require_pkg_mgr || return 1
    validate_inputs || return 1
    apply_users
}

main "$@"
