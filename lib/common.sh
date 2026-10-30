#!/usr/bin/env bash
# Shared helpers for linux-server-bootstrap.
# Source this file. Do not execute it.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "Source lib/common.sh. Do not execute it." >&2
    exit 1
fi

_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${_LIB_DIR}/.." && pwd)"

# Logging must exist before the helpers below are sourced, because they report
# through info/warn/error.
if [[ -t 1 ]]; then
    BLUE='\033[0;34m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    BLUE=''
    YELLOW=''
    RED=''
    GREEN=''
    NC=''
fi

_log() {
    local level="$1"
    shift
    mkdir -p -- "$(dirname -- "${LOG_FILE}")" 2>/dev/null || true
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${level}" "$*" >> "${LOG_FILE}" 2>/dev/null || true
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    _log INFO "$*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
    _log WARN "$*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    _log ERROR "$*"
}

success() {
    echo -e "${GREEN}[OK]${NC} $*"
    _log OK "$*"
}

# shellcheck source=os.sh
source "${_LIB_DIR}/os.sh"
# shellcheck source=init.sh
source "${_LIB_DIR}/init.sh"

BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/linux-server-bootstrap}"
STATE_DIR="${STATE_DIR:-/etc/linux-server-bootstrap}"
STATE_FILE="${STATE_DIR}/state.env"
LOG_FILE="${LOG_FILE:-/var/log/linux-server-bootstrap.log}"

# Shared paths and markers, so a stage and the verifier cannot disagree about
# where the SSH policy lives.
SSH_MAIN_CONFIG="${SSH_MAIN_CONFIG:-/etc/ssh/sshd_config}"
SSH_CONFIG_DIR="${SSH_CONFIG_DIR:-/etc/ssh/sshd_config.d}"
SSH_CONFIG_TARGET="${SSH_CONFIG_DIR}/00-linux-server-bootstrap.conf"
SSH_INCLUDE_LINE='Include /etc/ssh/sshd_config.d/*.conf'
SSH_BLOCK_BEGIN='# BEGIN linux-server-bootstrap'
SSH_BLOCK_END='# END linux-server-bootstrap'
JAIL_TARGET="${JAIL_TARGET:-/etc/fail2ban/jail.d/00-linux-server-bootstrap.conf}"

SSH_PORT="${SSH_PORT:-22}"
SSH_ALLOW_USERS=()
PORT_SET="${PORT_SET:-0}"
ASSUME_YES="${ASSUME_YES:-0}"
ACTION="${ACTION:-apply}"
SHOW_HELP="${SHOW_HELP:-0}"
BACKUP_DIR="${BACKUP_DIR:-}"
ROLLBACK_ARMED="${ROLLBACK_ARMED:-0}"
ROLLBACK_DONE="${ROLLBACK_DONE:-0}"
DRY_RUN="${DRY_RUN:-0}"

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root."
        return 1
    fi
}

# Commands that change system state go through run_cmd, so --dry-run can print
# the intent without touching the host.
run_cmd() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "  [dry-run] $*"
        _log DRYRUN "$*"
        return 0
    fi
    "$@"
}

dry_run() {
    [[ "${DRY_RUN}" -eq 1 ]]
}

# File writes go through install_file so a dry run never modifies the host.
install_file() {
    local mode="$1"
    local src="$2"
    local dest="$3"
    if dry_run; then
        echo "  [dry-run] install ${src} -> ${dest} (mode ${mode})"
        _log DRYRUN "install ${dest}"
        return 0
    fi
    install -m "${mode}" -o root -g root "${src}" "${dest}"
}

require_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        error "Required command is missing: ${cmd}"
        return 1
    fi
}

# Read-only runs must not need a package manager, so this is called only by
# stages that install something.
require_pkg_mgr() {
    require_command "${PKG_MGR}" || return 1
}

require_init_tools() {
    require_init || return 1
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        require_command systemctl || return 1
    fi
}

parse_standard_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)
                if [[ $# -lt 2 ]]; then
                    error "--user requires a username."
                    return 2
                fi
                SSH_ALLOW_USERS+=("$2")
                shift 2
                ;;
            --port)
                if [[ $# -lt 2 ]]; then
                    error "--port requires a number."
                    return 2
                fi
                SSH_PORT="$2"
                PORT_SET=1
                shift 2
                ;;
            --yes)
                ASSUME_YES=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --rollback)
                ACTION="rollback"
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

apply_port_default() {
    if [[ "${PORT_SET}" -eq 1 ]]; then
        return 0
    fi
    if [[ -f "${STATE_FILE}" ]]; then
        local saved
        saved="$(awk -F= '$1 == "SSH_PORT" { print substr($0, index($0, "=") + 1); exit }' "${STATE_FILE}")"
        if [[ -n "${saved}" ]]; then
            SSH_PORT="${saved}"
            info "Using saved SSH port ${SSH_PORT} from ${STATE_FILE}"
        fi
    fi
}

validate_port() {
    if [[ ! "${SSH_PORT}" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        error "SSH port must be an integer from 1 to 65535. Got: ${SSH_PORT}"
        return 1
    fi
}

validate_username() {
    local user_name="$1"
    if [[ ! "${user_name}" =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid username: ${user_name}"
        return 1
    fi
    if ! id "${user_name}" >/dev/null 2>&1; then
        error "User does not exist: ${user_name}"
        return 1
    fi
}

require_allow_users() {
    if ((${#SSH_ALLOW_USERS[@]} == 0)); then
        error "Pass at least one --user. That account must already have an SSH public key."
        return 1
    fi

    local user_name
    for user_name in "${SSH_ALLOW_USERS[@]}"; do
        validate_username "${user_name}" || return 1
        if [[ "${user_name}" == "root" ]]; then
            error "Do not pass --user root. PermitRootLogin is set to no."
            return 1
        fi
    done
}

load_saved_users_if_empty() {
    if ((${#SSH_ALLOW_USERS[@]} > 0)); then
        return 0
    fi
    if [[ ! -f "${STATE_FILE}" ]]; then
        return 0
    fi
    local line
    line="$(awk -F= '$1 == "SSH_ALLOW_USERS_LINE" { print substr($0, index($0, "=") + 1); exit }' "${STATE_FILE}")"
    if [[ -n "${line}" ]]; then
        # Usernames are validated before they are saved, so word-splitting is safe.
        # shellcheck disable=SC2206
        SSH_ALLOW_USERS=(${line})
    fi
}

save_state() {
    if dry_run; then
        echo "  [dry-run] save state ${SSH_PORT} ${SSH_ALLOW_USERS[*]} -> ${STATE_FILE}"
        _log DRYRUN "save_state"
        return 0
    fi
    load_saved_users_if_empty
    mkdir -p -- "${STATE_DIR}"
    chmod 0755 "${STATE_DIR}"

    local tmp
    tmp="$(mktemp)"
    {
        printf 'SSH_PORT=%s\n' "${SSH_PORT}"
        printf 'SSH_ALLOW_USERS_LINE=%s\n' "${SSH_ALLOW_USERS[*]}"
        printf 'OS_FAMILY=%s\n' "${OS_FAMILY}"
        printf 'OS_ID=%s\n' "${OS_ID}"
        if [[ -n "${SSH_DROPIN_STYLE:-}" ]]; then
            printf 'SSH_DROPIN_STYLE=%s\n' "${SSH_DROPIN_STYLE}"
        fi
    } > "${tmp}"
    install -m 0644 -o root -g root "${tmp}" "${STATE_FILE}"
    rm -f -- "${tmp}"
    info "Saved state to ${STATE_FILE}"
}

state_value() {
    local key="$1"
    [[ -f "${STATE_FILE}" ]] || return 0
    awk -F= -v want="${key}" '$1 == want { print substr($0, index($0, "=") + 1); exit }' "${STATE_FILE}"
}

# fail2ban reads logs through journald on systemd hosts and from the auth log
# everywhere else, so the backend follows the init system rather than the distro.
pick_fail2ban_backend() {
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        printf 'systemd\n'
    else
        printf 'auto\n'
    fi
}

confirm() {
    local prompt="$1"
    if [[ "${ASSUME_YES}" -eq 1 ]]; then
        info "Continuing because --yes was given."
        return 0
    fi
    if [[ ! -t 0 ]]; then
        error "This shell is not interactive. Pass --yes to apply the change."
        return 1
    fi
    local answer
    if ! read -r -p "${prompt} Type YES to continue: " answer; then
        error "Aborted."
        return 1
    fi
    if [[ "${answer}" != "YES" ]]; then
        error "Aborted."
        return 1
    fi
}

current_ssh_server_port() {
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        awk '{ print $4 }' <<< "${SSH_CONNECTION}"
    fi
}

# The port this SSH session is on, when it differs from the port being
# configured. A firewall must keep it open so the operator is not cut off.
extra_session_port() {
    local current
    current="$(current_ssh_server_port || true)"
    if [[ -n "${current}" && "${current}" != "${SSH_PORT}" ]]; then
        printf '%s' "${current}"
    fi
}

backup_begin() {
    local component="$1"
    local timestamp
    timestamp="$(date '+%Y%m%d-%H%M%S')"
    BACKUP_DIR="${BACKUP_ROOT}/${component}/${timestamp}"

    mkdir -p -- "${BACKUP_DIR}/files" "${BACKUP_DIR}/trees" "${BACKUP_DIR}/snapshots"
    chmod 0700 "${BACKUP_ROOT}" "${BACKUP_ROOT}/${component}" "${BACKUP_DIR}" || true

    cat > "${BACKUP_DIR}/manifest.env" <<EOF
component=${component}
timestamp=${timestamp}
EOF
    : > "${BACKUP_DIR}/manifest.list"
    ln -sfn "${BACKUP_DIR}" "${BACKUP_ROOT}/${component}/latest"
    success "Backup directory: ${BACKUP_DIR}"
}

record_kv() {
    if [[ -z "${BACKUP_DIR}" ]]; then
        error "backup_begin was not called."
        return 1
    fi
    printf '%s=%s\n' "$1" "$2" >> "${BACKUP_DIR}/manifest.env"
}

backup_file() {
    local path="$1"
    if [[ -z "${BACKUP_DIR}" ]]; then
        error "backup_begin was not called."
        return 1
    fi

    if [[ -e "${path}" ]]; then
        local dest="${BACKUP_DIR}/files${path}"
        mkdir -p -- "$(dirname -- "${dest}")"
        cp -a -- "${path}" "${dest}"
        printf 'FILE %s\n' "${path}" >> "${BACKUP_DIR}/manifest.list"
        info "Backed up ${path}"
    else
        printf 'MISSING %s\n' "${path}" >> "${BACKUP_DIR}/manifest.list"
        info "No existing file at ${path}"
    fi
}

backup_tree() {
    local path="$1"
    if [[ -z "${BACKUP_DIR}" ]]; then
        error "backup_begin was not called."
        return 1
    fi

    local name
    name="$(basename -- "${path}")"
    if [[ -d "${path}" ]]; then
        rm -rf -- "${BACKUP_DIR}/trees/${name}"
        cp -a -- "${path}" "${BACKUP_DIR}/trees/${name}"
        printf 'TREE %s\n' "${path}" >> "${BACKUP_DIR}/manifest.list"
        info "Backed up directory ${path}"
    else
        printf 'MISSING_TREE %s\n' "${path}" >> "${BACKUP_DIR}/manifest.list"
        info "No existing directory at ${path}"
    fi
}

save_snapshot() {
    local name="$1"
    shift
    if [[ -z "${BACKUP_DIR}" ]]; then
        error "backup_begin was not called."
        return 1
    fi
    "$@" > "${BACKUP_DIR}/snapshots/${name}" 2>&1 || true
    info "Saved snapshot ${BACKUP_DIR}/snapshots/${name}"
}

latest_backup_dir() {
    local component="$1"
    local link="${BACKUP_ROOT}/${component}/latest"
    if [[ ! -L "${link}" ]]; then
        error "No backup exists for ${component} under ${BACKUP_ROOT}"
        return 1
    fi
    readlink -f -- "${link}"
}

rollback_dir() {
    local dir="$1"
    if [[ ! -f "${dir}/manifest.list" ]]; then
        error "Backup manifest is missing: ${dir}/manifest.list"
        return 1
    fi

    local kind path
    while read -r kind path; do
        [[ -z "${kind}" ]] && continue
        case "${kind}" in
            FILE)
                if [[ -e "${dir}/files${path}" ]]; then
                    mkdir -p -- "$(dirname -- "${path}")"
                    cp -a -- "${dir}/files${path}" "${path}"
                    info "Restored ${path}"
                else
                    error "Backup copy is missing for ${path}"
                    return 1
                fi
                ;;
            MISSING)
                rm -f -- "${path}"
                info "Removed ${path}"
                ;;
            TREE)
                if [[ -d "${dir}/trees/$(basename -- "${path}")" ]]; then
                    rm -rf -- "${path}"
                    mkdir -p -- "$(dirname -- "${path}")"
                    cp -a -- "${dir}/trees/$(basename -- "${path}")" "${path}"
                    info "Restored directory ${path}"
                else
                    error "Backup tree is missing for ${path}"
                    return 1
                fi
                ;;
            MISSING_TREE)
                rm -rf -- "${path}"
                info "Removed directory ${path}"
                ;;
            *)
                error "Unknown manifest entry: ${kind} ${path}"
                return 1
                ;;
        esac
    done < "${dir}/manifest.list"
}

promote_previous_backup() {
    local component="$1"
    local root="${BACKUP_ROOT}/${component}"
    local current=""
    if [[ -L "${root}/latest" ]]; then
        current="$(readlink -f -- "${root}/latest")"
    fi

    local target=""
    target="$(
        find "${root}" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
            | sort -nr \
            | awk -v cur="${current}" '$2 != cur { print $2; exit }'
    )"

    if [[ -n "${target}" ]]; then
        ln -sfn "${target}" "${root}/latest"
        info "Next rollback for ${component} will use ${target}"
    else
        rm -f -- "${root}/latest"
        info "No older ${component} backup remains."
    fi
}

arm_rollback() {
    ROLLBACK_ARMED=1
    ROLLBACK_DONE=0
    trap 'unexpected_rollback $?' ERR
}

disarm_rollback() {
    ROLLBACK_ARMED=0
    trap - ERR
}

unexpected_rollback() {
    local rc="$1"
    trap - ERR
    if [[ "${ROLLBACK_ARMED}" -eq 1 && "${ROLLBACK_DONE}" -eq 0 ]]; then
        error "Unexpected error (exit ${rc}). Starting rollback."
        rollback_component || true
    fi
    exit "${rc}"
}

finish_rollback_pointer() {
    local component="$1"
    promote_previous_backup "${component}"
}

# Shared gate for every stage's rollback_component. A dry run must never
# restore or delete host files, and a stage must not roll back twice when both
# the explicit path and the ERR trap fire.
rollback_preflight() {
    if dry_run; then
        warn "Dry run: nothing was applied, so nothing is restored."
        return 1
    fi
    if [[ "${ROLLBACK_DONE}" -eq 1 ]]; then
        return 1
    fi
    ROLLBACK_DONE=1
    return 0
}
