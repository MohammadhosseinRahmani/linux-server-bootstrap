#!/usr/bin/env bash

set -euo pipefail

# --------------------------------------------------
# SSH Hardening Script
# Project: linux-server-bootstrap
# Author: Mohammad Rahmani
# --------------------------------------------------


# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SSH_CONFIG_SOURCE="${PROJECT_DIR}/config/sshd_config.conf"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSH_CONFIG_TARGET="${SSH_CONFIG_DIR}/sshd_config.conf"
BACKUP_DIR="/home/rahmni/backup"


# ------------------------------------------------------------
# Colors
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[OK]${NC} $*"
}


# ------------------------------------------------------------
# Validation
# ------------------------------------------------------------

require_root() {

    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root."
        return 1
    fi

}

check_prerequisites() {

    info "Checking prerequisites..."

    if ! command -v sshd >/dev/null 2>&1; then
        error "sshd command not found."
        return 1
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        error "systemctl command not found."
        return 1
    fi

    if [[ ! -f "${SSH_CONFIG_SOURCE}" ]]; then
        error "SSH configuration source not found:"
        error "${SSH_CONFIG_SOURCE}"
        return 1
    fi

    success "Prerequisites check passed."
}


# ------------------------------------------------------------
# Backup
# ------------------------------------------------------------

backup_config() {

    info "Creating SSH configuration backup..."

    mkdir -p "${BACKUP_DIR}"

    local timestamp
    timestamp="$(date '+%Y%m%d-%H%M%S')"

    BACKUP_FILE="${BACKUP_DIR}/99-linux-server-bootstrap.conf.${timestamp}"

    if [[ -f "${SSH_CONFIG_TARGET}" ]]; then

        cp -a "${SSH_CONFIG_TARGET}" "${BACKUP_FILE}"

        success "Existing hardening configuration backed up:"
        info "${BACKUP_FILE}"

    else

        warn "No previous hardening configuration found."
        info "A rollback will remove the new configuration if validation fails."

    fi
}


# ------------------------------------------------------------
# Install configuration
# ------------------------------------------------------------

install_config() {

    info "Installing SSH hardening configuration..."

    mkdir -p "${SSH_CONFIG_DIR}"

    cp -a "${SSH_CONFIG_SOURCE}" "${SSH_CONFIG_TARGET}"

    chmod 0644 "${SSH_CONFIG_TARGET}"
    chown root:root "${SSH_CONFIG_TARGET}"

    success "SSH hardening configuration installed."
}


# ------------------------------------------------------------
# Validate configuration
# ------------------------------------------------------------

validate_config() {

    info "Validating SSH configuration..."

    if sshd -t; then
        success "SSH configuration is valid."
        return 0
    fi

    error "SSH configuration validation failed."

    rollback_config

    return 1
}


# ------------------------------------------------------------
# Reload SSH
# ------------------------------------------------------------

reload_ssh() {

    info "Reloading SSH service..."

    local service

    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        service="ssh"
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
        service="sshd"
    else
        error "Could not determine SSH service name."
        return 1
    fi

    if systemctl reload "${service}"; then
        success "SSH service reloaded successfully."
    else
        error "Failed to reload SSH service."
        return 1
    fi
}

# ------------------------------------------------------------
# Rollback
# ------------------------------------------------------------

rollback_config() {

    warn "Rolling back SSH configuration..."

    if [[ -n "${BACKUP_FILE}" && -f "${BACKUP_FILE}" ]]; then

        cp -a "${BACKUP_FILE}" "${SSH_CONFIG_TARGET}"

        success "Previous SSH hardening configuration restored."

    else

        rm -f "${SSH_CONFIG_TARGET}"

        success "New SSH hardening configuration removed."

    fi
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
main() {

    info "Starting SSH hardening..."

    require_root
    check_prerequisites

    backup_config
    install_config

    if ! validate_config; then
        error "SSH hardening aborted."
        rollback_config
        exit 1
    fi

    if ! reload_ssh; then
        error "SSH reload failed."
        rollback_config
        exit 1
    fi

    success "SSH hardening completed successfully."
}

main "$@"