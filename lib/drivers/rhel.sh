#!/usr/bin/env bash
# RPM-family driver: dnf or yum, firewalld, SELinux, sshd.service.
# Covers RHEL, Rocky, AlmaLinux, CentOS, Oracle Linux, Amazon Linux, Fedora,
# and the other EL derivatives that lib/os.sh maps into this family.
#
# Sourced by lib/os.sh. Implements the drv_* contract only.

# shellcheck source=_firewalld.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_firewalld.sh"

SSH_SOCKET_DROPIN=""

drv_fw_install() {
    drv_pkg_install firewalld
}

drv_pkg_install() {
    require_pkg_mgr || return 1
    case "${PKG_MGR}" in
        dnf)
            run_cmd dnf install -y "$@"
            ;;
        yum)
            run_cmd yum install -y "$@"
            ;;
        *)
            error "Unsupported package manager: ${PKG_MGR}"
            return 1
            ;;
    esac
}

drv_pkg_install_remote() {
    require_pkg_mgr || return 1
    case "${PKG_MGR}" in
        dnf)
            run_cmd dnf install -y "$1"
            ;;
        yum)
            run_cmd yum install -y "$1"
            ;;
        *)
            error "Unsupported package manager: ${PKG_MGR}"
            return 1
            ;;
    esac
}

drv_updates_apply() {
    require_pkg_mgr || return 1
    case "${PKG_MGR}" in
        dnf)
            run_cmd dnf -y update
            ;;
        yum)
            run_cmd yum -y update
            ;;
    esac
}

# fail2ban is not in the base RHEL repositories, so EPEL has to be added first.
# Fedora and Amazon Linux ship it in their own repositories.
drv_f2b_prepare_repo() {
    if os_is_id fedora || os_is_id amzn; then
        return 0
    fi
    if rpm -q epel-release >/dev/null 2>&1; then
        return 0
    fi

    info "Installing EPEL so fail2ban is available..."
    if drv_pkg_install epel-release; then
        return 0
    fi

    local major
    major="$(rpm -E %rhel 2>/dev/null || true)"
    if [[ -z "${major}" || "${major}" == "%rhel" ]]; then
        error "Could not detect the EL major version needed for EPEL."
        return 1
    fi
    drv_pkg_install_remote "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm"
}

drv_mac_name() {
    printf 'selinux\n'
}

drv_timezone_apply() {
    local zone="$1"
    if [[ ! -f "/usr/share/zoneinfo/${zone}" ]]; then
        error "Unknown timezone: ${zone}"
        return 1
    fi
    if [[ "${INIT_SYSTEM}" == "systemd" ]] && command -v timedatectl >/dev/null 2>&1; then
        run_cmd timedatectl set-timezone "${zone}"
        return 0
    fi
    run_cmd ln -sf "/usr/share/zoneinfo/${zone}" /etc/localtime
}

drv_locale_apply() {
    local locale="$1"
    if ! locale -a 2>/dev/null | grep -Fxq "${locale}"; then
        error "${locale} is not available. Install glibc-langpack-en or generate it with localedef."
        return 1
    fi
    if [[ "${INIT_SYSTEM}" == "systemd" ]] && command -v localectl >/dev/null 2>&1; then
        run_cmd localectl set-locale "LANG=${locale}"
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    printf 'LANG=%s\n' "${locale}" > "${tmp}"
    install_file 0644 "${tmp}" /etc/locale.conf
    rm -f -- "${tmp}"
}

drv_timezone_file() {
    printf '/etc/localtime\n'
}

drv_locale_files() {
    printf '/etc/locale.conf\n'
}

drv_mac_install() {
    drv_pkg_install libselinux-utils policycoreutils
}

drv_mac_status() {
    if command -v getenforce >/dev/null 2>&1; then
        getenforce
    else
        printf 'getenforce is not installed\n'
    fi
}

drv_unattended_setup() {
    local major
    major="$(os_major_version)"
    if os_is_id fedora || os_is_id amzn || (( major >= 8 )); then
        drv_pkg_install dnf-automatic
        if svc_unit_exists dnf-automatic-install.timer; then
            svc_enable_now dnf-automatic-install.timer
        else
            svc_enable_now dnf-automatic.timer
        fi
    else
        drv_pkg_install yum-cron
        svc_enable_now yum-cron
    fi
}

drv_crypto_policy() {
    local profile="${1:-DEFAULT}"
    local major
    major="$(os_major_version)"
    if ! os_is_id fedora && (( major < 8 )); then
        warn "update-crypto-policies needs EL8 or newer; this system is ${OS_ID} ${OS_VERSION}."
        return 1
    fi
    if ! command -v update-crypto-policies >/dev/null 2>&1; then
        warn "update-crypto-policies is not installed, so the system crypto policy is unchanged."
        return 1
    fi
    run_cmd update-crypto-policies --set "${profile}"
}
