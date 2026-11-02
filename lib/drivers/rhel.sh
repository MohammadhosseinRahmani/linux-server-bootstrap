#!/usr/bin/env bash
# RPM-family driver: dnf or yum, firewalld, SELinux, sshd.service.
# Covers RHEL, Rocky, AlmaLinux, CentOS, Oracle Linux, Amazon Linux, Fedora,
# and the other EL derivatives that lib/os.sh maps into this family.
#
# Sourced by lib/os.sh. Implements the drv_* contract only.

# shellcheck source=_firewalld.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_firewalld.sh"
# shellcheck source=_mac.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_mac.sh"
# shellcheck source=_pam.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_pam.sh"

# This family has no socket-activated sshd; the empty value is the answer, and
# hardening/ssh.sh reads it before backing a drop-in up.
# shellcheck disable=SC2034
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

drv_mac_enforce() {
    mac_enforce_selinux
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
    if ! locale_is_available "${locale}"; then
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

# EL8 and newer build the stacks with authselect, and the with-faillock feature
# is the supported way to turn the module on: a hand-edit there is overwritten by
# the next authselect run. EL7 has authconfig for the same job. Only when neither
# tool exists is the stack spliced directly.
drv_lockout_files() {
    printf '%s\n' /etc/security/faillock.conf "${PAM_DIR}/system-auth" "${PAM_DIR}/password-auth"
}

drv_lockout_apply() {
    local deny="${1:-3}" fail_interval="${2:-900}" unlock_time="${3:-900}"

    if ! pam_faillock_module_path >/dev/null 2>&1; then
        error "pam_faillock.so is not installed, so account lockout cannot be enabled."
        return 1
    fi

    faillock_conf_write "${deny}" "${fail_interval}" "${unlock_time}" || return 1

    if command -v authselect >/dev/null 2>&1; then
        local profile
        profile="$(authselect current 2>/dev/null | awk '/Profile ID:/ { print $3; exit }')"
        if [[ -n "${profile}" ]] \
            && authselect list-features "${profile}" 2>/dev/null | grep -qx with-faillock; then
            info "Enabling faillock through authselect on profile ${profile}."
            run_cmd authselect select "${profile}" with-faillock --force
            return 0
        fi
        warn "The authselect profile ${profile:-unknown} has no with-faillock feature, so the stacks are edited directly."
    elif command -v authconfig >/dev/null 2>&1; then
        info "Enabling faillock through authconfig."
        run_cmd authconfig --enablefaillock \
            --faillockargs="deny=${deny} unlock_time=${unlock_time}" --update
        return 0
    fi

    # Each stack carries its own auth and account lines on EL, so the same file is
    # spliced for both record types.
    pam_splice_faillock "${PAM_DIR}/system-auth" "${PAM_DIR}/system-auth" || return 1
    pam_splice_faillock "${PAM_DIR}/password-auth" "${PAM_DIR}/password-auth"
}

drv_pwquality_pkg() {
    printf 'libpwquality\n'
}
