#!/usr/bin/env bash
# Debian-family driver: apt, ufw, AppArmor, ssh.socket where present.
# Sourced by lib/os.sh. Implements the drv_* contract only.

# shellcheck source=_mac.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_mac.sh"
# shellcheck source=_pam.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/_pam.sh"

_drv_apt_refresh() {
    if [[ "${_DRV_APT_REFRESHED:-0}" -eq 1 ]]; then
        return 0
    fi
    _DRV_APT_REFRESHED=1
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -qq
}

drv_pkg_install() {
    require_pkg_mgr || return 1
    _drv_apt_refresh
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

drv_pkg_install_remote() {
    require_pkg_mgr || return 1
    _drv_apt_refresh
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y "$1"
}

drv_updates_apply() {
    require_pkg_mgr || return 1
    _drv_apt_refresh
    run_cmd env DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold dist-upgrade -y
}

drv_fw_backend() {
    printf 'ufw\n'
}

drv_fw_install() {
    drv_pkg_install ufw
}

drv_fw_backup_paths() {
    printf '/etc/ufw\n'
}

drv_fw_snapshot() {
    ufw status verbose > "$1" 2>&1 || true
}

drv_fw_record_state() {
    local active=0
    if drv_fw_is_active; then
        active=1
    fi
    record_kv UFW_ACTIVE "${active}"
    record_kv FIREWALLD_ACTIVE 0
}

drv_fw_restore_runtime() {
    local dir="$1"
    # shellcheck disable=SC1091
    source "${dir}/manifest.env"
    if ! command -v ufw >/dev/null 2>&1; then
        return 0
    fi
    if [[ "${UFW_ACTIVE:-0}" == "1" ]]; then
        ufw --force enable || error "Could not re-enable ufw after restore."
        ufw reload || true
    else
        ufw --force disable || true
    fi
}

drv_fw_port_is_allowed() {
    ufw status 2>/dev/null | awk -v rule="$1/tcp" '$1 == rule { found = 1 } END { exit found ? 0 : 1 }'
}

drv_fw_allow() {
    local port="$1"
    local comment="${2:-linux-server-bootstrap}"
    if drv_fw_port_is_allowed "${port}"; then
        info "ufw already allows ${port}/tcp"
        return 0
    fi
    run_cmd ufw allow "${port}/tcp" comment "${comment}"
}

drv_fw_apply_port() {
    local port="$1"
    local keep="${2:-}"

    drv_fw_allow "${port}" "linux-server-bootstrap ssh"
    if [[ -n "${keep}" ]]; then
        drv_fw_allow "${keep}" "linux-server-bootstrap current session"
    fi

    if [[ "${port}" != "22" && "${keep}" != "22" ]]; then
        drv_fw_close 22
    fi
}

drv_fw_port_is_open() {
    local port="$1"
    drv_fw_is_active && drv_fw_port_is_allowed "${port}"
}

drv_fw_deny_others() {
    run_cmd ufw default deny incoming
    run_cmd ufw default allow outgoing
}

drv_fw_enable() {
    run_cmd ufw --force enable
}

drv_fw_close() {
    local port="$1"
    if drv_fw_port_is_allowed "${port}"; then
        run_cmd ufw --force delete allow "${port}/tcp" || warn "Could not delete the ufw rule for ${port}/tcp."
    fi
}

drv_fw_is_active() {
    ufw status 2>/dev/null | awk 'NR == 1 && /Status: active/ { found = 1 } END { exit found ? 0 : 1 }'
}

drv_fw_status_text() {
    ufw status verbose
}

drv_ssh_unit() {
    local candidate
    for candidate in ssh sshd; do
        if svc_is_active "${candidate}.service"; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    for candidate in ssh sshd; do
        if svc_unit_exists "${candidate}.service"; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    error "Could not find ssh.service or sshd.service."
    return 1
}

# Debian 12 and later, and Ubuntu 24.04 and later, can activate sshd through
# ssh.socket. The port then lives in the socket unit, not sshd_config.
SSH_SOCKET_DROPIN="/etc/systemd/system/ssh.socket.d/00-linux-server-bootstrap.conf"

drv_ssh_socket_setup() {
    local port="$1"
    if ! svc_unit_exists ssh.socket socket; then
        return 1
    fi

    local dropin="${SSH_SOCKET_DROPIN}"
    run_cmd mkdir -p -- "$(dirname -- "${dropin}")"
    if dry_run; then
        echo "  [dry-run] write ${dropin} (ListenStream=${port})"
        return 0
    fi
    cat > "${dropin}" <<EOF
[Socket]
ListenStream=
ListenStream=${port}
EOF
    chmod 0644 "${dropin}"
    svc_daemon_reload
    printf '%s\n' "${dropin}"
    return 0
}

drv_f2b_action() {
    if command -v ufw >/dev/null 2>&1; then
        printf 'ufw\n'
    else
        printf '\n'
    fi
}

drv_f2b_prepare_repo() {
    # fail2ban is in the main Debian and Ubuntu archives.
    return 0
}

drv_timezone_apply() {
    local zone="$1"
    if [[ ! -f "/usr/share/zoneinfo/${zone}" ]]; then
        error "Unknown timezone: ${zone}"
        return 1
    fi
    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "${zone}" > "${tmp}"
    install_file 0644 "${tmp}" /etc/timezone
    rm -f -- "${tmp}"
    # tzdata rewrites /etc/localtime and restarts the services that read it.
    run_cmd dpkg-reconfigure -f noninteractive tzdata
}

drv_locale_apply() {
    local locale="$1"
    if ! command -v locale-gen >/dev/null 2>&1; then
        error "locale-gen is missing. Install the locales package (apt install locales)."
        return 1
    fi
    if ! locale -a 2>/dev/null | grep -Fxq "${locale}"; then
        info "Generating ${locale}..."
        run_cmd locale-gen "${locale}"
    fi
    run_cmd update-locale "LANG=${locale}"
}

drv_timezone_file() {
    printf '/etc/timezone\n'
}

drv_locale_files() {
    printf '/etc/locale.gen\n/etc/default/locale\n'
}

drv_mac_name() {
    if command -v aa-status >/dev/null 2>&1 || [[ -d /sys/kernel/security/apparmor ]]; then
        printf 'apparmor\n'
    else
        printf 'none\n'
    fi
}

drv_mac_install() {
    drv_pkg_install apparmor apparmor-utils
}

drv_mac_status() {
    if command -v aa-status >/dev/null 2>&1; then
        aa-status --enabled 2>/dev/null && printf 'AppArmor is enabled\n' || printf 'AppArmor is not enabled\n'
    else
        printf 'aa-status is not installed\n'
    fi
}

drv_sysctl_dir() {
    printf '/etc/sysctl.d\n'
}

drv_sysctl_file() {
    printf '/etc/sysctl.d/99-linux-server-bootstrap.conf\n'
}

drv_audit_pkg() {
    printf 'auditd\n'
}

drv_timesync_pkg() {
    printf 'chrony\n'
}

drv_timesync_unit() {
    printf 'chrony\n'
}

drv_unattended_setup() {
    drv_pkg_install unattended-upgrades
    if dry_run; then
        echo "  [dry-run] write /etc/apt/apt.conf.d/20auto-upgrades"
        return 0
    fi
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    chmod 0644 /etc/apt/apt.conf.d/20auto-upgrades
}

drv_crypto_policy() {
    warn "Debian-family systems have no update-crypto-policies command; SSH algorithm lists carry the policy."
    return 1
}

drv_mac_enforce() {
    mac_enforce_apparmor
}

drv_audit_rules_file() {
    printf '/etc/audit/rules.d/99-linux-server-bootstrap.rules\n'
}

drv_audit_apply() {
    if command -v augenrules >/dev/null 2>&1; then
        run_cmd augenrules --load
        return 0
    fi
    if command -v auditctl >/dev/null 2>&1; then
        run_cmd auditctl -R "$(drv_audit_rules_file)"
        return 0
    fi
    error "Neither augenrules nor auditctl is installed, so the rules cannot be loaded."
    return 1
}

drv_legacy_services() {
    local scope="${1:-cleartext}"
    printf '%s\n' telnet.socket rsh.socket rlogin.socket rexec.socket tftp.socket xinetd nis
    if [[ "${scope}" == "all" ]]; then
        printf '%s\n' avahi-daemon cups cups-browsed nfs-kernel-server rpcbind rpcbind.socket
    fi
}

# Debian's stack is generated by pam-auth-update, but the auth and account lines
# in common-auth and common-account are what every service actually reads.
drv_lockout_files() {
    printf '%s\n' /etc/security/faillock.conf "${PAM_DIR}/common-auth" "${PAM_DIR}/common-account"
}

drv_lockout_apply() {
    local module
    if ! module="$(pam_faillock_module_path)"; then
        error "pam_faillock.so is not installed. On Debian it ships in libpam-modules."
        return 1
    fi
    info "Using ${module}"

    faillock_conf_write "${1:-3}" "${2:-900}" "${3:-900}" || return 1
    pam_splice_faillock "${PAM_DIR}/common-auth" "${PAM_DIR}/common-account"
}

drv_pwquality_pkg() {
    printf 'libpam-pwquality\n'
}
