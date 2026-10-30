#!/usr/bin/env bash
# Shared firewalld backend for RPM-family and SUSE drivers.
# Sourced by lib/drivers/rhel.sh and lib/drivers/suse.sh, which supply
# drv_pkg_install and the package name.
#
# firewalld's default zone already rejects unsolicited inbound traffic, so this
# backend adds allow rules and does not change the zone target. Changing the
# target affects every service on the host and is left to the operator.

_drv_fw_was_active=0

firewalld_installed() {
    command -v firewall-cmd >/dev/null 2>&1
}

# Runtime changes need the daemon; when it is stopped the permanent configuration
# is edited with firewall-offline-cmd instead.
_firewalld_cmd() {
    if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
        run_cmd firewall-cmd "$@"
    else
        run_cmd firewall-offline-cmd "$@"
    fi
}

_firewalld_query() {
    if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
        firewall-cmd "$@" >/dev/null 2>&1
    else
        firewall-offline-cmd "$@" >/dev/null 2>&1
    fi
}

drv_fw_backend() {
    printf 'firewalld\n'
}

drv_fw_install() {
    drv_pkg_install firewalld
}

drv_fw_backup_paths() {
    printf '/etc/firewalld\n'
}

drv_fw_snapshot() {
    if firewalld_installed; then
        firewall-cmd --list-all > "$1" 2>&1 || true
    else
        printf 'firewall-cmd is not installed\n' > "$1"
    fi
}

drv_fw_record_state() {
    _drv_fw_was_active=0
    if svc_is_active firewalld; then
        _drv_fw_was_active=1
    fi
    record_kv UFW_ACTIVE 0
    record_kv FIREWALLD_ACTIVE "${_drv_fw_was_active}"
}

drv_fw_restore_runtime() {
    local dir="$1"
    # shellcheck disable=SC1091
    source "${dir}/manifest.env"
    if [[ "${FIREWALLD_ACTIVE:-0}" == "1" ]]; then
        svc_enable_now firewalld || error "Could not start firewalld after restore."
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif svc_unit_exists firewalld.service; then
        svc_disable_now firewalld || true
    fi
}

drv_fw_port_is_allowed() {
    local port="$1"
    _firewalld_query --query-port="${port}/tcp"
}

drv_fw_allow() {
    local port="$1"
    if drv_fw_port_is_allowed "${port}"; then
        info "firewalld already allows ${port}/tcp"
        return 0
    fi
    _firewalld_cmd --add-port="${port}/tcp"
    if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
        if ! _firewalld_query --permanent --query-port="${port}/tcp"; then
            run_cmd firewall-cmd --permanent --add-port="${port}/tcp"
        fi
    fi
}

drv_fw_deny_others() {
    info "firewalld's default zone rejects inbound connections that no rule allows."
}

drv_fw_enable() {
    if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
        run_cmd firewall-cmd --reload
    else
        svc_enable_now firewalld
    fi
}

drv_fw_close() {
    local port="$1"
    if drv_fw_port_is_allowed "${port}"; then
        _firewalld_cmd --remove-port="${port}/tcp" || true
        if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
            run_cmd firewall-cmd --permanent --remove-port="${port}/tcp" || true
        fi
    fi
}

# Port 22 is normally opened through the ssh service rather than a raw port.
drv_fw_close_service_ssh() {
    if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
        run_cmd firewall-cmd --permanent --remove-service=ssh || true
        run_cmd firewall-cmd --remove-service=ssh || true
    else
        run_cmd firewall-offline-cmd --remove-service=ssh || true
    fi
}

drv_fw_open_service_ssh() {
    if [[ "${_drv_fw_was_active}" -eq 1 ]]; then
        run_cmd firewall-cmd --permanent --add-service=ssh || true
    else
        run_cmd firewall-offline-cmd --add-service=ssh || true
    fi
}

# firewalld ships a named "ssh" service object for port 22, so opening 22 has two
# paths. This keeps the port rule and the service object consistent, and never
# closes a port that the live session still needs.
drv_fw_apply_port() {
    local port="$1"
    local keep="${2:-}"

    drv_fw_allow "${port}"
    if [[ -n "${keep}" ]]; then
        drv_fw_allow "${keep}"
    fi

    if [[ "${port}" == "22" || "${keep}" == "22" ]]; then
        drv_fw_open_service_ssh
    else
        drv_fw_close_service_ssh
        drv_fw_close 22
    fi
}

drv_fw_is_active() {
    svc_is_active firewalld
}

drv_fw_status_text() {
    firewall-cmd --list-all
}

drv_fw_port_is_open() {
    local port="$1"
    drv_fw_is_active || return 1
    if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
        return 0
    fi
    if [[ "${port}" == "22" ]] && firewall-cmd --query-service=ssh >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

drv_ssh_unit() {
    if svc_is_active sshd.service; then
        printf 'sshd\n'
        return 0
    fi
    if svc_unit_exists sshd.service; then
        printf 'sshd\n'
        return 0
    fi
    if svc_is_active ssh.service || svc_unit_exists ssh.service; then
        printf 'ssh\n'
        return 0
    fi
    error "Could not find sshd.service or ssh.service."
    return 1
}

drv_ssh_socket_setup() {
    # RPM and SUSE hosts run sshd as a plain service.
    return 1
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
    printf 'chronyd\n'
}

drv_f2b_action() {
    if command -v firewall-cmd >/dev/null 2>&1; then
        printf 'firewallcmd-rich-rules\n'
    else
        printf '\n'
    fi
}

drv_audit_rules_file() {
    printf '/etc/audit/rules.d/99-linux-server-bootstrap.rules\n'
}

# augenrules rebuilds the single rules file from every fragment in rules.d, which
# is the layout all three RPM families use. auditctl -R is the fallback for a
# host where the audit package ships the binary but not the helper.
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

# Cleartext remote shells and legacy name services are the default list. Printer,
# scanner and file-share daemons are only listed when the caller asks for them,
# because disabling one of those is a feature removal, not a hardening step.
drv_legacy_services() {
    local scope="${1:-cleartext}"
    printf '%s\n' telnet.socket rsh.socket rlogin.socket rexec.socket tftp.socket xinetd ypbind
    if [[ "${scope}" == "all" ]]; then
        printf '%s\n' avahi-daemon cups nfs-server rpcbind
    fi
}
