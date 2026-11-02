#!/usr/bin/env bash
# SUSE-family driver: zypper, firewalld, AppArmor (SELinux on SLE when enabled).
# Covers openSUSE Leap, openSUSE Tumbleweed, SLES, and SLED.
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

drv_pkg_install() {
    require_pkg_mgr || return 1
    run_cmd zypper --non-interactive install --no-recommends "$@"
}

drv_pkg_install_remote() {
    require_pkg_mgr || return 1
    run_cmd zypper --non-interactive install "$1"
}

drv_updates_apply() {
    require_pkg_mgr || return 1
    run_cmd zypper --non-interactive update
}

drv_fw_install() {
    if ! command -v firewall-cmd >/dev/null 2>&1 && [[ -x /sbin/SuSEfirewall2 || -x /usr/sbin/SuSEfirewall2 ]]; then
        # SuSEfirewall2 is the old SUSE firewall and has no fail2ban action.
        error "This host uses SuSEfirewall2, which this project does not manage."
        error "Install firewalld (zypper install firewalld) or run with --skip-firewall."
        return 1
    fi
    drv_pkg_install firewalld
}

drv_f2b_prepare_repo() {
    # fail2ban ships in the openSUSE OSS repository; SLE may need Package Hub.
    return 0
}

drv_tzdata_pkg() {
    # SUSE ships the zone database as its own package, not inside glibc.
    printf 'timezone\n'
}

drv_timezone_apply() {
    local zone="$1"
    timezone_is_supported "${zone}" || return 1
    if [[ "${INIT_SYSTEM}" == "systemd" ]] && command -v timedatectl >/dev/null 2>&1; then
        run_cmd timedatectl set-timezone "${zone}"
    else
        run_cmd ln -sf "${ZONEINFO_DIR}/${zone}" /etc/localtime
    fi
    # SUSE keeps its own copy of the zone, and the boot scripts read it.
    local tmp
    tmp="$(mktemp)"
    printf 'TIMEZONE="%s"\n' "${zone}" > "${tmp}"
    install_file 0644 "${tmp}" /etc/sysconfig/clock
    rm -f -- "${tmp}"
}

drv_locale_apply() {
    local locale="$1"
    if ! locale_is_available "${locale}"; then
        error "${locale} is not available. Generate it with localedef."
        return 1
    fi
    if [[ "${INIT_SYSTEM}" == "systemd" ]] && command -v localectl >/dev/null 2>&1; then
        run_cmd localectl set-locale "LANG=${locale}"
    fi
    local tmp
    tmp="$(mktemp)"
    printf 'RC_LANG="%s"\n' "${locale}" > "${tmp}"
    install_file 0644 "${tmp}" /etc/sysconfig/language
    rm -f -- "${tmp}"
}

drv_timezone_file() {
    printf '/etc/sysconfig/clock\n'
}

drv_locale_files() {
    printf '/etc/locale.conf\n/etc/sysconfig/language\n'
}

drv_mac_name() {
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
        printf 'selinux\n'
    else
        printf 'apparmor\n'
    fi
}

drv_mac_enforce() {
    if [[ "$(drv_mac_name)" == "selinux" ]]; then
        mac_enforce_selinux
    else
        mac_enforce_apparmor
    fi
}

drv_mac_install() {
    if [[ "$(drv_mac_name)" == "selinux" ]]; then
        drv_pkg_install libselinux-utils policycoreutils
    else
        drv_pkg_install apparmor-utils
    fi
}

drv_mac_status() {
    if [[ "$(drv_mac_name)" == "selinux" ]] && command -v getenforce >/dev/null 2>&1; then
        getenforce
    elif command -v aa-status >/dev/null 2>&1; then
        aa-status --enabled 2>/dev/null && printf 'AppArmor is enabled\n' || printf 'AppArmor is not enabled\n'
    else
        printf 'no mandatory access control tool is installed\n'
    fi
}

# SUSE has no unattended-upgrades or dnf-automatic package, so automatic patching
# runs through a timer unit that this project installs.
drv_unattended_setup() {
    local unit_dir=/etc/systemd/system
    run_cmd mkdir -p -- "${unit_dir}"
    if dry_run; then
        echo "  [dry-run] write ${unit_dir}/linux-server-bootstrap-autoupdates.{service,timer}"
        return 0
    fi
    cat > "${unit_dir}/linux-server-bootstrap-autoupdates.service" <<'EOF'
[Unit]
Description=Weekly zypper security updates installed by linux-server-bootstrap

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive update
EOF
    cat > "${unit_dir}/linux-server-bootstrap-autoupdates.timer" <<'EOF'
[Unit]
Description=Run linux-server-bootstrap automatic updates weekly

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
    chmod 0644 "${unit_dir}/linux-server-bootstrap-autoupdates.service" \
        "${unit_dir}/linux-server-bootstrap-autoupdates.timer"
    svc_daemon_reload
    svc_enable_now linux-server-bootstrap-autoupdates.timer
}

drv_crypto_policy() {
    local profile="${1:-DEFAULT}"
    if ! command -v crypto-policies-config >/dev/null 2>&1 \
        && ! command -v update-crypto-policies >/dev/null 2>&1; then
        warn "This SUSE system has no crypto policy command; the SSH algorithm lists carry the policy."
        return 1
    fi
    if command -v update-crypto-policies >/dev/null 2>&1; then
        run_cmd update-crypto-policies --set "${profile}"
    else
        run_cmd crypto-policies-config --level "${profile}"
    fi
}

# SUSE regenerates common-auth and common-account from its own configuration when
# pam-configd runs, so the splice is the only step available here and the stage
# warns about it.
drv_lockout_files() {
    printf '%s\n' /etc/security/faillock.conf "${PAM_DIR}/common-auth" "${PAM_DIR}/common-account"
}

drv_lockout_apply() {
    local deny="${1:-3}" fail_interval="${2:-900}" unlock_time="${3:-900}"

    if ! pam_faillock_module_path >/dev/null 2>&1; then
        error "pam_faillock.so is not installed. Install the pam module package (zypper install pam)."
        return 1
    fi

    faillock_conf_write "${deny}" "${fail_interval}" "${unlock_time}" || return 1
    if command -v pam-configd >/dev/null 2>&1; then
        warn "pam-configd can rewrite these stacks; keep the faillock lines in /etc/pam.d/standard."
    fi
    pam_splice_faillock "${PAM_DIR}/common-auth" "${PAM_DIR}/common-account"
}

drv_pwquality_pkg() {
    # openSUSE and SLE ship pam_pwquality.so inside the pam package.
    printf 'pam\n'
}
