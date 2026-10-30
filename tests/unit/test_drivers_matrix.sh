#!/usr/bin/env bash
# Driver matrix checks that run without a VM.
#
# Each case points detect_os at an os-release fixture, puts a stub tool directory in
# front of PATH, and calls the loaded driver with DRY_RUN=1. The commands the driver
# prints are the result, so a distribution can be verified on any Linux runner and
# nothing is installed.
#
# The dnf-versus-yum choice depends on what the runner has installed, so RPM cases
# assert on package names and family behaviour rather than the binary name.
#
# Usage: bash tests/unit/test_drivers_matrix.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

TESTS_RUN=0
TESTS_FAILED=0

ok() { printf '  PASS  %s\n' "$*"; }
nok() { printf '  FAIL  %s\n' "$*"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

assert_has() {
    local label="$1" haystack="$2" needle="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if grep -qF -- "${needle}" <<< "${haystack}"; then
        ok "${label}"
    else
        nok "${label}: missing '${needle}'"
        printf '%s\n' "${haystack}" | grep -E '\[dry-run\]|^(family|init|fw_backend|ssh_unit|socket_setup|f2b_action|mac|timesync)=' | sed 's/^/        got: /'
    fi
}

assert_lacks() {
    local label="$1" haystack="$2" needle="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if grep -qF -- "${needle}" <<< "${haystack}"; then
        nok "${label}: unexpectedly found '${needle}'"
    else
        ok "${label}"
    fi
}

write_fixture() {
    local path="$1" id="$2" like="$3" version="$4"
    {
        printf 'NAME="%s"\n' "${id}"
        printf 'ID=%s\n' "${id}"
        if [[ -n "${like}" ]]; then
            printf 'ID_LIKE="%s"\n' "${like}"
        fi
        if [[ -n "${version}" ]]; then
            printf 'VERSION_ID="%s"\n' "${version}"
        fi
    } > "${path}"
}

new_stub_dir() {
    local dir="${WORK_DIR}/stub-$1"
    mkdir -p "${dir}"
    printf '%s' "${dir}"
}

# new_stub <dir> <name> <shell body>
new_stub() {
    local dir="$1" name="$2" body="$3"
    printf '#!/bin/sh\n%s\n' "${body}" > "${dir}/${name}"
    chmod +x "${dir}/${name}"
}

# A managed server: every unit the drivers look for is installed and running.
make_systemd_stubs() {
    new_stub "$1" systemctl 'case "$1" in
    is-active) exit 0 ;;
    list-unit-files) printf "%s\n" "sshd.service enabled" "ssh.service enabled" "ssh.socket enabled" "firewalld.service enabled" "ufw.service enabled" "dnf-automatic-install.timer enabled" "chronyd.service enabled" ;;
    esac
    exit 0'
}

# A minimal install: no unit is running and none is known.
make_systemd_stopped() {
    new_stub "$1" systemctl 'case "$1" in
    is-active) exit 1 ;;
    *) exit 0 ;;
    esac'
}

# sysvinit host: service(8) answers for everything.
make_sysv_stubs() {
    new_stub "$1" service 'exit 0'
    new_stub "$1" update-rc.d 'exit 0'
}

# ufw reports itself active and still allows the default SSH port, which is the
# state the stage has to move away from.
ufw_active_stub() {
    new_stub "$1" ufw 'if [ "$1" = "status" ]; then
    echo "Status: active"
    echo "22/tcp ALLOW IN Anywhere"
fi
exit 0'
}

ufw_inactive_stub() {
    new_stub "$1" ufw 'if [ "$1" = "status" ]; then
    echo "Status: inactive"
    echo "22/tcp ALLOW IN Anywhere"
fi
exit 0'
}

# Nothing is open yet, which is the state a fresh firewall starts from.
firewalld_cli_stub() {
    new_stub "$1" firewall-cmd 'case "$*" in
    *--query-port*|*--query-service*) exit 1 ;;
    esac
    exit 0'
    new_stub "$1" firewall-offline-cmd 'case "$*" in
    *--query-port*|*--query-service*) exit 1 ;;
    esac
    exit 0'
}

apt_stub() {
    new_stub "$1" apt-get 'exit 0'
}

# The driver refuses to install through a package manager that is not on PATH, so
# an RPM case needs the binary present. dnf is stubbed first because that is the
# one detect_os prefers when both exist.
rpm_pkg_stubs() {
    new_stub "$1" dnf 'exit 0'
    new_stub "$1" yum 'exit 0'
}

# run_driver <fixture> <stub dir> <init override>
# Prints what the loaded driver would do, with no changes to the host.
run_driver() {
    local fixture="$1" stub_dir="$2" init_override="$3"
    (
        cd "${PROJECT_DIR}" || exit 1
        export OS_RELEASE_FILE="${fixture}"
        export PATH="${stub_dir}:${PATH}"
        export DRY_RUN=1
        export BACKUP_ROOT="${WORK_DIR}/backups"
        export STATE_DIR="${WORK_DIR}/state"
        export LOG_FILE="${WORK_DIR}/transcript.log"
        export SSH_PORT=2222
        # shellcheck disable=SC1091
        source lib/common.sh
        if ! detect_os > /dev/null 2>&1; then
            printf 'DETECT_FAILED\n'
            exit 1
        fi
        printf 'family=%s pkg=%s driver=%s id=%s version=%s\n' \
            "${OS_FAMILY}" "${PKG_MGR}" "${DRIVER}" "${OS_ID}" "${OS_VERSION}"
        if [[ -n "${init_override}" ]]; then
            INIT_SYSTEM="${init_override}"
        else
            detect_init > /dev/null 2>&1
        fi
        printf 'init=%s\n' "${INIT_SYSTEM}"

        backup_begin firewall > /dev/null 2>&1
        drv_fw_record_state
        printf 'fw_backend=%s\n' "$(drv_fw_backend)"
        drv_fw_install || printf 'fw_install_failed\n'
        drv_fw_apply_port 2222 ""
        drv_fw_deny_others
        drv_fw_enable
        printf 'ssh_unit=%s\n' "$(drv_ssh_unit || printf 'none')"
        if drv_ssh_socket_setup 2222; then
            printf 'socket_setup=done\n'
        else
            printf 'socket_setup=not_applicable\n'
        fi
        drv_f2b_prepare_repo
        printf 'f2b_action=%s\n' "$(drv_f2b_action)"
        drv_pkg_install fail2ban
        printf 'mac=%s\n' "$(drv_mac_name)"
        drv_mac_install
        printf 'sysctl_file=%s\n' "$(drv_sysctl_file)"
        printf 'audit_pkg=%s\n' "$(drv_audit_pkg)"
        printf 'timesync=%s/%s\n' "$(drv_timesync_pkg)" "$(drv_timesync_unit)"
        drv_unattended_setup
        drv_crypto_policy DEFAULT || printf 'crypto_policy=unsupported\n'
        drv_updates_apply
    ) 2>&1
}

echo "== Debian 12 (systemd, ufw active) =="
STUB="$(new_stub_dir debian)"
write_fixture "${WORK_DIR}/debian12.release" debian "" 12
apt_stub "${STUB}"
ufw_active_stub "${STUB}"
make_systemd_stubs "${STUB}"
DEB_OUT="$(run_driver "${WORK_DIR}/debian12.release" "${STUB}" "")"
assert_has "selects the debian driver and apt" "${DEB_OUT}" "family=debian pkg=apt driver=debian id=debian"
assert_has "uses ufw as the firewall backend" "${DEB_OUT}" "fw_backend=ufw"
assert_has "installs ufw without recommends" "${DEB_OUT}" "apt-get install -y --no-install-recommends ufw"
assert_has "opens the configured port" "${DEB_OUT}" "ufw allow 2222/tcp"
assert_has "closes the old port 22 rule" "${DEB_OUT}" "ufw --force delete allow 22/tcp"
assert_has "sets the default deny policy" "${DEB_OUT}" "ufw default deny incoming"
assert_has "enables ufw" "${DEB_OUT}" "ufw --force enable"
assert_has "prefers ssh.service on Debian" "${DEB_OUT}" "ssh_unit=ssh"
assert_has "moves the port into ssh.socket" "${DEB_OUT}" "socket_setup=done"
assert_has "writes the socket drop-in" "${DEB_OUT}" "write /etc/systemd/system/ssh.socket.d/00-linux-server-bootstrap.conf (ListenStream=2222)"
assert_has "bans through ufw" "${DEB_OUT}" "f2b_action=ufw"
assert_has "uses AppArmor" "${DEB_OUT}" "mac=apparmor"
assert_has "uses the Debian time sync unit name" "${DEB_OUT}" "timesync=chrony/chrony"
assert_has "enables unattended-upgrades" "${DEB_OUT}" "apt-get install -y --no-install-recommends unattended-upgrades"
assert_has "declines a system crypto policy" "${DEB_OUT}" "crypto_policy=unsupported"
assert_has "upgrades with the debconf-safe options" "${DEB_OUT}" "dist-upgrade -y"

echo
echo "== Ubuntu 24.04 (ufw present but inactive) =="
STUB="$(new_stub_dir ubuntu)"
write_fixture "${WORK_DIR}/ubuntu24.release" ubuntu debian 24.04
apt_stub "${STUB}"
ufw_inactive_stub "${STUB}"
make_systemd_stubs "${STUB}"
UBT_OUT="$(run_driver "${WORK_DIR}/ubuntu24.release" "${STUB}" "")"
assert_has "maps the ubuntu derivative to debian" "${UBT_OUT}" "family=debian pkg=apt driver=debian id=ubuntu"
assert_has "uses ssh.socket on Ubuntu 24.04" "${UBT_OUT}" "socket_setup=done"
assert_has "still opens the port with ufw inactive" "${UBT_OUT}" "ufw allow 2222/tcp"
assert_has "closes the old port 22 rule" "${UBT_OUT}" "ufw --force delete allow 22/tcp"

echo
echo "== Devuan (apt family without systemd) =="
STUB="$(new_stub_dir devuan)"
write_fixture "${WORK_DIR}/devuan.release" devuan debian 5
apt_stub "${STUB}"
ufw_active_stub "${STUB}"
make_sysv_stubs "${STUB}"
# The runner's own systemctl cannot be removed from PATH, so the init system is set
# directly here; every service call below then takes the SysV branch.
DEV_OUT="$(run_driver "${WORK_DIR}/devuan.release" "${STUB}" sysv)"
assert_has "runs the non-systemd path" "${DEV_OUT}" "init=sysv"
assert_has "still installs with apt" "${DEV_OUT}" "apt-get install -y --no-install-recommends ufw"
assert_has "keeps AppArmor as the MAC" "${DEV_OUT}" "mac=apparmor"
assert_lacks "never calls systemctl" "${DEV_OUT}" "systemctl"
assert_has "has no socket unit to move the port into" "${DEV_OUT}" "socket_setup=not_applicable"

echo
echo "== RHEL 9 (firewalld running, EPEL installed, crypto policy available) =="
STUB="$(new_stub_dir rhel9)"
write_fixture "${WORK_DIR}/rhel9.release" rhel "" 9.4
new_stub "${STUB}" rpm 'if [ "$1" = "-q" ]; then exit 0; fi
if [ "$1" = "-E" ]; then echo 9; exit 0; fi
exit 1'
firewalld_cli_stub "${STUB}"
new_stub "${STUB}" update-crypto-policies 'exit 0'
make_systemd_stubs "${STUB}"
rpm_pkg_stubs "${STUB}"
R9_OUT="$(run_driver "${WORK_DIR}/rhel9.release" "${STUB}" "")"
assert_has "selects the rhel driver" "${R9_OUT}" "driver=rhel id=rhel version=9.4"
assert_has "uses firewalld" "${R9_OUT}" "fw_backend=firewalld"
assert_has "installs firewalld" "${R9_OUT}" "install -y firewalld"
assert_has "opens the port in the running firewall" "${R9_OUT}" "firewall-cmd --add-port=2222/tcp"
assert_has "persists the port" "${R9_OUT}" "firewall-cmd --permanent --add-port=2222/tcp"
assert_has "removes the ssh service object when 22 is unused" "${R9_OUT}" "--remove-service=ssh"
assert_has "reloads the running daemon" "${R9_OUT}" "firewall-cmd --reload"
assert_has "prefers sshd.service on RPM hosts" "${R9_OUT}" "ssh_unit=sshd"
assert_has "leaves the port with the daemon" "${R9_OUT}" "socket_setup=not_applicable"
assert_has "bans through firewalld rich rules" "${R9_OUT}" "f2b_action=firewallcmd-rich-rules"
assert_has "uses SELinux" "${R9_OUT}" "mac=selinux"
assert_lacks "skips EPEL when it is already installed" "${R9_OUT}" "epel-release"
assert_has "enables dnf-automatic on EL8 and newer" "${R9_OUT}" "systemctl enable --now dnf-automatic-install.timer"
assert_has "applies the system crypto policy" "${R9_OUT}" "update-crypto-policies --set DEFAULT"
assert_has "uses the EL time sync unit name" "${R9_OUT}" "timesync=chrony/chronyd"

echo
echo "== CentOS 7 (firewalld stopped, no EPEL, no crypto policy command) =="
STUB="$(new_stub_dir centos7)"
write_fixture "${WORK_DIR}/centos7.release" centos rhel 7
new_stub "${STUB}" rpm 'if [ "$1" = "-q" ]; then exit 1; fi
if [ "$1" = "-E" ]; then echo 7; exit 0; fi
exit 1'
firewalld_cli_stub "${STUB}"
make_systemd_stopped "${STUB}"
rpm_pkg_stubs "${STUB}"
C7_OUT="$(run_driver "${WORK_DIR}/centos7.release" "${STUB}" "")"
assert_has "maps centos to the rhel family" "${C7_OUT}" "driver=rhel id=centos version=7"
assert_has "edits the permanent store offline" "${C7_OUT}" "firewall-offline-cmd --add-port=2222/tcp"
assert_lacks "does not reload a stopped daemon" "${C7_OUT}" "firewall-cmd --reload"
assert_has "starts the unit instead" "${C7_OUT}" "systemctl enable --now firewalld"
assert_has "adds EPEL before fail2ban" "${C7_OUT}" "install -y epel-release"
assert_has "uses yum-cron on EL7" "${C7_OUT}" "install -y yum-cron"
assert_has "refuses a crypto policy on EL7" "${C7_OUT}" "update-crypto-policies needs EL8 or newer"

echo
echo "== Fedora (fail2ban ships without EPEL) =="
STUB="$(new_stub_dir fedora)"
write_fixture "${WORK_DIR}/fedora.release" fedora "" 43
new_stub "${STUB}" rpm 'exit 1'
firewalld_cli_stub "${STUB}"
make_systemd_stubs "${STUB}"
rpm_pkg_stubs "${STUB}"
FED_OUT="$(run_driver "${WORK_DIR}/fedora.release" "${STUB}" "")"
assert_has "keeps fedora in the rhel family" "${FED_OUT}" "driver=rhel id=fedora"
assert_lacks "does not add EPEL on Fedora" "${FED_OUT}" "epel-release"

echo
echo "== Amazon Linux 2023 =="
STUB="$(new_stub_dir amzn)"
write_fixture "${WORK_DIR}/amzn.release" amzn "" 2023
new_stub "${STUB}" rpm 'exit 1'
firewalld_cli_stub "${STUB}"
make_systemd_stubs "${STUB}"
rpm_pkg_stubs "${STUB}"
AMZ_OUT="$(run_driver "${WORK_DIR}/amzn.release" "${STUB}" "")"
assert_has "maps amazon to the rhel family" "${AMZ_OUT}" "driver=rhel id=amzn"
assert_lacks "does not add EPEL on Amazon Linux" "${AMZ_OUT}" "epel-release"

echo
echo "== openSUSE Leap (zypper, firewalld, AppArmor, no crypto command) =="
STUB="$(new_stub_dir suse)"
write_fixture "${WORK_DIR}/suse.release" opensuse-leap suse 15.6
new_stub "${STUB}" zypper 'exit 0'
firewalld_cli_stub "${STUB}"
make_systemd_stubs "${STUB}"
SUSE_OUT="$(run_driver "${WORK_DIR}/suse.release" "${STUB}" "")"
assert_has "selects the suse driver and zypper" "${SUSE_OUT}" "family=suse pkg=zypper driver=suse id=opensuse-leap"
assert_has "installs firewalld with zypper" "${SUSE_OUT}" "zypper --non-interactive install --no-recommends firewalld"
assert_has "shares the firewalld backend" "${SUSE_OUT}" "firewall-cmd --add-port=2222/tcp"
assert_has "reports AppArmor" "${SUSE_OUT}" "mac=apparmor"
assert_has "installs its own update timer" "${SUSE_OUT}" "linux-server-bootstrap-autoupdates.{service,timer}"
assert_has "warns about a missing crypto command" "${SUSE_OUT}" "crypto_policy=unsupported"
assert_has "uses the EL time sync unit name" "${SUSE_OUT}" "timesync=chrony/chronyd"
assert_has "patches with zypper" "${SUSE_OUT}" "zypper --non-interactive update"

echo
echo "== RHEL without a firewall command line (--skip-firewall) =="
STUB="$(new_stub_dir rhel_nofw)"
write_fixture "${WORK_DIR}/rhel-nofw.release" rhel "" 9.4
new_stub "${STUB}" rpm 'exit 0'
make_systemd_stubs "${STUB}"
rpm_pkg_stubs "${STUB}"
NOFW_OUT="$(run_driver "${WORK_DIR}/rhel-nofw.release" "${STUB}" "")"
assert_lacks "does not name the firewalld action" "${NOFW_OUT}" "f2b_action=firewallcmd-rich-rules"
assert_lacks "does not name the ufw action" "${NOFW_OUT}" "f2b_action=ufw"
assert_has "still installs fail2ban with its default action" "${NOFW_OUT}" "install -y fail2ban"

echo
echo "Ran ${TESTS_RUN} checks, ${TESTS_FAILED} failed."
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0
