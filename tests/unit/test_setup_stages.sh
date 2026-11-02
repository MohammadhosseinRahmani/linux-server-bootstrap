#!/usr/bin/env bash
# Setup stage checks: base setup, user preparation, and the shared state file.
#
# The stages run with DRY_RUN=1 and every writable path redirected into a temporary
# directory, so no account, clock or locale on the runner is touched.
#
# Usage: bash tests/unit/test_setup_stages.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

SANDBOX="${WORK_DIR}/sandbox"
mkdir -p "${SANDBOX}"
export DRY_RUN=1
export BACKUP_ROOT="${SANDBOX}/backups"
export STATE_DIR="${SANDBOX}/state"
export LOG_FILE="${SANDBOX}/test.log"
# base.sh will not plan for a host that has no way to start a daemon, and a container
# reports exactly that, so the refusals asserted below would be about the runner rather
# than about the argument under test. The sysv path needs no binary here because the
# dry run intercepts every command that would have used one; the case that wants
# systemd says so itself and stubs the tool.
export INIT_SYSTEM=sysv

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
        printf '%s\n' "${haystack}" | tail -15 | sed 's/^/        out: /'
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

assert_rc() {
    local label="$1" want="$2" got="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${want}" == "${got}" ]]; then
        ok "${label}"
    else
        nok "${label}: expected rc ${want}, got ${got}"
    fi
}

assert_absent_file() {
    local label="$1" path="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -e "${path}" ]]; then
        nok "${label}: ${path} exists"
    else
        ok "${label}"
    fi
}

printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIunittestkey unit@test\n' > "${SANDBOX}/key.pub"
printf 'this is not a public key\n' > "${SANDBOX}/badkey.pub"

# The driver looks a zone up in this tree before it plans the change, so the pass
# reads a fixture rather than the runner's /usr/share/zoneinfo. UTC is in it and
# Not/AZone is not, which is the whole difference the two cases below assert; an
# image that ships without tzdata would otherwise answer both the same way.
mkdir -p "${SANDBOX}/zoneinfo/Europe"
printf 'UTC\n' > "${SANDBOX}/zoneinfo/UTC"
printf 'CET-1\n' > "${SANDBOX}/zoneinfo/Europe/Berlin"

HOSTNAME_BEFORE="$(cat /etc/hostname)"

echo "== every stage entry point enables errtrace =="
# Without -E the ERR trap does not fire inside function calls, so a stage could fail
# after its first change and leave the host half-configured in silence.
TESTS_RUN=$((TESTS_RUN + 1))
MISSING_TRACE=""
for script in bootstrap.sh hardening/ssh.sh hardening/firewall.sh hardening/fail2ban.sh \
    setup/base.sh setup/users.sh; do
    if ! grep -q '^set -Eeuo pipefail' "${PROJECT_DIR}/${script}"; then
        MISSING_TRACE="${MISSING_TRACE} ${script}"
    fi
done
if [[ -z "${MISSING_TRACE}" ]]; then
    ok "all stages roll back on an unexpected error"
else
    nok "missing -E in:${MISSING_TRACE}"
fi

echo
echo "== base setup dry-run =="
# The plan quotes the driver's own commands, so this pass is pinned to a Debian
# fixture instead of the runner's family and the assertions hold on every distro in
# the matrix. The service manager is pinned for the same reason: WSL and a container
# answer sysv, and a sysv plan quotes chkconfig instead of systemctl. The stubs cover
# the binaries that family owns: a stage that installs looks for its package manager
# before it prints a line, dry run or not, the locale step asks for locale-gen before
# it can report what it would generate, and a systemd host is checked for the
# systemctl binary the enable step names even though the dry run never runs it.
mkdir -p "${SANDBOX}/bin"
for stub in apt apt-get locale-gen update-locale systemctl; do
    printf '#!/bin/sh\nexit 0\n' > "${SANDBOX}/bin/${stub}"
    chmod +x "${SANDBOX}/bin/${stub}"
done
printf 'NAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="12"\n' > "${SANDBOX}/os-release.debian"
BASE_OUT="$(cd "${PROJECT_DIR}" && PATH="${SANDBOX}/bin:${PATH}" \
    OS_RELEASE_FILE="${SANDBOX}/os-release.debian" INIT_SYSTEM=systemd \
    ZONEINFO_DIR="${SANDBOX}/zoneinfo" \
    bash setup/base.sh --updates --hostname testbox \
    --timezone UTC --locale C.UTF-8 --timesync --autoupdates --yes 2>&1)"
BASE_RC=$?
assert_rc "base.sh plans successfully" 0 "${BASE_RC}"
assert_has "announces the package upgrade" "${BASE_OUT}" "apply package upgrades with"
assert_has "announces the hostname change" "${BASE_OUT}" "set the hostname to testbox"
assert_has "announces the timezone change" "${BASE_OUT}" "set the timezone to UTC"
assert_has "announces the locale change" "${BASE_OUT}" "set the locale to C.UTF-8"
assert_has "announces the time sync service" "${BASE_OUT}" "install and enable chrony"
assert_has "runs the distribution upgrade" "${BASE_OUT}" "dist-upgrade -y"
assert_has "writes the static hostname" "${BASE_OUT}" "-> /etc/hostname (mode 0644)"
assert_has "applies the new hostname" "${BASE_OUT}" "hostname -F /etc/hostname"
assert_has "applies the timezone through the driver" "${BASE_OUT}" "dpkg-reconfigure -f noninteractive tzdata"
assert_has "enables the time sync unit" "${BASE_OUT}" "systemctl enable --now chrony"
assert_has "enables unattended upgrades" "${BASE_OUT}" "unattended-upgrades"
assert_has "finished the stage" "${BASE_OUT}" "Base setup completed."
assert_lacks "no package was downloaded" "${BASE_OUT}" "Get:"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(cat /etc/hostname)" == "${HOSTNAME_BEFORE}" ]]; then
    ok "host hostname unchanged by the dry run"
else
    nok "dry run changed /etc/hostname"
fi
assert_absent_file "no state file written to the host" "/etc/linux-server-bootstrap/state.env"

echo
echo "== base setup rejects bad input before changing anything =="
BAD_HOST="$(cd "${PROJECT_DIR}" && bash setup/base.sh --hostname 'bad name!' --yes 2>&1)"
assert_rc "invalid hostname is refused" 1 "$?"
assert_has "explains the hostname problem" "${BAD_HOST}" "Invalid hostname"

NO_ARGS="$(cd "${PROJECT_DIR}" && bash setup/base.sh --yes 2>&1)"
assert_rc "an empty request is refused" 2 "$?"
assert_has "lists the usable options" "${NO_ARGS}" "Nothing to do."

BAD_TZ="$(cd "${PROJECT_DIR}" && ZONEINFO_DIR="${SANDBOX}/zoneinfo" \
    bash setup/base.sh --timezone Not/AZone --yes 2>&1)"
BAD_TZ_RC=$?
assert_rc "unknown timezone is refused" 1 "${BAD_TZ_RC}"
assert_has "driver rejects the zone" "${BAD_TZ}" "Unknown timezone: Not/AZone"
assert_has "the ERR trap started the rollback" "${BAD_TZ}" "Starting rollback."
assert_has "the dry run refused to restore" "${BAD_TZ}" "nothing is restored"

echo
echo "== user setup dry-run =="
USERS_OUT="$(cd "${PROJECT_DIR}" && bash setup/users.sh --user newadmin \
    --key "${SANDBOX}/key.pub" --sudo --groups users --yes 2>&1)"
USERS_RC=$?
assert_rc "users.sh plans successfully" 0 "${USERS_RC}"
assert_has "creates the account" "${USERS_OUT}" "useradd -m -s /bin/bash -- newadmin"
assert_has "adds the extra group" "${USERS_OUT}" "usermod -aG users -- newadmin"
assert_has "plans the key at the new home" "${USERS_OUT}" "/home/newadmin/.ssh/authorized_keys (mode 0600)"
assert_has "installs the sudo drop-in" "${USERS_OUT}" "/etc/sudoers.d/99-linux-server-bootstrap-newadmin (mode 0440)"
assert_has "finished the stage" "${USERS_OUT}" "User setup completed."
assert_absent_file "no account directory created" "/home/newadmin"
TESTS_RUN=$((TESTS_RUN + 1))
if id newadmin >/dev/null 2>&1; then
    nok "dry run created a real account"
else
    ok "no real account created"
fi

BAD_KEY="$(cd "${PROJECT_DIR}" && bash setup/users.sh --user newadmin \
    --key "${SANDBOX}/badkey.pub" --yes 2>&1)"
assert_rc "a non-key file is refused" 1 "$?"
assert_has "names the offending line" "${BAD_KEY}" "is not an SSH public key"

ROOT_USER="$(cd "${PROJECT_DIR}" && bash setup/users.sh --user root \
    --key "${SANDBOX}/key.pub" --yes 2>&1)"
assert_rc "root is refused" 1 "$?"
assert_has "explains why root is refused" "${ROOT_USER}" "Do not prepare root"

NO_USERS="$(cd "${PROJECT_DIR}" && bash setup/users.sh --yes 2>&1)"
assert_rc "at least one user is required" 1 "$?"
assert_has "names the option that is missing" "${NO_USERS}" "Pass at least one --user."

echo
echo "== the shared state file keeps keys from every stage =="
# save_state rewrites the file, so it must carry forward what another stage wrote.
MERGED="$(
    cd "${PROJECT_DIR}" || exit 1
    unset DRY_RUN
    export STATE_DIR="${WORK_DIR}/state2" LOG_FILE="${WORK_DIR}/state2.log"
    export SSH_PORT=2222
    # shellcheck disable=SC1091
    source lib/common.sh
    SSH_ALLOW_USERS=(admin)
    state_set TIMEZONE UTC
    state_set LOCALE C.UTF-8
    save_state > /dev/null
    # A second stage run must not drop the first stage's keys.
    state_set AUTOUPDATES 1
    save_state > /dev/null
    cat "${STATE_FILE}"
)"
assert_has "keeps the SSH port" "${MERGED}" "SSH_PORT=2222"
assert_has "keeps the allowed users" "${MERGED}" "SSH_ALLOW_USERS_LINE=admin"
assert_has "keeps the timezone" "${MERGED}" "TIMEZONE=UTC"
assert_has "keeps the locale" "${MERGED}" "LOCALE=C.UTF-8"
assert_has "adds the later stage key" "${MERGED}" "AUTOUPDATES=1"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -c '^TIMEZONE=' <<< "${MERGED}")" == "1" ]]; then
    ok "no duplicated keys after a second save"
else
    nok "TIMEZONE appears more than once: ${MERGED}"
fi

STATE_READ="$(
    cd "${PROJECT_DIR}" || exit 1
    export STATE_DIR="${WORK_DIR}/state2" LOG_FILE="${WORK_DIR}/state2.log"
    # shellcheck disable=SC1091
    source lib/common.sh
    state_value LOCALE
)"
assert_has "state_value reads a saved key" "${STATE_READ}" "C.UTF-8"

echo
echo "== a zone name is only unknown until the database is looked at =="
# A minimal image can ship without the timezone package, and then /usr/share/zoneinfo
# holds nothing: every name an operator asks for, valid or not, reads as unknown. The
# check installs the package before refusing, and says what it cannot know in a dry run.
mkdir -p "${SANDBOX}/tzbin"
printf '#!/bin/sh\nexit 0\n' > "${SANDBOX}/tzbin/apt"
chmod +x "${SANDBOX}/tzbin/apt"
# The stub stands in for the package: it lays down the tree the driver then reads, so
# a successful install and a failed one are two different fixtures rather than two
# different hosts.
printf '#!/bin/sh\nif [ "${TZ_INSTALL_RC:-0}" -ne 0 ]; then exit "${TZ_INSTALL_RC}"; fi\n' > "${SANDBOX}/tzbin/apt-get"
printf 'mkdir -p "${TZ_INSTALL_DIR}" && printf x > "${TZ_INSTALL_DIR}/UTC"\n' >> "${SANDBOX}/tzbin/apt-get"
printf 'exit 0\n' >> "${SANDBOX}/tzbin/apt-get"
chmod +x "${SANDBOX}/tzbin/apt-get"

# tz_probe <dry-run> <install-rc> <zoneinfo dir> <zone>
# Prints what the check reported and returns its exit status.
tz_probe() {
    (
        cd "${PROJECT_DIR}" || exit 1
        export PATH="${SANDBOX}/tzbin:${PATH}"
        export DRY_RUN="$1"
        export TZ_INSTALL_RC="$2"
        export TZ_INSTALL_DIR="$3"
        export BACKUP_ROOT="${SANDBOX}/tz-backups"
        export STATE_DIR="${SANDBOX}/tz-state"
        export LOG_FILE="${SANDBOX}/tz.log"
        export OS_RELEASE_FILE="${SANDBOX}/os-release.debian"
        export ZONEINFO_DIR="$3"
        # shellcheck disable=SC1091
        source lib/common.sh
        detect_os > /dev/null 2>&1
        timezone_is_supported "$4"
    ) 2>&1
}

TZ_MISSING="${WORK_DIR}/tz-missing"
TZ_TYPO="${WORK_DIR}/tz-typo"
mkdir -p "${TZ_TYPO}/Europe"
printf 'x' > "${TZ_TYPO}/Europe/Berlin"
TZ_OK_DIR="${WORK_DIR}/tz-ok"
mkdir -p "${TZ_OK_DIR}"
printf 'x' > "${TZ_OK_DIR}/UTC"

TZ_OUT="$(tz_probe 1 0 "${TZ_OK_DIR}" UTC)"
assert_rc "a zone in the database is accepted" 0 "$?"
assert_lacks "a readable database needs no comment" "${TZ_OUT}" "timezone database"

TZ_OUT="$(tz_probe 1 0 "${TZ_TYPO}" 'Not/AZone')"
assert_rc "a name that is not in the database is refused" 1 "$?"
assert_has "and says the database has no such zone" "${TZ_OUT}" "It is not in this host's timezone database"

TZ_OUT="$(tz_probe 1 0 "${TZ_MISSING}" UTC)"
assert_rc "a dry run without a database plans the install" 0 "$?"
assert_has "and names the package it would install" "${TZ_OUT}" "tzdata"

TZ_OUT="$(tz_probe 0 0 "${TZ_MISSING}" UTC)"
assert_rc "a real run installs the database and accepts the zone" 0 "$?"
assert_has "and says it is installing" "${TZ_OUT}" "Installing tzdata"

TZ_OUT="$(tz_probe 0 1 "${WORK_DIR}/tz-broken" UTC)"
assert_rc "a failed install is an error, not a silent unknown" 1 "$?"
assert_has "and names the package that failed" "${TZ_OUT}" "did not install"

echo
echo "== a locale tool the image forgot to ship =="
# The same reasoning as above, for the other half of the clock: locale-gen lives in
# the locales package, a slim Debian image has no locales package, and refusing to
# plan a locale on such a host makes the dry run useless on exactly the images a
# operator is most likely to start from.
mkdir -p "${SANDBOX}/locbin"
printf '#!/bin/sh\nexit 0\n' > "${SANDBOX}/locbin/apt"
printf '#!/bin/sh\nexit 0\n' > "${SANDBOX}/locbin/update-locale"
# The apt-get stub stands in for the locales package by putting the real command
# onto the PATH the driver searches again right afterwards.
printf '#!/bin/sh\nif [ "${LOCALES_INSTALL_RC:-0}" -ne 0 ]; then exit "${LOCALES_INSTALL_RC}"; fi\n' > "${SANDBOX}/locbin/apt-get"
printf 'printf "#!/bin/sh\\nexit 0\\n" > "${LOCALES_STUB_DIR}/locale-gen"\n' >> "${SANDBOX}/locbin/apt-get"
printf 'chmod +x "${LOCALES_STUB_DIR}/locale-gen"\nexit 0\n' >> "${SANDBOX}/locbin/apt-get"
printf '#!/bin/sh\nexit 0\n' >> "${SANDBOX}/locbin/apt-get"
chmod +x "${SANDBOX}/locbin/apt" "${SANDBOX}/locbin/apt-get" "${SANDBOX}/locbin/update-locale"

# locale_probe <dry-run> <install-rc>: calls the Debian driver with no locale-gen
# on PATH at first.
locale_probe() {
    local probe_dir="${WORK_DIR}/loc-$1-$2"
    mkdir -p "${probe_dir}"
    (
        cd "${PROJECT_DIR}" || exit 1
        export PATH="${probe_dir}:${SANDBOX}/locbin:/usr/bin:/bin"
        export DRY_RUN="$1"
        export LOCALES_INSTALL_RC="$2"
        export LOCALES_STUB_DIR="${probe_dir}"
        export BACKUP_ROOT="${SANDBOX}/loc-backups"
        export STATE_DIR="${SANDBOX}/loc-state"
        export LOG_FILE="${SANDBOX}/loc.log"
        export OS_RELEASE_FILE="${SANDBOX}/os-release.debian"
        # shellcheck disable=SC1091
        source lib/common.sh
        detect_os > /dev/null 2>&1
        drv_locale_apply C.UTF-8
    ) 2>&1
}

LOC_OUT="$(locale_probe 1 0)"
assert_rc "a dry run plans the install instead of refusing" 0 "$?"
assert_has "and says the install was simulated" "${LOC_OUT}" "the install was simulated"
assert_has "and names the package" "${LOC_OUT}" "locales"

LOC_OUT="$(locale_probe 0 0)"
assert_rc "a real run gets the tool and generates the locale" 0 "$?"
assert_lacks "and reports no error" "${LOC_OUT}" "[ERROR]"

LOC_OUT="$(locale_probe 0 1)"
assert_rc "a failed install is reported as one" 1 "$?"
assert_has "and names what could not be installed" "${LOC_OUT}" "The locales package did not install"

echo
echo "Ran ${TESTS_RUN} checks, ${TESTS_FAILED} failed."
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0
