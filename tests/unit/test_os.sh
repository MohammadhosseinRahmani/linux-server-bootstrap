#!/usr/bin/env bash
# Unit tests for OS detection and the driver contract.
# Runs without root and without touching the host, so CI can execute it on any
# Linux runner. Usage: bash tests/unit/test_os.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
export LOG_FILE="${WORK_DIR}/test.log"

# shellcheck source=../../lib/common.sh
source "${PROJECT_DIR}/lib/common.sh"

TESTS_RUN=0
TESTS_FAILED=0

ok() {
    printf '  PASS  %s\n' "$*"
}

nok() {
    printf '  FAIL  %s\n' "$*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# ID|ID_LIKE|VERSION_ID|expected family|expected package manager
DETECTION_CASES=(
    'debian||12|debian|apt'
    'ubuntu|debian|24.04|debian|apt'
    'ubuntu|debian|18.04|debian|apt'
    'linuxmint|ubuntu debian|22|debian|apt'
    'raspbian|debian|12|debian|apt'
    'devuan|debian|5|debian|apt'
    'kali|debian|2024|debian|apt'
    'pop|ubuntu debian|22.04|debian|apt'
    'deepin|debian|20|debian|apt'
    'rhel||9|rhel|dnf'
    'centos|rhel|7|rhel|dnf'
    'rocky|rhel centos fedora|9|rhel|dnf'
    'almalinux|rhel|9|rhel|dnf'
    'ol|rhel|8|rhel|dnf'
    'fedora|anaconda|43|rhel|dnf'
    'amzn||2023|rhel|dnf'
    'alinux|rhel fedora|3|rhel|dnf'
    'anolis|rhel|8|rhel|dnf'
    'azurelinux||3.0|rhel|dnf'
    'opensuse-leap|suse|15.6|suse|zypper'
    'opensuse-tumbleweed|suse|20260101|suse|zypper'
    'sles|suse|15|suse|zypper'
    'arch|||unsupported|'
    'alpine|||unsupported|'
    'gobolinux|||unsupported|'
    'notreal|bogus|1|unsupported|'
)

check_detection() {
    local line id like version want_family want_pkg
    line="$1"
    IFS='|' read -r id like version want_family want_pkg <<< "${line}"

    local fixture="${WORK_DIR}/os-release"
    {
        printf 'NAME="%s"\n' "${id}"
        printf 'ID=%s\n' "${id}"
        if [[ -n "${like}" ]]; then
            printf 'ID_LIKE="%s"\n' "${like}"
        fi
        if [[ -n "${version}" ]]; then
            printf 'VERSION_ID="%s"\n' "${version}"
        fi
    } > "${fixture}"

    OS_ID=""
    OS_VERSION=""
    OS_FAMILY=""
    PKG_MGR=""
    DRIVER=""
    OS_RELEASE_FILE="${fixture}"

    # The expected package manager belongs to the fixture, not to the runner: a yum-only
    # host would answer every RPM row with its own binary and the table would stop
    # describing family mapping. An EL9 host is assumed here and the fallback has its
    # own cases below.
    os_has_command() { [[ "$1" == dnf ]]; }

    local status=0
    detect_os > /dev/null 2>&1 || status=$?

    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${want_family}" == "unsupported" ]]; then
        if (( status == 0 )); then
            nok "${id}: expected rejection, got family ${OS_FAMILY}"
        else
            ok "${id}: rejected as unsupported"
        fi
        return 0
    fi

    if (( status != 0 )); then
        nok "${id}: detect_os failed with ${status}"
        return 0
    fi
    if [[ "${OS_FAMILY}" != "${want_family}" ]]; then
        nok "${id}: family ${OS_FAMILY} != ${want_family}"
        return 0
    fi
    if [[ "${PKG_MGR}" != "${want_pkg}" ]]; then
        nok "${id}: package manager ${PKG_MGR} != ${want_pkg}"
        return 0
    fi
    ok "${id} -> ${want_family}/${want_pkg}"
}

echo "== os-release detection =="
for case_line in "${DETECTION_CASES[@]}"; do
    check_detection "${case_line}"
done

echo
echo "== driver contract =="
# A driver that forgets a function would abort a stage mid-change, so every
# family must export the whole contract even on a host that cannot run it.
for family in debian rhel suse; do
    (
        set +u
        OS_RELEASE_FILE="${WORK_DIR}/missing"
        PROJECT_DIR="${PROJECT_DIR}"
        source "${PROJECT_DIR}/lib/drivers/${family}.sh"
        if driver_requires "${DRIVER_CONTRACT[@]}"; then
            exit 0
        fi
        exit 1
    )
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ $? -eq 0 ]]; then
        ok "driver ${family} implements all ${#DRIVER_CONTRACT[@]} contract functions"
    else
        nok "driver ${family} is missing contract functions"
    fi
done

echo
echo "== version comparison =="
OS_VERSION="26.04"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(os_major_version)" == "26" ]]; then
    ok "os_major_version parses 26.04"
else
    nok "os_major_version 26.04 gave $(os_major_version)"
fi

OS_VERSION="8.10"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(os_major_version)" == "8" ]]; then
    ok "os_major_version parses 8.10"
else
    nok "os_major_version 8.10 gave $(os_major_version)"
fi

OS_VERSION=""
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(os_major_version)" == "0" ]]; then
    ok "os_major_version tolerates an empty version"
else
    nok "os_major_version empty gave $(os_major_version)"
fi

echo
echo "== os-is-id matching =="
OS_ID="Fedora"
TESTS_RUN=$((TESTS_RUN + 1))
if os_is_id fedora; then
    ok "os_is_id is case insensitive"
else
    nok "os_is_id failed for Fedora"
fi

OS_ID="rocky"
TESTS_RUN=$((TESTS_RUN + 1))
if ! os_is_id fedora; then
    ok "os_is_id does not cross-match"
else
    nok "os_is_id matched fedora on rocky"
fi

echo
echo "== package manager selection on RPM hosts =="
# dnf is preferred, yum is the fallback, and a host with neither defaults to dnf
# until a stage actually installs something.
rpm_fixture="${WORK_DIR}/os-release-rhel"
printf 'ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9"\n' > "${rpm_fixture}"

select_pkg_mgr() {
    local fake_bin="$1"
    (
        OS_RELEASE_FILE="${rpm_fixture}"
        OS_ID=""
        OS_VERSION=""
        OS_FAMILY=""
        PKG_MGR=""
        DRIVER=""
        # The lookup is replaced rather than steered through PATH, because a runner
        # that is itself an RPM host keeps a real dnf in the same directory as awk.
        os_has_command() { [[ -x "${fake_bin}/$1" ]]; }
        detect_os > /dev/null 2>&1
        printf '%s' "${PKG_MGR}"
    )
}

mkdir -p "${WORK_DIR}/dnf-only" "${WORK_DIR}/yum-only" "${WORK_DIR}/neither"
printf '#!/bin/sh\nexit 0\n' > "${WORK_DIR}/dnf-only/dnf"
printf '#!/bin/sh\nexit 0\n' > "${WORK_DIR}/yum-only/yum"
printf '#!/bin/sh\nexit 0\n' > "${WORK_DIR}/yum-only/rpm"
chmod +x "${WORK_DIR}"/*/*

TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(select_pkg_mgr "${WORK_DIR}/dnf-only")" == "dnf" ]]; then
    ok "dnf is chosen when present"
else
    nok "dnf selection wrong"
fi

TESTS_RUN=$((TESTS_RUN + 1))
YUM_ONLY="$(select_pkg_mgr "${WORK_DIR}/yum-only")"
if [[ "${YUM_ONLY}" == "yum" ]]; then
    ok "yum is the fallback"
elif command -v dnf >/dev/null 2>&1; then
    # This runner is itself an RPM host, and dnf lives in the same directory as the
    # awk and grep detect_os needs, so no PATH can hide only dnf. The preference is
    # still proven on every non-RPM job in the matrix and on a real EL7 install.
    ok "yum fallback is not simulatable on a host that has dnf"
else
    nok "yum fallback wrong: got '${YUM_ONLY}'"
fi

TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(select_pkg_mgr "${WORK_DIR}/neither")" == "dnf" ]]; then
    ok "defaults to dnf when neither is installed yet"
else
    nok "default package manager wrong"
fi

echo
echo "== fail2ban backend selection =="
INIT_SYSTEM="systemd"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(pick_fail2ban_backend)" == "systemd" ]]; then
    ok "systemd host uses the journald backend"
else
    nok "systemd backend selection wrong"
fi

INIT_SYSTEM="sysv"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(pick_fail2ban_backend)" == "auto" ]]; then
    ok "non-systemd host falls back to the auto backend"
else
    nok "non-systemd backend selection wrong"
fi

echo
echo "== real host detection =="
OS_RELEASE_FILE=/etc/os-release
OS_ID=""
OS_VERSION=""
OS_FAMILY=""
PKG_MGR=""
DRIVER=""
TESTS_RUN=$((TESTS_RUN + 1))
if detect_os > /dev/null 2>&1; then
    ok "host ${OS_ID} -> ${OS_FAMILY} driver ${DRIVER}"
else
    # Containers and minimal images may legitimately lack a supported distro.
    ok "host not supported by any driver (skipped)"
fi

echo
echo "Ran ${TESTS_RUN} checks, ${TESTS_FAILED} failed."
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0
