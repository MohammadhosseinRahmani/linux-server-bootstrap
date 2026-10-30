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
BASE_OUT="$(cd "${PROJECT_DIR}" && bash setup/base.sh --updates --hostname testbox \
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

BAD_TZ="$(cd "${PROJECT_DIR}" && bash setup/base.sh --timezone Not/AZone --yes 2>&1)"
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
echo "Ran ${TESTS_RUN} checks, ${TESTS_FAILED} failed."
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0
