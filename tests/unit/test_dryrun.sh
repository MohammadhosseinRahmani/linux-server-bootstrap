#!/usr/bin/env bash
# Stage-level dry-run tests.
#
# These exercise the real hardening scripts end to end with DRY_RUN=1 and every
# writable path redirected into a temporary directory, so a CI runner is never
# modified. Usage: bash tests/unit/test_dryrun.sh

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
        printf '%s\n' "${haystack}" | sed 's/^/        out: /' | tail -20
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

assert_absent_file() {
    local label="$1" path="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -e "${path}" ]]; then
        nok "${label}: ${path} was created"
    else
        ok "${label}"
    fi
}

export DRY_RUN=1
export BACKUP_ROOT="${WORK_DIR}/backups"
export STATE_DIR="${WORK_DIR}/state"
export LOG_FILE="${WORK_DIR}/test.log"
export SSH_PORT=2222

echo "== firewall stage dry-run through the driver =="
BACKEND="$(cd "${PROJECT_DIR}" && bash -c '
    # shellcheck disable=SC1091
    source lib/common.sh
    detect_os > /dev/null 2>&1
    drv_fw_backend
')"



FW_OUT="$(cd "${PROJECT_DIR}" && bash hardening/firewall.sh --port 2222 --yes 2>&1)"
FW_RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${FW_RC}" -eq 0 ]]; then
    ok "firewall.sh completed in dry-run"
else
    nok "firewall.sh exited ${FW_RC}"
    printf '%s\n' "${FW_OUT}" | tail -20
fi
assert_has "asks the driver for its backend" "${FW_OUT}" "backend is ${BACKEND}"
assert_has "opens the configured port" "${FW_OUT}" "2222/tcp"
assert_has "reached the end of the stage" "${FW_OUT}" "Firewall hardening completed with ${BACKEND}"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -c '\[dry-run\]' <<< "${FW_OUT}")" -ge 3 ]]; then
    ok "several state-changing commands were intercepted"
else
    nok "expected multiple [dry-run] lines, got: ${FW_OUT}"
fi
assert_lacks "no package download happened" "${FW_OUT}" "Reading package lists"

echo
echo "== state and backup trees land in the sandbox only =="
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -d "${BACKUP_ROOT}/firewall" ]]; then
    ok "backup tree created under the sandbox"
else
    nok "no sandbox backup tree at ${BACKUP_ROOT}/firewall"
fi
assert_absent_file "host backup root untouched" "/var/backups/linux-server-bootstrap"
assert_absent_file "host state file untouched" "/etc/linux-server-bootstrap/state.env"

echo
echo "== ssh stage refuses to half-apply without sshd =="
# The stage must stop at its prerequisite check instead of writing config for a
# daemon that is not there.
SSH_OUT="$(cd "${PROJECT_DIR}" && bash hardening/ssh.sh --user rootish --port 2222 --yes 2>&1)"
SSH_RC=$?
if command -v sshd >/dev/null 2>&1; then
    assert_has "ssh stage runs with sshd present" "${SSH_OUT}" "SSH hardening will"
else
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${SSH_RC}" -ne 0 ]] && ! grep -q "Installed " <<< "${SSH_OUT}"; then
        ok "ssh stage aborted before writing any config"
    else
        nok "ssh stage should abort without sshd (rc=${SSH_RC})"
        printf '%s\n' "${SSH_OUT}" | tail -20
    fi
    assert_absent_file "no drop-in written" "${WORK_DIR}/etc-ssh"
fi

echo
echo "== fail2ban stage dry-run =="
# JAIL_TARGET is redirected into the sandbox, so the test proves the stage wrote
# nothing even when fail2ban is absent from the runner.
F2B_JAIL="${WORK_DIR}/etc-fail2ban-jail.conf"
F2B_OUT="$(cd "${PROJECT_DIR}" && JAIL_TARGET="${F2B_JAIL}" bash hardening/fail2ban.sh --port 2222 --yes 2>&1)"
F2B_RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${F2B_RC}" -eq 0 ]]; then
    ok "fail2ban.sh completed in dry-run"
else
    nok "fail2ban.sh exited ${F2B_RC}"
    printf '%s\n' "${F2B_OUT}" | tail -20
fi
assert_has "rendered jail install was intercepted" "${F2B_OUT}" "[dry-run] install"
assert_has "reached the end of the stage" "${F2B_OUT}" "fail2ban hardening plan is complete"
assert_has "no live reload attempted" "${F2B_OUT}" "skipping fail2ban reload"
assert_absent_file "jail target not written" "${F2B_JAIL}"

echo
echo "== bootstrap orchestration dry-run =="
# The real stages stop on missing daemons, so the orchestrator is exercised with
# stub stages in a sandbox copy of the repository. That proves the --dry-run flag
# reaches every child command line instead of depending on the host. The account
# check is stubbed too, because a throwaway user cannot be assumed to exist.
BOOT_DIR="${WORK_DIR}/orchestrator"
mkdir -p "${BOOT_DIR}/hardening" "${BOOT_DIR}/tests"
cp -a "${PROJECT_DIR}/lib" "${BOOT_DIR}/lib"
cp "${PROJECT_DIR}/bootstrap.sh" "${BOOT_DIR}/bootstrap.sh"
printf '\nrequire_allow_users() { return 0; }\n' >> "${BOOT_DIR}/lib/common.sh"
for stage in ssh firewall fail2ban; do
    printf '#!/usr/bin/env bash\necho "STAGE %s $*"\n' "${stage}" > "${BOOT_DIR}/hardening/${stage}.sh"
done
printf '#!/usr/bin/env bash\necho "STAGE verify $*"\n' > "${BOOT_DIR}/tests/verify.sh"

BOOT_OUT="$(cd "${BOOT_DIR}" && bash bootstrap.sh --user testadmin --port 2222 --yes --dry-run 2>&1)"
assert_lacks "the orchestrator knows the flag" "${BOOT_OUT}" "Unknown argument: --dry-run"
STAGE_LINES="$(printf '%s\n' "${BOOT_OUT}" | grep -F 'STAGE ' || true)"
STAGE_COUNT="$(printf '%s\n' "${STAGE_LINES}" | grep -cF STAGE || true)"
DRY_COUNT="$(printf '%s\n' "${STAGE_LINES}" | grep -cF -- --dry-run || true)"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${STAGE_COUNT}" -eq 3 && "${DRY_COUNT}" -eq 3 ]]; then
    ok "every stage was invoked with --dry-run"
else
    nok "a stage was invoked without --dry-run (stages=${STAGE_COUNT}, dry=${DRY_COUNT})"
    printf '%s\n' "${BOOT_OUT}" | tail -20 | sed 's/^/        out: /'
fi
assert_lacks "the verifier was not run for a plan-only pass" "${BOOT_OUT}" "STAGE verify"

echo
echo "== rollback is a no-op in dry-run =="
# A restore would delete or overwrite live files, so a planned run must refuse it.
RB_OUT="$(cd "${PROJECT_DIR}" && bash hardening/firewall.sh --rollback --dry-run --yes 2>&1)"
assert_has "dry-run rollback declined to restore" "${RB_OUT}" "nothing is restored"
assert_lacks "no restore was attempted" "${RB_OUT}" "Rolling back firewall configuration"

echo
echo "== jail rendering =="
# Load the real render_jail by dropping the common.sh source line and the main call.
sed -e '/source .*common\.sh/d' -e '/^main "\$@"$/d' "${PROJECT_DIR}/hardening/fail2ban.sh" \
    | tr -d '\r' > "${WORK_DIR}/fail2ban_lib.sh"
(
    cd "${PROJECT_DIR}" || exit 1
    # shellcheck disable=SC1091
    source lib/common.sh
    # shellcheck disable=SC1091
    source "${WORK_DIR}/fail2ban_lib.sh"
    SSH_PORT=2222
    INIT_SYSTEM=systemd
    render_jail "${WORK_DIR}/jail-systemd.conf" "ufw" "systemd"
    INIT_SYSTEM=sysv
    render_jail "${WORK_DIR}/jail-sysv.conf" "" "auto"
)
assert_has "port token replaced" "$(cat "${WORK_DIR}/jail-systemd.conf")" "port = 2222"
assert_has "backend token replaced" "$(cat "${WORK_DIR}/jail-systemd.conf")" "backend = systemd"
assert_has "ban action replaced" "$(cat "${WORK_DIR}/jail-systemd.conf")" "banaction = ufw"
assert_has "non-systemd backend" "$(cat "${WORK_DIR}/jail-sysv.conf")" "backend = auto"
assert_lacks "empty action drops the line" "$(cat "${WORK_DIR}/jail-sysv.conf")" "banaction"
assert_lacks "no unresolved tokens" "$(cat "${WORK_DIR}/jail-systemd.conf")" "__"

echo
echo "Ran ${TESTS_RUN} checks, ${TESTS_FAILED} failed."
if [[ "${TESTS_FAILED}" -gt 0 ]]; then
    exit 1
fi
exit 0
