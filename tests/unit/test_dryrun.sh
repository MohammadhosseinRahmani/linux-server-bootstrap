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
echo "== a dry run builds no backup tree anywhere =="
# The backup root the stage was pointed at stays empty as well: the latest symlink a
# stage writes there is what tests/verify.sh reads to decide the stage was applied, so
# a plan that left one behind would be indistinguishable from a change.
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -d "${BACKUP_ROOT}/firewall" ]]; then
    nok "dry run wrote a backup tree at ${BACKUP_ROOT}/firewall"
else
    ok "no backup tree written, in the sandbox or on the host"
fi
assert_absent_file "host backup root untouched" "/var/backups/linux-server-bootstrap"
assert_absent_file "host state file untouched" "/etc/linux-server-bootstrap/state.env"

echo
echo "== ssh stage stops before writing for an account it cannot prove =="
# The stage checks the allow-listed account for an installed public key before it
# prints a plan, and needs an sshd binary afterwards. Both are host facts, so the
# test looks for an account that really carries a key and expects the refusal when
# the runner has none; either way nothing may be written, because this runs dry.
SSH_TEST_USER=""
while IFS=$'\t' read -r candidate candidate_home; do
    [[ -s "${candidate_home}/.ssh/authorized_keys" ]] || continue
    SSH_TEST_USER="${candidate}"
    break
done < <(awk -F: '{printf "%s\t%s\n", $1, $6}' /etc/passwd)

SSH_OUT="$(cd "${PROJECT_DIR}" && bash hardening/ssh.sh --user "${SSH_TEST_USER:-nobody}" --port 2222 --yes 2>&1)"
SSH_RC=$?
if [[ -n "${SSH_TEST_USER}" ]] && command -v sshd >/dev/null 2>&1; then
    assert_has "ssh stage runs with a keyed account and sshd present" "${SSH_OUT}" "SSH hardening will"
else
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "${SSH_RC}" -ne 0 ]] && ! grep -q "Installed " <<< "${SSH_OUT}"; then
        ok "ssh stage aborted before writing any config"
    else
        nok "ssh stage should abort without a provable account (rc=${SSH_RC})"
        printf '%s\n' "${SSH_OUT}" | tail -20
    fi
fi
assert_absent_file "no drop-in written" "${WORK_DIR}/etc-ssh"

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
mkdir -p "${BOOT_DIR}/hardening" "${BOOT_DIR}/setup" "${BOOT_DIR}/tests"
cp -a "${PROJECT_DIR}/lib" "${BOOT_DIR}/lib"
cp "${PROJECT_DIR}/bootstrap.sh" "${BOOT_DIR}/bootstrap.sh"
printf '\nrequire_allow_users() { return 0; }\n' >> "${BOOT_DIR}/lib/common.sh"
printf '#!/usr/bin/env bash\necho "STAGE verify $*"\n' > "${BOOT_DIR}/tests/verify.sh"
# One stub per registered stage, so a full pass reaches every entry in
# STAGE_ORDER and the counts below are the registry's, not the host's.
for stage in ssh firewall fail2ban sysctl limits perms audit mac services banner auth_policy; do
    printf '#!/usr/bin/env bash\necho "STAGE %s $*"\n' "${stage}" \
        > "${BOOT_DIR}/hardening/${stage}.sh"
done
for stage in base users; do
    printf '#!/usr/bin/env bash\necho "STAGE %s $*"\n' "${stage}" \
        > "${BOOT_DIR}/setup/${stage}.sh"
done

BOOT_OUT="$(cd "${BOOT_DIR}" && bash bootstrap.sh --user testadmin --port 2222 --yes --dry-run 2>&1)"
assert_lacks "the orchestrator knows the flag" "${BOOT_OUT}" "Unknown argument: --dry-run"
STAGE_LINES="$(printf '%s\n' "${BOOT_OUT}" | grep -F 'STAGE ' || true)"
STAGE_COUNT="$(printf '%s\n' "${STAGE_LINES}" | grep -cF STAGE || true)"
DRY_COUNT="$(printf '%s\n' "${STAGE_LINES}" | grep -cF -- --dry-run || true)"
# Thirteen stages are registered; the two setup stages need an option nobody gave,
# so a full pass runs eleven.
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${STAGE_COUNT}" -eq 11 && "${DRY_COUNT}" -eq 11 ]]; then
    ok "all eleven stages a full pass owns were invoked with --dry-run"
else
    nok "expected 11 stages, each with --dry-run (stages=${STAGE_COUNT}, dry=${DRY_COUNT})"
    printf '%s\n' "${BOOT_OUT}" | tail -25 | sed 's/^/        out: /'
fi
assert_has "base setup is left out when nothing asked for it" "${BOOT_OUT}" "Not asked for by any option, so left out: base setup, user preparation"
assert_has "the port reaches the firewall stub" "${STAGE_LINES}" "STAGE firewall --yes --dry-run --port 2222"
assert_has "the account reaches the ssh stub" "${STAGE_LINES}" "STAGE ssh --yes --dry-run --user testadmin --port 2222"
assert_lacks "the verifier was not run for a plan-only pass" "${BOOT_OUT}" "STAGE verify"

echo
echo "== a stage that fails stops the run =="
# Bash suspends errexit for the whole of an `if !` condition, so a run_stage that
# left the failing stage's status to errexit printed "finished" for a stage that
# exited non-zero, and bootstrap reported success with broken stages. The stub is
# replaced in a second copy of the sandbox so the plan tests below still see the
# working set.
FAIL_DIR="${WORK_DIR}/orchestrator-fail"
mkdir -p "${FAIL_DIR}"
cp -a "${BOOT_DIR}/lib" "${BOOT_DIR}/bootstrap.sh" "${BOOT_DIR}/hardening" \
    "${BOOT_DIR}/setup" "${BOOT_DIR}/tests" "${FAIL_DIR}/"
printf '#!/usr/bin/env bash\necho "STAGE sysctl $*"\nexit 3\n' \
    > "${FAIL_DIR}/hardening/sysctl.sh"
FAIL_OUT="$(cd "${FAIL_DIR}" && bash bootstrap.sh --user testadmin --yes --dry-run 2>&1)"
FAIL_RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${FAIL_RC}" -ne 0 ]]; then
    ok "the orchestrator exits non-zero when a stage does (rc=${FAIL_RC})"
else
    nok "a run with a failing stage should not report success"
    printf '%s\n' "${FAIL_OUT}" | tail -25 | sed 's/^/        out: /'
fi
assert_has "the failing stage is named with its own status" "${FAIL_OUT}" "kernel parameters exited 3."
assert_has "the run says it stopped" "${FAIL_OUT}" "The run stopped."
assert_lacks "a stage after the failure was not attempted" "${FAIL_OUT}" "STAGE limits"

echo
echo "== --only and --skip narrow the plan =="
ONLY_OUT="$(cd "${BOOT_DIR}" && bash bootstrap.sh --only base,users --hostname srv1 --new-user bob --sudo --yes --dry-run 2>&1)"
ONLY_LINES="$(printf '%s\n' "${ONLY_OUT}" | grep -F 'STAGE ' || true)"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(printf '%s\n' "${ONLY_LINES}" | grep -cF STAGE)" -eq 2 ]]; then
    ok "--only ran exactly the two named stages"
else
    nok "--only ran the wrong set"
    printf '%s\n' "${ONLY_OUT}" | tail -25 | sed 's/^/        out: /'
fi
assert_has "--only still passes --dry-run down" "${ONLY_LINES}" "STAGE base --yes --dry-run --hostname srv1"
assert_has "the new account is handed to the users stage" "${ONLY_LINES}" "STAGE users --yes --dry-run --user bob --sudo"

SKIP_OUT="$(cd "${BOOT_DIR}" && bash bootstrap.sh --user testadmin --skip firewall --skip-fail2ban --yes --dry-run 2>&1)"
SKIP_LINES="$(printf '%s\n' "${SKIP_OUT}" | grep -F 'STAGE ' || true)"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(printf '%s\n' "${SKIP_LINES}" | grep -cF STAGE)" -eq 9 ]] \
    && ! grep -qF 'STAGE firewall' <<< "${SKIP_LINES}" \
    && ! grep -qF 'STAGE fail2ban' <<< "${SKIP_LINES}"; then
    ok "--skip left both named stages out of the pass"
else
    nok "--skip produced the wrong plan"
    printf '%s\n' "${SKIP_OUT}" | tail -25 | sed 's/^/        out: /'
fi

TESTS_RUN=$((TESTS_RUN + 1))
if grep -qF 'Unknown stage: firewal' <<< "$(cd "${BOOT_DIR}" && bash bootstrap.sh --only firewal --yes 2>&1)"; then
    ok "a misspelled stage name is refused"
else
    nok "a misspelled stage name should be refused"
fi

TESTS_RUN=$((TESTS_RUN + 1))
if grep -qF 'needs at least one stage name' <<< "$(cd "${BOOT_DIR}" && bash bootstrap.sh --skip '' --yes 2>&1)"; then
    ok "an empty stage list is refused instead of running everything"
else
    nok "an empty stage list should be refused"
fi

# The plan the operator confirms has to be the plan that runs, so a stage that
# will be left alone must not appear in it.
assert_lacks "the confirmed plan omits the stage that will not run" "${BOOT_OUT}" "user preparation (setup/users.sh)"
EMPTY_PLAN_OUT="$(cd "${BOOT_DIR}" && bash bootstrap.sh --only base,users --yes --dry-run 2>&1)"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${EMPTY_PLAN_OUT}" == *"Nothing in the plan was asked for"* ]]; then
    ok "--only with no matching option says so instead of confirming an empty plan"
else
    nok "expected an empty-plan refusal, got: ${EMPTY_PLAN_OUT}"
fi

echo
echo "== --status and --report read without touching the host =="
# A dedicated backup root keeps the counts below deterministic: the earlier
# dry-runs in this file already left firewall and fail2ban backups behind.
STATUS_BACKUP="${WORK_DIR}/status-backups"
STATUS_STATE="${WORK_DIR}/status-state"
mkdir -p "${STATUS_BACKUP}/firewall/20260101-000000" "${STATUS_STATE}"
ln -sfn "${STATUS_BACKUP}/firewall/20260101-000000" "${STATUS_BACKUP}/firewall/latest"
printf 'SSH_PORT=2222\nSSH_ALLOW_USERS_LINE=testadmin\n' > "${STATUS_STATE}/state.env"

STATUS_OUT="$(cd "${BOOT_DIR}" && BACKUP_ROOT="${STATUS_BACKUP}" STATE_DIR="${STATUS_STATE}" bash bootstrap.sh --status 2>&1)"
assert_has "status names the ssh port from the state file" "${STATUS_OUT}" "ssh port: 2222"
assert_has "status names the allowed user" "${STATUS_OUT}" "allowed users: testadmin"
assert_has "status shows the backup a stage really left behind" "${STATUS_OUT}" "20260101-000000"
assert_has "status marks a stage with no backup as not applied" "${STATUS_OUT}" "not applied"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -cF 'not applied' <<< "${STATUS_OUT}")" -eq 12 ]]; then
    ok "every stage appears exactly once in the table"
else
    nok "expected 12 'not applied' rows, got: ${STATUS_OUT}"
fi
assert_absent_file "a read-only status run takes no lock" "${STATUS_STATE}/run.lock"

REPORT_JSON="${WORK_DIR}/report.json"
REPORT_ERR="${WORK_DIR}/report.err"
(cd "${BOOT_DIR}" && BACKUP_ROOT="${STATUS_BACKUP}" STATE_DIR="${STATUS_STATE}" bash bootstrap.sh --report > "${REPORT_JSON}" 2> "${REPORT_ERR}")
REPORT_OUT="$(cat "${REPORT_JSON}")"
assert_has "report carries the backup root" "${REPORT_OUT}" "\"backup_root\": \"${STATUS_BACKUP}\""
assert_has "report marks the firewall stage applied" "${REPORT_OUT}" "\"name\": \"firewall\", \"title\": \"firewall\", \"applied\": true"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "$(grep -cF '"applied": false' <<< "${REPORT_OUT}")" -eq 12 ]]; then
    ok "report lists all thirteen stages"
else
    nok "expected 12 unapplied stages, got: ${REPORT_OUT}"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if grep -qF 'Detected ' "${REPORT_ERR}" && ! grep -qF 'Detected ' "${REPORT_OUT}"; then
    ok "the progress chatter went to stderr, not into the document"
else
    nok "a report must keep stdout machine-readable"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if command -v python3 >/dev/null 2>&1; then
    if printf '%s\n' "${REPORT_OUT}" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
        ok "the report parses as JSON"
    else
        nok "the report is not valid JSON"
        printf '%s\n' "${REPORT_OUT}" | sed 's/^/        out: /'
    fi
else
    ok "the report ends cleanly (no JSON parser on this host to check it)"
fi
TESTS_RUN=$((TESTS_RUN + 1))
LAST_OBJECT="$(printf '%s\n' "${REPORT_OUT}" | grep -F '"name":' | tail -1)"
if [[ -n "${LAST_OBJECT}" && "${LAST_OBJECT}" != *, ]]; then
    ok "the last stage object is not followed by a comma"
else
    nok "the last stage object must have no trailing comma, got: ${LAST_OBJECT}"
fi

echo
echo "== the run lock keeps two writers apart =="
# mkdir is the lock, so a live holder has to make a second run refuse, and a
# holder that died has to leave a lock the next run can reclaim.
LOCK_STATE="${WORK_DIR}/lockstate"
mkdir -p "${LOCK_STATE}/run.lock"
# The holder is a real live process, because the lock is only honoured when the
# pid recorded in it still exists.
sleep 30 &
HOLDER_PID=$!
printf '%s\n' "${HOLDER_PID}" > "${LOCK_STATE}/run.lock/pid"
LOCK_OUT="$(cd "${PROJECT_DIR}" && bash -c "
    # shellcheck disable=SC1091
    source lib/common.sh
    DRY_RUN=0
    RUN_LOCK_DIR='${LOCK_STATE}/run.lock'
    take_run_lock
" 2>&1)"
LOCK_RC=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [[ "${LOCK_RC}" -ne 0 ]] && grep -qF 'Another run is in progress' <<< "${LOCK_OUT}"; then
    ok "a second run is refused while the holder lives"
else
    nok "the lock should refuse a concurrent run (rc=${LOCK_RC})"
    printf '%s\n' "${LOCK_OUT}" | sed 's/^/        out: /'
fi
kill "${HOLDER_PID}" 2>/dev/null || true
wait "${HOLDER_PID}" 2>/dev/null || true
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -d "${LOCK_STATE}/run.lock" ]]; then
    ok "a refused run leaves the holder's lock in place"
else
    nok "the refused run deleted the lock it did not own"
fi

STALE_OUT="$(cd "${PROJECT_DIR}" && bash -c "
    # shellcheck disable=SC1091
    source lib/common.sh
    DRY_RUN=0
    RUN_LOCK_DIR='${LOCK_STATE}/stale.lock'
    mkdir -p \"\${RUN_LOCK_DIR}\"
    printf '${HOLDER_PID}\n' > \"\${RUN_LOCK_DIR}/pid\"
    take_run_lock && printf 'TOOK_THE_LOCK\n'
" 2>&1)"
assert_has "a lock left by a dead run is reclaimed" "${STALE_OUT}" "Removing the lock left behind"
assert_has "the reclaiming run holds the lock" "${STALE_OUT}" "TOOK_THE_LOCK"

echo
echo "== a re-run closes the port the earlier run opened =="
# Moving the port twice would otherwise leave the old one filtered-open forever.
PREV_STATE_DIR="${WORK_DIR}/prevstate"
PREV_BACKUP_DIR="${WORK_DIR}/prevbackups"
mkdir -p "${PREV_STATE_DIR}" "${PREV_BACKUP_DIR}"
printf 'SSH_PORT=9022\nSSH_MANAGED_PORT=9022\nSSH_ALLOW_USERS_LINE=testadmin\n' > "${PREV_STATE_DIR}/state.env"
CLOSE_OUT="$(cd "${PROJECT_DIR}" && STATE_DIR="${PREV_STATE_DIR}" BACKUP_ROOT="${PREV_BACKUP_DIR}" bash hardening/firewall.sh --port 2222 --yes 2>&1)"
assert_has "the plan closes the port the earlier run opened" "${CLOSE_OUT}" "close port 9022, which an earlier run opened"
assert_has "the managed port is recorded for the next run" "${CLOSE_OUT}" "save state 2222"
# The session-port guard wins over the close: killing the operator's own
# connection is worse than leaving one stale rule behind.
LIVE_OUT="$(cd "${PROJECT_DIR}" && STATE_DIR="${PREV_STATE_DIR}" BACKUP_ROOT="${PREV_BACKUP_DIR}" SSH_CONNECTION="10.0.0.1 5555 10.0.0.2 9022" bash hardening/firewall.sh --port 2222 --yes 2>&1)"
assert_has "the live session port is kept open" "${LIVE_OUT}" "This session uses port 9022"
assert_lacks "the live session port is not closed" "${LIVE_OUT}" "close port 9022, which an earlier run opened"

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
