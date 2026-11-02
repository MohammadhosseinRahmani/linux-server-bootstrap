#!/usr/bin/env bash
# Prove this repository works on this distribution without changing it.
#
# One script serves every host that needs to answer the same question: a GitHub
# Actions container, a WSL distro and a Vagrant VM all run exactly this, so a
# green result means the same thing everywhere. It runs in three steps and then
# compares a fingerprint of the files each stage could have written, because a
# dry run that silently modified the host would otherwise report success.
#
# Usage: sudo bash ci/selfcheck.sh [--with-daemons] [--skip-unit]
#   --with-daemons     also dry-run the ssh, firewall and fail2ban stages. Leave
#                      it off on a minimal image: those stages stop when sshd, ufw
#                      or fail2ban is absent, which is a host fact, not a defect.
#   --skip-unit        run only the orchestrator pass and the fingerprint.
#   --expect-driver N  fail unless the loaded driver is N, which is how CI proves
#                      each image is testing the family it is supposed to.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

WITH_DAEMONS=0
SKIP_UNIT=0
EXPECT_DRIVER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-daemons) WITH_DAEMONS=1; shift ;;
        --skip-unit) SKIP_UNIT=1; shift ;;
        --expect-driver)
            if [[ $# -lt 2 ]]; then
                printf -- '--expect-driver needs a driver name.\n' >&2
                exit 2
            fi
            EXPECT_DRIVER="$2"
            shift 2
            ;;
        -h|--help) sed -n '1,20p' "$0"; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    printf 'Run as root: the stages check for root before anything else.\n' >&2
    exit 1
fi

SANDBOX="$(mktemp -d)"
trap 'rm -rf -- "${SANDBOX}"' EXIT

# Every path a stage writes goes through these three, so redirecting them keeps
# the host clean even if a dry-run guard were ever removed by mistake.
export BACKUP_ROOT="${SANDBOX}/backups"
export STATE_DIR="${SANDBOX}/state"
export LOG_FILE="${SANDBOX}/selfcheck.log"
export SSH_PORT="${SSH_PORT:-2222}"
mkdir -p -- "${BACKUP_ROOT}" "${STATE_DIR}"

FAILED=0

section() {
    printf '\n===== %s =====\n' "$1"
}

# Paths the stages could touch. A directory is fingerprinted by its contents and
# its own mode, because a stage may add a file without replacing the directory.
WATCHED=(
    /etc/hostname
    /etc/timezone
    /etc/locale.gen
    /etc/default/locale
    /etc/locale.conf
    /etc/sysconfig/clock
    /etc/sysconfig/language
    /etc/sysconfig/network
    /etc/sysconfig/SuSEfirewall2
    /etc/apt/apt.conf.d
    /etc/cron.d
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/gshadow
    /etc/sudoers
    /etc/sudoers.d
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d
    /etc/ufw
    /etc/firewalld
    /etc/fail2ban
    /etc/sysctl.conf
    /etc/sysctl.d
    /etc/security/limits.conf
    /etc/security/limits.d
    /etc/security/faillock.conf
    /etc/security/pwquality.conf
    /etc/security/opasswd
    /etc/systemd/system.conf.d
    /etc/audit
    /etc/audit/rules.d
    /etc/selinux/config
    /etc/apparmor.d
    /etc/sysconfig/security
    /etc/pam.d
    /etc/login.defs
    /etc/issue
    /etc/issue.net
    /etc/motd
    /etc/linux-server-bootstrap
    /var/backups/linux-server-bootstrap
    /var/log/linux-server-bootstrap.log
    /root/.ssh
    /home
)

fingerprint() {
    local path mode
    for path in "${WATCHED[@]}"; do
        if [[ -d "${path}" ]]; then
            mode="$(stat -c '%a %U:%G' "${path}" 2>/dev/null || printf unreadable)"
            printf '%s DIR %s %s\n' \
                "$(find "${path}" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum | cut -c1-16)" \
                "${mode}" "${path}"
        elif [[ -e "${path}" ]]; then
            mode="$(stat -c '%a %U:%G' "${path}" 2>/dev/null || printf unreadable)"
            printf '%s FILE %s %s\n' \
                "$(sha256sum "${path}" 2>/dev/null | cut -c1-16)" "${mode}" "${path}"
        else
            printf 'ABSENT %s\n' "${path}"
        fi
    done
}

section "host"
printf 'bash  %s\n' "${BASH_VERSION}"
for tool in awk sed grep find stat; do
    printf '%-5s %s\n' "${tool}" "$(command -v "${tool}" || printf ABSENT)"
done
printf 'awk   %s\n' "$(awk --version 2>/dev/null | head -1 || awk -W version 2>&1 | head -1 || printf unknown)"
# shellcheck disable=SC1091
source "${PROJECT_DIR}/lib/common.sh"
if ! detect_os; then
    error "detect_os failed on this host, so no driver was loaded."
    exit 1
fi
detect_init
printf 'os    %s %s family=%s driver=%s pkg=%s init=%s\n' \
    "${OS_ID}" "${OS_VERSION}" "${OS_FAMILY}" "${DRIVER}" "${PKG_MGR}" "${INIT_SYSTEM}"

# The matrix in CI declares which driver each image should load, so an image
# moving its os-release or a new ID token matching the wrong family fails here
# instead of quietly testing the wrong driver.
if [[ -n "${EXPECT_DRIVER}" && "${EXPECT_DRIVER}" != "${DRIVER}" ]]; then
    error "expected the ${EXPECT_DRIVER} driver, loaded ${DRIVER}"
    FAILED=1
fi

# Taken before anything runs, so the comparison at the end is against this host
# as it was, not against a state a previous test already changed.
fingerprint > "${SANDBOX}/host-before.txt"

section "syntax"
SYNTAX_BAD=0
while IFS= read -r file; do
    if ! bash -n "${file}"; then
        printf 'SYNTAX FAIL %s\n' "${file}"
        SYNTAX_BAD=1
    fi
done < <(cd "${PROJECT_DIR}" && find . -name '*.sh' -not -path './.git/*' -print)
if [[ "${SYNTAX_BAD}" -eq 0 ]]; then
    success "bash -n clean on every shell file"
else
    error "bash -n found a syntax error."
    FAILED=1
fi

if [[ "${SKIP_UNIT}" -eq 0 ]]; then
    section "unit suite"
    if bash "${PROJECT_DIR}/tests/unit/run_all.sh" > "${SANDBOX}/unit.out" 2>&1; then
        grep -E '^Ran [0-9]+ checks|: [0-9]+ check\(s\), [0-9]+ failure' "${SANDBOX}/unit.out" | sed 's/^/  /'
        success "unit suite passed"
    else
        # The suites run in order, so a raw tail reports whichever finished last and
        # hides the one that failed. The runner names the failures instead, and a
        # FAIL line says which check went wrong.
        UNIT_WHY="$(grep -E '^FAILED_SUITES |^  FAIL ' "${SANDBOX}/unit.out" || true)"
        if [[ -n "${UNIT_WHY}" ]]; then
            printf '%s\n' "${UNIT_WHY}" | head -40
            # A FAIL line names the check that went wrong but not what it saw. The
            # suite prints the offending output underneath, so the first failure is
            # reproduced with its context.
            grep -m 1 -A 25 '^  FAIL ' "${SANDBOX}/unit.out" || true
        else
            # No FAIL line means a suite died before it could print one; its output
            # is the only clue left.
            tail -60 "${SANDBOX}/unit.out"
        fi
        error "unit suite failed"
        FAILED=1
    fi
fi

section "orchestrator dry-run"
# Stages that enable a daemon refuse a host with no service manager, which is what a
# container reports, so a plan-only pass there would fail on the runner rather than on
# the plan. The pass describes a sysv host instead: every command a service manager
# would have run is intercepted by the dry run, so nothing is asked of this host, and
# the plan the operator sees is still the plan the stages produce.
if [[ "${INIT_SYSTEM}" == "none" ]]; then
    printf 'no service manager on this host, so the pass plans for a sysv one\n'
    INIT_SYSTEM=sysv
    export INIT_SYSTEM
fi
# A minimal image does not always ship the locale the operator would ask for, and
# the base stage refuses to point LANG at something glibc never generated, so the
# pass uses the first name this host can actually produce.
LOCALE_WANTED="$(
    normalized="$(locale -a 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '-')"
    for candidate in en_US.UTF-8 C.UTF-8 C; do
        if grep -qxF -- "$(tr '[:upper:]' '[:lower:]' <<< "${candidate}" | tr -d '-')" <<< "${normalized}"; then
            printf '%s\n' "${candidate}"
            break
        fi
    done
)"
printf 'locale this host offers: %s\n' "${LOCALE_WANTED:-none}"

BOOT_ARGS=(--user selfcheck --port "${SSH_PORT}" --hostname selfcheck-host
    --timezone UTC --updates --timesync --autoupdates
    --max-logins 5 --core-size 0 --disable-routing --fix-world-writable
    --watch-privileged --immutable --install-mac --include-optional
    --deny 5 --min-len 16 --umask 027 --yes --dry-run)
if [[ -n "${LOCALE_WANTED}" ]]; then
    BOOT_ARGS+=(--locale "${LOCALE_WANTED}")
fi
if [[ "${WITH_DAEMONS}" -eq 0 ]]; then
    BOOT_ARGS+=(--skip ssh --skip firewall --skip-fail2ban)
    printf 'ssh, firewall and fail2ban are left out; pass --with-daemons to include them.\n'
fi
# A host account named selfcheck does not exist, and bootstrap only needs the
# name to build the ssh stage's command line, so the ssh stage is the one place
# the check cannot reach without a real account.
(
    cd "${PROJECT_DIR}" || exit 1
    bash bootstrap.sh "${BOOT_ARGS[@]}"
) > "${SANDBOX}/boot.out" 2>&1
BOOT_RC=$?
if [[ "${BOOT_RC}" -ne 0 ]] && [[ "${WITH_DAEMONS}" -eq 1 ]]; then
    printf 'The ssh stage needs an account that really exists, so retry without it.\n'
    (
        cd "${PROJECT_DIR}" || exit 1
        bash bootstrap.sh "${BOOT_ARGS[@]}" --skip ssh
    ) > "${SANDBOX}/boot.out" 2>&1
    BOOT_RC=$?
fi
STAGES_RUN="$(grep -cE '^\[INFO\] Starting ' "${SANDBOX}/boot.out" || true)"
DRY_LINES="$(grep -c '\[dry-run\]' "${SANDBOX}/boot.out" || true)"
if [[ "${BOOT_RC}" -eq 0 ]]; then
    success "bootstrap --dry-run finished (stages started: ${STAGES_RUN}, dry-run actions: ${DRY_LINES})"
else
    error "bootstrap --dry-run exited ${BOOT_RC}"
    tail -40 "${SANDBOX}/boot.out"
    FAILED=1
fi
if grep -qE '^\[(ERROR|WARN)\]' "${SANDBOX}/boot.out"; then
    printf 'Notable lines from the pass:\n'
    grep -E '^\[(ERROR|WARN)\]' "${SANDBOX}/boot.out" | sed 's/^/  /' | head -15
fi

section "verifier gate"
# The dry run above leaves a backup directory behind for every stage it planned, so
# the verifier gets a rollback root of its own: with nothing applied it has to read
# each stage as not applied and still exit 0.
VERIFY_SANDBOX="${SANDBOX}/verify"
mkdir -p "${VERIFY_SANDBOX}/backups" "${VERIFY_SANDBOX}/state"
(
    cd "${PROJECT_DIR}" || exit 1
    export BACKUP_ROOT="${VERIFY_SANDBOX}/backups"
    export STATE_DIR="${VERIFY_SANDBOX}/state"
    bash tests/verify.sh --port "${SSH_PORT}" --skip-firewall --skip-fail2ban
) > "${SANDBOX}/verify.out" 2>&1
VERIFY_RC=$?
NOT_APPLIED="$(grep -c '^\[SKIP\] .* was not applied' "${SANDBOX}/verify.out" || true)"
if [[ "${VERIFY_RC}" -ne 0 ]]; then
    error "verify.sh exited ${VERIFY_RC} on a host it never changed:"
    grep -E '^\[FAIL\]' "${SANDBOX}/verify.out" | sed 's/^/  /' | head -20
    FAILED=1
elif [[ "${NOT_APPLIED}" -lt 9 ]]; then
    error "verify.sh reported only ${NOT_APPLIED} stage(s) as not applied"
    tail -30 "${SANDBOX}/verify.out"
    FAILED=1
else
    success "verify.sh held back ${NOT_APPLIED} unapplied stage(s) and passed"
fi

section "host fingerprint"
fingerprint > "${SANDBOX}/host-after.txt"
# diff is not a guarantee on a minimal image (the EL containers ship without
# diffutils), and this comparison only needs the lines that differ. grep -Fxv is
# in every image, so a missing diffutility cannot turn into a missing defect.
ADDED="$(grep -Fxv -f "${SANDBOX}/host-before.txt" "${SANDBOX}/host-after.txt" || true)"
GONE="$(grep -Fxv -f "${SANDBOX}/host-after.txt" "${SANDBOX}/host-before.txt" || true)"
if [[ ! -s "${SANDBOX}/host-before.txt" ]]; then
    # An empty baseline would make every later reading look unchanged.
    error "the host fingerprint took no readings, so the comparison proves nothing"
    FAILED=1
elif [[ -z "${ADDED}" && -z "${GONE}" ]]; then
    success "nothing on the host changed"
else
    error "the dry run touched the host:"
    if [[ -n "${ADDED}" ]]; then
        printf '  appeared or changed:\n'
        printf '%s\n' "${ADDED}" | sed 's/^/    /'
    fi
    if [[ -n "${GONE}" ]]; then
        printf '  disappeared:\n'
        printf '%s\n' "${GONE}" | sed 's/^/    /'
    fi
    FAILED=1
fi

section "result"
if [[ "${FAILED}" -eq 0 ]]; then
    printf 'SELFCHECK_OK driver=%s init=%s stages=%s dry_actions=%s\n' \
        "${DRIVER}" "${INIT_SYSTEM}" "${STAGES_RUN}" "${DRY_LINES}"
    exit 0
fi
printf 'SELFCHECK_FAILED driver=%s\n' "${DRIVER}"
exit 1
