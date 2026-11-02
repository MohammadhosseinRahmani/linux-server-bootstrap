#!/usr/bin/env bash
# End-to-end proof on the machine it runs on: apply the baseline, verify it, roll it
# back, and confirm the host came back to where it started.
#
# This is the one script in the repository that changes the host by design. It is
# meant for a throwaway VM (Vagrant, WSL, a cloud instance you can delete), never for
# a server you care about. Usage:
#
#   sudo bash tests/live_check.sh --user admin --key /home/admin/.ssh/id_ed25519.pub
#   sudo bash tests/live_check.sh --family rhel --keep     # leave the baseline applied

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${PROJECT_DIR}/lib/common.sh"

EXPECT_FAMILY=""
KEEP=0
PASS_ARGS=()

usage() {
    cat <<'EOF'
Usage: sudo bash tests/live_check.sh [options] [--yes]

Options:
  --family NAME    Fail unless detect_os reports this family (debian, rhel, suse).
  --keep           Stop after the verification pass; do not roll the host back.
  Everything else (--user, --key, --port, --sudo, ...) is forwarded to bootstrap.sh.

Phases: fingerprint, apply, verify, rollback, fingerprint again. The last step has to
match the first, otherwise the rollback did not undo what it claims to have undone.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --family)
            if [[ $# -lt 2 ]]; then
                printf -- '--family needs a name.\n' >&2
                exit 2
            fi
            EXPECT_FAMILY="$2"
            shift 2
            ;;
        --keep)
            KEEP=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            PASS_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    printf 'Run as root: this applies the baseline to this machine.\n' >&2
    exit 1
fi

SANDBOX="$(mktemp -d)"
trap 'rm -rf -- "${SANDBOX}"' EXIT
# The sourced library writes its log here; nothing in this file reads it back.
# shellcheck disable=SC2034
LOG_FILE="${SANDBOX}/live.log"

# A short list, sampled with the same command before and after, so a difference means
# something the rollback missed. Only paths a stage actually writes are in it: the
# package set and anything a distribution owns are deliberately not compared, because
# a baseline run legitimately leaves those alone.
FINGERPRINT_PATHS=(
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d
    /etc/sysctl.d
    /etc/security/limits.d
    /etc/systemd/system.conf.d
    /etc/security/faillock.conf
    /etc/security/pwquality.conf
    /etc/login.defs
    /etc/passwd
    /etc/group
    /etc/shadow
    /etc/sudoers
    /etc/sudoers.d
    /etc/audit/rules.d
    /etc/pam.d
    /etc/apparmor.d
    /etc/selinux/config
    /etc/issue.net
    /etc/motd
    /etc/hostname
)

fingerprint() {
    local path
    for path in "${FINGERPRINT_PATHS[@]}"; do
        [[ -e "${path}" ]] || {
            printf '%s ABSENT\n' "${path}"
            continue
        }
        if [[ -d "${path}" ]]; then
            # Directory contents matter as much as the directory itself.
            find "${path}" -maxdepth 1 -type f -printf '%p %m %s\n' 2>/dev/null | LC_ALL=C sort
            printf '%s DIR %s\n' "${path}" "$(stat -c '%a' "${path}")"
        else
            # Mode and owner, because a stage that only chowns must still show up here.
            printf '%s %s %s\n' "${path}" \
                "$(stat -c '%a' "${path}")" "$(stat -c '%u:%g' "${path}")"
        fi
    done
}

section() {
    printf '\n===== %s =====\n' "$1"
}

FAILED=0

section "host"
detect_os
detect_init
printf 'family=%s id=%s version=%s init=%s\n' \
    "${OS_FAMILY}" "${OS_ID}" "${OS_VERSION}" "${INIT_SYSTEM}"
if [[ -n "${EXPECT_FAMILY}" && "${OS_FAMILY}" != "${EXPECT_FAMILY}" ]]; then
    error "This image reports family ${OS_FAMILY}, the caller expected ${EXPECT_FAMILY}."
    exit 1
fi

section "fingerprint before"
fingerprint > "${SANDBOX}/before"
printf '%s line(s) recorded\n' "$(wc -l < "${SANDBOX}/before")"

section "apply the baseline"
if ! bash "${PROJECT_DIR}/bootstrap.sh" "${PASS_ARGS[@]+"${PASS_ARGS[@]}"}" --yes 2>&1 |
    tee "${SANDBOX}/apply.out"; then
    error "bootstrap.sh did not finish. The host may be partly configured; the rollback below is the way back."
    FAILED=1
fi

section "verify the baseline"
SSH_PORT_FOR_VERIFY="$(printf '%s\n' "${PASS_ARGS[@]+"${PASS_ARGS[@]}"}" |
    awk '/^--port$/{getline; print; exit}')"
VERIFY_ARGS=()
if [[ -n "${SSH_PORT_FOR_VERIFY}" ]]; then
    VERIFY_ARGS+=(--port "${SSH_PORT_FOR_VERIFY}")
fi
if [[ "${PASS_ARGS[*]-}" == *"--skip-firewall"* ]]; then
    VERIFY_ARGS+=(--skip-firewall)
fi
if [[ "${PASS_ARGS[*]-}" == *"--skip-fail2ban"* ]]; then
    VERIFY_ARGS+=(--skip-fail2ban)
fi
if ! bash "${PROJECT_DIR}/tests/verify.sh" "${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}" 2>&1 |
    tee "${SANDBOX}/verify.out"; then
    error "The verifier found something the baseline claimed to have done."
    FAILED=1
fi

if [[ "${KEEP}" -eq 1 ]]; then
    section "result"
    if [[ "${FAILED}" -eq 0 ]]; then
        success "live_check applied and verified; the baseline is left in place (--keep)."
    else
        printf '[FAIL] live_check finished with errors. bash %s --rollback restores the host.\n' \
            "${PROJECT_DIR}/bootstrap.sh" >&2
        exit 1
    fi
    exit 0
fi

section "rollback"
if ! bash "${PROJECT_DIR}/bootstrap.sh" --rollback --yes 2>&1 | tee "${SANDBOX}/rollback.out"; then
    error "The rollback pass reported a failure."
    FAILED=1
fi

section "fingerprint after"
fingerprint > "${SANDBOX}/after"
if diff -u "${SANDBOX}/before" "${SANDBOX}/after" > "${SANDBOX}/diff"; then
    success "the host is back to its pre-run state"
else
    error "the rollback left these differences behind:"
    sed 's/^/  /' "${SANDBOX}/diff"
    FAILED=1
fi

section "result"
if [[ "${FAILED}" -eq 0 ]]; then
    printf 'LIVE_CHECK_OK family=%s init=%s\n' "${OS_FAMILY}" "${INIT_SYSTEM}"
else
    printf 'LIVE_CHECK_FAILED family=%s\n' "${OS_FAMILY}" >&2
    exit 1
fi
