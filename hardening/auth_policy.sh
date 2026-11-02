#!/usr/bin/env bash
# Set password aging, complexity, and failed-login lockout.
#
# Three mechanisms meet here, and only the driver knows how the family wires them
# together: login.defs carries the aging and umask defaults, pam_faillock carries
# the lockout, and pam_pwquality carries complexity. The stack edit is the part
# that can lock everybody out, so the stage proves it by authenticating an existing
# account through PAM and rolls back if that fails.

# -E keeps the rollback ERR trap alive inside function calls.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

DENY="${DENY:-3}"
FAIL_INTERVAL="${FAIL_INTERVAL:-900}"
UNLOCK_TIME="${UNLOCK_TIME:-900}"
MIN_LENGTH="${MIN_LENGTH:-14}"
MAX_DAYS="${MAX_DAYS:-365}"
MIN_DAYS="${MIN_DAYS:-1}"
WARN_AGE="${WARN_AGE:-7}"
UMASK="${UMASK:-027}"
PROBE_USER=""
LOGIN_DEFS_DONE=0
LOCKOUT_DONE=0
PWQUALITY_DONE=0

usage() {
    cat <<EOF
Usage: bash hardening/auth_policy.sh [--yes] [--dry-run]
               [--deny N] [--fail-interval S] [--unlock-time S]
               [--min-len N] [--max-days N] [--min-days N] [--warn-age N]
               [--umask 0NN]
       bash hardening/auth_policy.sh --rollback

Writes a managed block into ${LOGIN_DEFS_FILE}, installs the faillock and
pwquality configuration the driver places for this family, and enables account
lockout through the family's supported mechanism.

Defaults: lock after ${DENY} failures within ${FAIL_INTERVAL}s, unlock after
${UNLOCK_TIME}s; minimum password length ${MIN_LENGTH}; password lifetime
${MAX_DAYS}d, warning ${WARN_AGE}d ahead; umask ${UMASK}.

Backups: ${BACKUP_ROOT}/auth/<timestamp>
EOF
}

parse_auth_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --deny|--fail-interval|--unlock-time|--min-len|--max-days|--min-days|--warn-age)
                if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
                    error "$1 requires a non-negative number."
                    return 2
                fi
                case "$1" in
                    --deny) DENY="$2" ;;
                    --fail-interval) FAIL_INTERVAL="$2" ;;
                    --unlock-time) UNLOCK_TIME="$2" ;;
                    --min-len) MIN_LENGTH="$2" ;;
                    --max-days) MAX_DAYS="$2" ;;
                    --min-days) MIN_DAYS="$2" ;;
                    --warn-age) WARN_AGE="$2" ;;
                esac
                shift 2
                ;;
            --umask)
                if [[ $# -lt 2 || ! "$2" =~ ^0?[0-7]{3}$ ]]; then
                    error "--umask needs an octal mode such as 027."
                    return 2
                fi
                UMASK="$2"
                shift 2
                ;;
            --yes|--dry-run|--rollback|-h|--help|--user|--port)
                parse_standard_args "$1" || return 2
                shift
                ;;
            *)
                error "Unknown argument: $1"
                return 2
                ;;
        esac
    done

    if [[ "${DENY}" -eq 0 ]]; then
        error "--deny 0 would lock every account out. Use a value from 1 to 10."
        return 2
    fi
}

# login.defs keeps reading after a match, so the last definition wins and an
# appended managed block overrides the distro defaults.
login_defs_block() {
    printf 'PASS_MAX_DAYS %s\n' "${MAX_DAYS}"
    printf 'PASS_MIN_DAYS %s\n' "${MIN_DAYS}"
    printf 'PASS_WARN_AGE %s\n' "${WARN_AGE}"
    printf 'UMASK %s\n' "${UMASK}"
    printf 'HOME_MODE 0750\n'
    printf 'LOGIN_RETRIES 3\n'
}

apply_login_defs() {
    if [[ ! -f "${LOGIN_DEFS_FILE}" ]]; then
        # A minimal image can ship without login.defs, and the lockout and
        # complexity rules below do not depend on it, so this part is skipped
        # rather than failing the whole policy.
        warn "${LOGIN_DEFS_FILE} does not exist, so aging and umask were left alone."
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    login_defs_block > "${tmp}"
    managed_block_set "${LOGIN_DEFS_FILE}" "${LOGIN_DEFS_BEGIN}" "${LOGIN_DEFS_END}" "${tmp}" || {
        rm -f -- "${tmp}"
        return 1
    }
    rm -f -- "${tmp}"
    LOGIN_DEFS_DONE=1
    success "Updated the managed block in ${LOGIN_DEFS_FILE}"
}

verify_login_defs() {
    if ! grep -q "^${LOGIN_DEFS_BEGIN}$" "${LOGIN_DEFS_FILE}"; then
        error "The managed block is not in ${LOGIN_DEFS_FILE}."
        return 1
    fi
    if ! grep -Eq "^PASS_MAX_DAYS[[:space:]]+${MAX_DAYS}$" "${LOGIN_DEFS_FILE}"; then
        error "PASS_MAX_DAYS did not take the configured value."
        return 1
    fi
    success "${LOGIN_DEFS_FILE} carries the configured defaults."
}

# The order of the three auth lines is what makes faillock work: preauth must
# reject a locked account before any module is consulted, and authfail must run
# only after a failed unix check. A stack that got spliced in the wrong order
# either never locks or locks everyone, so it is checked before anything else.
verify_lockout_stack() {
    local file checked=0
    while IFS= read -r file; do
        [[ "${file}" == */pam.d/* ]] || continue
        [[ -f "${file}" ]] || continue
        # EL7 and a profile without the faillock feature leave the stack alone,
        # and a stack the driver edited by hand is the only one worth checking.
        grep -q 'pam_faillock\.so preauth' "${file}" || continue
        checked=$((checked + 1))

        local pre unix post
        pre="$(grep -n 'pam_faillock\.so preauth' "${file}" | head -n 1 | cut -d: -f1)"
        unix="$(grep -n '^[[:space:]]*auth.*pam_unix\.so' "${file}" | head -n 1 | cut -d: -f1)"
        post="$(grep -n 'pam_faillock\.so authfail' "${file}" | head -n 1 | cut -d: -f1)"

        if [[ -z "${pre}" || -z "${unix}" || -z "${post}" ]] \
            || (( pre >= unix || unix >= post )); then
            error "The faillock lines in ${file} are out of order (preauth ${pre:-none}, unix ${unix:-none}, authfail ${post:-none})."
            return 1
        fi
        if (( $(grep -c 'pam_faillock\.so' "${file}") != 3 )) \
            && (( $(grep -c 'pam_faillock\.so' "${file}") != 2 )); then
            error "${file} carries $(grep -c 'pam_faillock\.so' "${file}") faillock lines; a spliced stack has two auth lines and one account line."
            return 1
        fi
        info "Checked the faillock order in ${file}"
    done < <(drv_lockout_files)

    if [[ "${checked}" -eq 0 ]]; then
        warn "No spliced PAM stack was found, so the faillock order could not be checked."
    fi
    return 0
}

# A login shell reports the umask the stack produced, which is both the proof that
# login.defs was read and a check that the edited account stack still lets an
# existing account in.
pick_probe_user() {
    local candidate
    candidate="${SUDO_USER:-}"
    if [[ -n "${candidate}" && "${candidate}" != "root" ]] \
        && [[ -x "$(getent passwd "${candidate}" | awk -F: '{ print $7 }')" ]]; then
        printf '%s\n' "${candidate}"
        return 0
    fi

    getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 && $1 != "root" { print $1 ":" $7 }' \
        | while IFS=: read -r name shell; do
            if [[ -x "${shell}" ]]; then
                printf '%s\n' "${name}"
                break
            fi
        done
}

pam_smoke_test() {
    PROBE_USER="$(pick_probe_user)"
    if [[ -z "${PROBE_USER}" ]]; then
        warn "No non-root account with a usable shell was found, so the PAM stack was not tested live."
        return 0
    fi

    info "Testing a PAM login as ${PROBE_USER}..."
    local reported
    if ! reported="$(su - "${PROBE_USER}" -c 'umask' 2>/dev/null)"; then
        error "An existing account could not authenticate after the PAM edit."
        return 1
    fi
    success "Login through the edited stack works (umask ${reported} for ${PROBE_USER})."
    if [[ "${reported}" != "${UMASK}" && "${reported}" != "${UMASK#0}" ]]; then
        warn "The shell reports umask ${reported} rather than ${UMASK}; a profile may override it."
    fi
}

apply_lockout() {
    local -a files
    mapfile -t files < <(drv_lockout_files)
    local file
    for file in "${files[@]}"; do
        backup_file "${file}"
    done

    if ! drv_lockout_apply "${DENY}" "${FAIL_INTERVAL}" "${UNLOCK_TIME}"; then
        return 1
    fi
    LOCKOUT_DONE=1
    success "Account lockout is configured: ${DENY} failures, ${UNLOCK_TIME}s."
}

ensure_pwquality() {
    local module
    if module="$(pam_pwquality_module_path)"; then
        info "pam_pwquality is available at ${module}"
        return 0
    fi

    if dry_run; then
        warn "Dry run: pam_pwquality is not present, so the complexity file would be inert."
        return 1
    fi

    info "pam_pwquality is missing, so $(drv_pwquality_pkg) is installed."
    require_pkg_mgr || return 1
    drv_pkg_install "$(drv_pwquality_pkg)" || return 1
    pam_pwquality_module_path
}

apply_pwquality() {
    if ! ensure_pwquality; then
        warn "Password complexity was skipped because pam_pwquality is unavailable."
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    {
        printf '%s\n' "# Managed by linux-server-bootstrap hardening/auth_policy.sh"
        printf 'minlen = %s\n' "${MIN_LENGTH}"
        printf 'dcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n'
        printf 'maxrepeat = 3\n'
        printf 'dictcheck = 1\nusercheck = 1\nenforce_for_root = 1\n'
    } > "${tmp}"
    backup_file "${PWQUALITY_CONF}"
    install_file 0644 "${tmp}" "${PWQUALITY_CONF}"
    rm -f -- "${tmp}"
    PWQUALITY_DONE=1
    success "Password complexity requires at least ${MIN_LENGTH} characters with mixed classes."
}

rollback_component() {
    trap - ERR
    rollback_preflight || return 0

    local dir="${BACKUP_DIR:-}"
    if [[ -z "${dir}" ]]; then
        dir="$(latest_backup_dir auth)" || return 1
    fi

    warn "Rolling back authentication policy from ${dir}"
    rollback_dir "${dir}" || return 1
    finish_rollback_pointer auth
    if [[ -f "${dir}/snapshots/authselect.txt" ]]; then
        info "If authselect was used, this was the profile before the change:"
        sed 's/^/  /' "${dir}/snapshots/authselect.txt"
    fi
    success "Authentication policy rollback finished."
    warn "Test a login from a second session before closing this one."
}

plan_text() {
    printf '%s\n' "Authentication policy will:"
    if [[ -f "${LOGIN_DEFS_FILE}" ]]; then
        printf '%s\n' "  - set aging to ${MAX_DAYS}d max, ${MIN_DAYS}d min, ${WARN_AGE}d warning and umask ${UMASK} in ${LOGIN_DEFS_FILE}"
    else
        printf '%s\n' "  - leave aging and umask alone because ${LOGIN_DEFS_FILE} does not exist"
    fi
    printf '%s\n' "  - lock an account after ${DENY} failures in ${FAIL_INTERVAL}s for ${UNLOCK_TIME}s"
    printf '%s\n' "  - require ${MIN_LENGTH} characters with mixed classes when pam_pwquality is present"
    printf '%s\n' "  - authenticate an existing account afterwards to prove the stack still works"
}

apply_auth() {
    plan_text
    confirm "Apply the authentication policy?" || return 1

    backup_begin auth
    backup_file "${LOGIN_DEFS_FILE}"
    backup_file "${STATE_FILE}"
    if command -v authselect >/dev/null 2>&1; then
        save_snapshot authselect.txt authselect current
    fi
    record_kv DENY "${DENY}"
    record_kv MIN_LENGTH "${MIN_LENGTH}"

    arm_rollback
    apply_login_defs || return 1
    apply_lockout || {
        error "Lockout could not be enabled. Restoring the backup."
        rollback_component
        exit 1
    }
    apply_pwquality

    if dry_run; then
        info "Dry run: skipping the login.defs and PAM proofs."
        disarm_rollback
        success "Authentication policy plan is complete."
        return 0
    fi

    if [[ "${LOGIN_DEFS_DONE}" -eq 1 ]] && ! verify_login_defs; then
        error "login.defs was not updated as expected. Restoring the backup."
        rollback_component
        exit 1
    fi
    if [[ "${LOCKOUT_DONE}" -eq 1 ]] && ! verify_lockout_stack; then
        error "The edited PAM stack is not in a working order. Restoring the backup."
        rollback_component
        exit 1
    fi
    if [[ "${LOCKOUT_DONE}" -eq 1 ]] && ! pam_smoke_test; then
        error "An existing account could not log in after the PAM edit. Restoring the backup."
        rollback_component
        exit 1
    fi

    state_set LOCKOUT_DENY "${DENY}"
    # Recorded only for the parts that really ran, so the verifier is not chasing
    # a value this pass never wrote.
    if [[ "${LOGIN_DEFS_DONE}" -eq 1 ]]; then
        state_set PASSWORD_MAX_DAYS "${MAX_DAYS}"
        state_set LOGIN_UMASK "${UMASK}"
    fi
    if [[ "${LOCKOUT_DONE}" -eq 1 ]]; then
        state_set LOCKOUT_FAIL_INTERVAL "${FAIL_INTERVAL}"
        state_set LOCKOUT_UNLOCK_TIME "${UNLOCK_TIME}"
    fi
    if [[ "${PWQUALITY_DONE}" -eq 1 ]]; then
        state_set PASSWORD_MIN_LEN "${MIN_LENGTH}"
    fi
    save_state
    disarm_rollback
    success "Authentication policy completed."
    warn "Aging applies to passwords set from now on; existing hashes keep their dates until they are changed."
}

main() {
    parse_auth_args "$@" || {
        usage >&2
        exit 2
    }
    if [[ "${SHOW_HELP}" -eq 1 ]]; then
        usage
        exit 0
    fi

    require_root
    detect_os
    detect_init

    if [[ "${ACTION}" == "rollback" ]]; then
        confirm "Roll back the latest authentication policy backup?" || exit 1
        rollback_component
        exit 0
    fi

    apply_auth
}

main "$@"
