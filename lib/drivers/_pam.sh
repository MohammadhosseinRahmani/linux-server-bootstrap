#!/usr/bin/env bash
# Shared PAM helpers for the drivers.
# Source this file from a driver. The drv_* functions below the probe helpers are
# for drivers only; the module-path probes answer a question about the host, so a
# stage may call those directly.
#
# A wrongly spliced PAM stack stops every new login, so the splice is written to
# be idempotent and the stage checks the resulting order and a real login before
# it reports success.

# The stack directory. It is a variable rather than a literal because a driver
# test has to splice stacks that are not the ones the runner logs people in with.
PAM_DIR="${PAM_DIR:-/etc/pam.d}"

# The module paths are probed because the package that ships pam_faillock.so
# differs by family. PAM_FAILLOCK_MODULE_PATH names the file directly for a
# fixture or a non-standard install.
pam_faillock_module_path() {
    if [[ -n "${PAM_FAILLOCK_MODULE_PATH:-}" ]]; then
        printf '%s\n' "${PAM_FAILLOCK_MODULE_PATH}"
        return 0
    fi
    local dir candidate
    for dir in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /usr/lib/*/security; do
        candidate="${dir}/pam_faillock.so"
        if [[ -f "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

pam_pwquality_module_path() {
    if [[ -n "${PAM_PWQUALITY_MODULE_PATH:-}" ]]; then
        printf '%s\n' "${PAM_PWQUALITY_MODULE_PATH}"
        return 0
    fi
    local dir candidate
    for dir in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /usr/lib/*/security; do
        candidate="${dir}/pam_pwquality.so"
        if [[ -f "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

# pam_faillock reads this file itself, so the thresholds live here and the stack
# lines stay free of arguments. That matters on Debian, where the stack lines are
# also edited by other tools.
faillock_conf_write() {
    local deny="${1:-3}" fail_interval="${2:-900}" unlock_time="${3:-900}"
    local tmp
    tmp="$(mktemp)"
    cat > "${tmp}" <<EOF
# Managed by linux-server-bootstrap hardening/auth_policy.sh
deny = ${deny}
fail_interval = ${fail_interval}
unlock_time = ${unlock_time}
even_deny_root
EOF
    run_cmd mkdir -p -- /etc/security
    install_file 0644 "${tmp}" /etc/security/faillock.conf
    rm -f -- "${tmp}"
}

pwquality_conf_write() {
    local minlen="${1:-14}"
    local tmp
    tmp="$(mktemp)"
    cat > "${tmp}" <<EOF
# Managed by linux-server-bootstrap hardening/auth_policy.sh
minlen = ${minlen}
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforce_for_root
EOF
    run_cmd mkdir -p -- /etc/security
    install_file 0644 "${tmp}" /etc/security/pwquality.conf
    rm -f -- "${tmp}"
}

pam_stack_has_faillock() {
    local file="$1"
    [[ -f "${file}" ]] || return 1
    grep -q 'pam_faillock\.so' -- "${file}"
}

# Inserts the preauth line before the stack's unix auth line and the authfail
# line after it. A stack that jumps over pam_deny with [success=N] has to count
# the inserted line too, otherwise every successful password lands on pam_deny
# and no account can log in.
pam_splice_faillock() {
    local auth_file="$1"
    local account_file="$2"

    if [[ ! -f "${auth_file}" || ! -f "${account_file}" ]]; then
        error "PAM stack is missing: ${auth_file} or ${account_file}"
        return 1
    fi
    # On EL these stacks are symlinks owned by authselect or alternatives. A write
    # has to land on the file the link names: replacing the link itself would
    # detach the managed profile and leave the stack unmanaged.
    auth_file="$(readlink -f -- "${auth_file}")"
    account_file="$(readlink -f -- "${account_file}")"
    if pam_stack_has_faillock "${auth_file}"; then
        info "${auth_file} already references pam_faillock."
        splice_account_line "${account_file}"
        return 0
    fi

    local tmp
    local rc=0
    tmp="$(mktemp)"
    # gawk rejects the "\[" escape in a regex constant, and the drivers have to
    # run on gawk, mawk and busybox awk alike, so a bracket class matches the
    # literal opening bracket instead.
    awk '
        BEGIN { pre = "auth        required      pam_faillock.so preauth silent"; \
                post = "auth        [default=die] pam_faillock.so authfail"; \
                jump = "[[]success=[0-9]+"; \
                spliced = 0 }
        {
            if ($1 == "auth" && $0 ~ /pam_unix\.so/ && spliced == 0) {
                print pre
                line = $0
                # Raise the success jump by one to account for the inserted line.
                if (match(line, jump) > 0) {
                    count = substr(line, RSTART + 9, RLENGTH - 9) + 1
                    line = substr(line, 1, RSTART + 8) count substr(line, RSTART + RLENGTH)
                }
                print line
                print post
                spliced = 1
                next
            }
            print
        }
        END { if (spliced == 0) exit 3 }
    ' "${auth_file}" > "${tmp}" || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        rm -f -- "${tmp}"
        if [[ "${rc}" -eq 3 ]]; then
            error "No pam_unix auth line was found in ${auth_file}, so the stack was left alone."
        fi
        return 1
    fi

    local mode
    mode="$(stat -c '%a' "${auth_file}" 2>/dev/null || printf '0644')"
    install_file "${mode}" "${tmp}" "${auth_file}"
    rm -f -- "${tmp}"

    splice_account_line "${account_file}"
}

splice_account_line() {
    local file="$1"
    if grep -Eq '^[[:space:]]*account[[:space:]].*pam_faillock\.so' -- "${file}"; then
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    awk '
        BEGIN { done = 0 }
        {
            if (done == 0 && $1 == "account" && $0 ~ /pam_unix\.so/) {
                print "account     required      pam_faillock.so"
                print
                done = 1
                next
            }
            print
        }
        END { if (done == 0) exit 3 }
    ' "${file}" > "${tmp}" || {
        rm -f -- "${tmp}"
        error "No pam_unix account line was found in ${file}."
        return 1
    }

    local mode
    mode="$(stat -c '%a' "${file}" 2>/dev/null || printf '0644')"
    install_file "${mode}" "${tmp}" "${file}"
    rm -f -- "${tmp}"
}
