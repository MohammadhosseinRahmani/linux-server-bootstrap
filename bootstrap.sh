#!/usr/bin/env bash
# Run the baseline in one pass: setup first, then SSH, then the firewall, then
# everything that closes the rest of the CIS gaps.
#
# Stages stay separate scripts. This file only decides which ones run, in what
# order, and with what arguments, so a stage can always be run on its own.

# -E is required: the rollback ERR trap has to fire inside function calls, and
# every stage does its work inside functions.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# The order a full run follows. A stage that needs an option it was not given
# reports that and is skipped, so one missing option does not stop the pass.
STAGE_ORDER=(base users ssh firewall fail2ban sysctl limits perms audit mac services banner auth)

# What each stage is called and where it lives. A name built at run time, such as
# ${STAGE_TITLE_$name}, is not valid bash, so the registry is a real map.
declare -A STAGE_TITLE=(
    [base]="base setup"
    [users]="user preparation"
    [ssh]="SSH hardening"
    [firewall]="firewall"
    [fail2ban]="fail2ban"
    [sysctl]="kernel parameters"
    [limits]="login and core limits"
    [perms]="file permissions"
    [audit]="audit rules"
    [mac]="mandatory access control"
    [services]="legacy services"
    [banner]="login banner"
    [auth]="authentication policy"
)
declare -A STAGE_SCRIPT=(
    [base]="setup/base.sh"
    [users]="setup/users.sh"
    [ssh]="hardening/ssh.sh"
    [firewall]="hardening/firewall.sh"
    [fail2ban]="hardening/fail2ban.sh"
    [sysctl]="hardening/sysctl.sh"
    [limits]="hardening/limits.sh"
    [perms]="hardening/perms.sh"
    [audit]="hardening/audit.sh"
    [mac]="hardening/mac.sh"
    [services]="hardening/services.sh"
    [banner]="hardening/banner.sh"
    [auth]="hardening/auth_policy.sh"
)

ONLY_STAGES=()
SKIP_STAGES=()
RUN_PLAN=()
RUN_STAGES=()
NOT_REQUESTED=()
STATUS_RECORDS=()
NEW_USERS=()
KEY_FILES=()

OPT_HOSTNAME=""
OPT_TIMEZONE=""
OPT_LOCALE=""
OPT_UPDATES=0
OPT_TIMESYNC=0
OPT_AUTOUPDATES=0
OPT_SUDO=0
OPT_GROUPS=""
OPT_MAX_LOGINS=""
OPT_CORE_SIZE=""
OPT_DENY=""
OPT_MIN_LEN=""
OPT_UMASK=""
OPT_DISABLE_ROUTING=0
OPT_FIX_WORLD_WRITABLE=0
OPT_WATCH_PRIVILEGED=0
OPT_IMMUTABLE=0
OPT_INSTALL_MAC=0
OPT_INCLUDE_OPTIONAL=0
SHOW_STATUS=0
SHOW_REPORT=0

usage() {
    cat <<EOF
Usage: bash bootstrap.sh --user NAME [--user NAME...] [options] [--yes]
       bash bootstrap.sh --only STAGE[,STAGE...] [options] [--yes]
       bash bootstrap.sh --status
       bash bootstrap.sh --report
       bash bootstrap.sh --rollback

Stage order:
  ${STAGE_ORDER[*]}

Selection:
  --only LIST           Run just these stages, in the order above.
  --skip NAME           Leave a stage out. Repeatable.
  --skip-firewall       Alias for --skip firewall.
  --skip-fail2ban       Alias for --skip fail2ban.

Base setup (each option turns its own step on, none are implied):
  --updates --timesync --autoupdates
  --hostname NAME --timezone ZONE --locale LANG

Accounts:
  --user NAME        Account that may log in with a key. Repeatable.
  --new-user NAME    Account to create first. Repeatable.
  --key FILE         Public key to install. Repeatable.
  --sudo --groups G1,G2
  --port N           SSH port. Default: saved port, or 22.

Hardening options (a stage without its option uses its own default):
  --disable-routing --fix-world-writable --watch-privileged --immutable
  --install-mac --include-optional --max-logins N --core-size N
  --deny N --min-len N --umask 0NN

Reporting:
  --status           Show the host, the state file and what each stage did.
  --report           Print the same information as JSON.
  --yes --dry-run    Apply without prompting / plan without changing anything.
  --rollback         Undo every stage, in the reverse of the order above.

Supported systems: Debian and Ubuntu family (including non-systemd variants),
RHEL/Rocky/AlmaLinux/Fedora and RPM derivatives, openSUSE Leap and SLES.
Run this on the server as root, after the allowed user has an SSH key.
EOF
}

list_has() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        if [[ "${item}" == "${needle}" ]]; then
            return 0
        fi
    done
    return 1
}

# Reads a comma separated stage list and prints one validated name per line.
parse_stage_list() {
    local raw="$1" name
    local -a parts=()
    local IFS=','
    read -r -a parts <<< "${raw}"
    if [[ "${#parts[@]}" -eq 0 ]]; then
        return 0
    fi
    for name in "${parts[@]}"; do
        [[ -z "${name}" ]] && continue
        if ! list_has "${name}" "${STAGE_ORDER[@]}"; then
            error "Unknown stage: ${name}"
            printf 'Stages are: %s\n' "${STAGE_ORDER[*]}" >&2
            return 2
        fi
        printf '%s\n' "${name}"
    done
}

parse_bootstrap_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --only|--skip)
                if [[ $# -lt 2 ]]; then
                    error "$1 requires a stage name."
                    return 2
                fi
                local list
                list="$(parse_stage_list "$2")" || return 2
                local -a names=()
                local item
                while IFS= read -r item; do
                    [[ -z "${item}" ]] && continue
                    names+=("${item}")
                done <<< "${list}"
                if [[ "${#names[@]}" -eq 0 ]]; then
                    error "$1 needs at least one stage name."
                    return 2
                fi
                if [[ "$1" == "--only" ]]; then
                    ONLY_STAGES+=("${names[@]}")
                else
                    SKIP_STAGES+=("${names[@]}")
                fi
                shift 2
                ;;
            --skip-firewall)
                SKIP_STAGES+=(firewall)
                shift
                ;;
            --skip-fail2ban)
                SKIP_STAGES+=(fail2ban)
                shift
                ;;
            --user|--new-user|--key|--hostname|--timezone|--locale|--groups|\
            --port|--max-logins|--core-size|--deny|--min-len|--umask)
                if [[ $# -lt 2 ]]; then
                    error "$1 requires a value."
                    return 2
                fi
                parse_stage_option "$1" "$2" || return 2
                shift 2
                ;;
            --updates|--timesync|--autoupdates|--sudo|--disable-routing|\
            --fix-world-writable|--watch-privileged|--immutable|--install-mac|\
            --include-optional)
                parse_stage_option "$1" "" || return 2
                shift
                ;;
            --status)
                SHOW_STATUS=1
                shift
                ;;
            --report)
                SHOW_REPORT=1
                shift
                ;;
            --yes|--rollback|--dry-run|-h|--help)
                parse_standard_args "$1" || return 2
                shift
                ;;
            *)
                error "Unknown argument: $1"
                return 2
                ;;
        esac
    done
}

parse_stage_option() {
    local flag="$1" value="$2"
    case "${flag}" in
        --user) SSH_ALLOW_USERS+=("${value}") ;;
        --new-user) NEW_USERS+=("${value}") ;;
        --key) KEY_FILES+=("${value}") ;;
        --groups) OPT_GROUPS="${value}" ;;
        --hostname) OPT_HOSTNAME="${value}" ;;
        --timezone) OPT_TIMEZONE="${value}" ;;
        --locale) OPT_LOCALE="${value}" ;;
        --port) parse_standard_args --port "${value}" || return 2 ;;
        --max-logins) OPT_MAX_LOGINS="${value}" ;;
        --core-size) OPT_CORE_SIZE="${value}" ;;
        --deny) OPT_DENY="${value}" ;;
        --min-len) OPT_MIN_LEN="${value}" ;;
        --umask) OPT_UMASK="${value}" ;;
        --updates) OPT_UPDATES=1 ;;
        --timesync) OPT_TIMESYNC=1 ;;
        --autoupdates) OPT_AUTOUPDATES=1 ;;
        --sudo) OPT_SUDO=1 ;;
        --disable-routing) OPT_DISABLE_ROUTING=1 ;;
        --fix-world-writable) OPT_FIX_WORLD_WRITABLE=1 ;;
        --watch-privileged) OPT_WATCH_PRIVILEGED=1 ;;
        --immutable) OPT_IMMUTABLE=1 ;;
        --install-mac) OPT_INSTALL_MAC=1 ;;
        --include-optional) OPT_INCLUDE_OPTIONAL=1 ;;
        *)
            error "Unknown argument: ${flag}"
            return 2
            ;;
    esac
}

# Builds the argument vector for one stage into STAGE_ARGS. The two setup stages
# return 1 when no option asked for them: creating an account or moving the clock
# is a request, never a default. Every hardening stage has a default and runs in
# a full pass either way.
STAGE_ARGS=()
stage_args() {
    local name="$1"
    local item
    STAGE_ARGS=()

    case "${name}" in
        base)
            local asked=0
            local flag on
            for flag in --hostname --timezone --locale; do
                case "${flag}" in
                    --hostname) on="${OPT_HOSTNAME}" ;;
                    --timezone) on="${OPT_TIMEZONE}" ;;
                    --locale) on="${OPT_LOCALE}" ;;
                esac
                if [[ -n "${on}" ]]; then
                    STAGE_ARGS+=("${flag}" "${on}")
                    asked=1
                fi
            done
            for flag in --updates --timesync --autoupdates; do
                case "${flag}" in
                    --updates) on="${OPT_UPDATES}" ;;
                    --timesync) on="${OPT_TIMESYNC}" ;;
                    --autoupdates) on="${OPT_AUTOUPDATES}" ;;
                esac
                if [[ "${on}" -eq 1 ]]; then
                    STAGE_ARGS+=("${flag}")
                    asked=1
                fi
            done
            if [[ "${asked}" -eq 0 ]]; then
                return 1
            fi
            ;;
        users)
            if [[ "${#NEW_USERS[@]}" -eq 0 ]]; then
                return 1
            fi
            for item in "${NEW_USERS[@]}"; do
                STAGE_ARGS+=(--user "${item}")
            done
            if [[ "${#KEY_FILES[@]}" -gt 0 ]]; then
                for item in "${KEY_FILES[@]}"; do
                    STAGE_ARGS+=(--key "${item}")
                done
            fi
            if [[ "${OPT_SUDO}" -eq 1 ]]; then
                STAGE_ARGS+=(--sudo)
            fi
            if [[ -n "${OPT_GROUPS}" ]]; then
                STAGE_ARGS+=(--groups "${OPT_GROUPS}")
            fi
            ;;
        ssh)
            # The empty test is not decoration: bash 4.2 treats an empty array as
            # unbound, and the plan is built before the missing account is reported.
            if [[ "${#SSH_ALLOW_USERS[@]}" -gt 0 ]]; then
                for item in "${SSH_ALLOW_USERS[@]}"; do
                    STAGE_ARGS+=(--user "${item}")
                done
            fi
            STAGE_ARGS+=(--port "${SSH_PORT}")
            ;;
        firewall|fail2ban)
            STAGE_ARGS+=(--port "${SSH_PORT}")
            ;;
        sysctl)
            if [[ "${OPT_DISABLE_ROUTING}" -eq 1 ]]; then
                STAGE_ARGS+=(--disable-routing)
            fi
            ;;
        limits)
            if [[ -n "${OPT_MAX_LOGINS}" ]]; then
                STAGE_ARGS+=(--max-logins "${OPT_MAX_LOGINS}")
            fi
            if [[ -n "${OPT_CORE_SIZE}" ]]; then
                STAGE_ARGS+=(--core-size "${OPT_CORE_SIZE}")
            fi
            ;;
        perms)
            if [[ "${OPT_FIX_WORLD_WRITABLE}" -eq 1 ]]; then
                STAGE_ARGS+=(--fix-world-writable)
            fi
            ;;
        audit)
            if [[ "${OPT_WATCH_PRIVILEGED}" -eq 1 ]]; then
                STAGE_ARGS+=(--watch-privileged)
            fi
            if [[ "${OPT_IMMUTABLE}" -eq 1 ]]; then
                STAGE_ARGS+=(--immutable)
            fi
            ;;
        mac)
            if [[ "${OPT_INSTALL_MAC}" -eq 1 ]]; then
                STAGE_ARGS+=(--install)
            fi
            ;;
        services)
            if [[ "${OPT_INCLUDE_OPTIONAL}" -eq 1 ]]; then
                STAGE_ARGS+=(--include-optional)
            fi
            ;;
        banner)
            ;;
        auth)
            if [[ -n "${OPT_DENY}" ]]; then
                STAGE_ARGS+=(--deny "${OPT_DENY}")
            fi
            if [[ -n "${OPT_MIN_LEN}" ]]; then
                STAGE_ARGS+=(--min-len "${OPT_MIN_LEN}")
            fi
            if [[ -n "${OPT_UMASK}" ]]; then
                STAGE_ARGS+=(--umask "${OPT_UMASK}")
            fi
            ;;
    esac
}

# RUN_PLAN is what the selection flags left in. RUN_STAGES is what really runs:
# a setup stage nobody asked for is dropped here, so the plan the operator
# confirms is the plan that gets executed.
build_plan() {
    local name
    RUN_PLAN=()
    RUN_STAGES=()
    NOT_REQUESTED=()
    for name in "${STAGE_ORDER[@]}"; do
        if [[ "${#ONLY_STAGES[@]}" -gt 0 ]] && ! list_has "${name}" "${ONLY_STAGES[@]}"; then
            continue
        fi
        if [[ "${#SKIP_STAGES[@]}" -gt 0 ]] && list_has "${name}" "${SKIP_STAGES[@]}"; then
            continue
        fi
        RUN_PLAN+=("${name}")
        if stage_args "${name}"; then
            RUN_STAGES+=("${name}")
        else
            NOT_REQUESTED+=("${STAGE_TITLE[${name}]}")
        fi
    done
}

plan_includes() {
    if [[ "${#RUN_PLAN[@]}" -eq 0 ]]; then
        return 1
    fi
    list_has "$1" "${RUN_PLAN[@]}"
}

run_stage() {
    local name="$1"
    # The vector is built again rather than carried over from the plan, so the
    # arguments shown and the arguments executed cannot drift apart.
    if ! stage_args "${name}"; then
        return 0
    fi

    local -a full=(--yes)
    if dry_run; then
        full+=(--dry-run)
    fi
    if [[ "${#STAGE_ARGS[@]}" -gt 0 ]]; then
        full+=("${STAGE_ARGS[@]}")
    fi

    info "Starting ${STAGE_TITLE[${name}]}..."
    # The status has to be taken from the stage itself. This function only ever runs
    # inside `if ! run_stage ...`, and bash suspends errexit for the whole condition,
    # so a failing stage neither stops the function nor sets its status: the success
    # line below would, and the run would report every stage as finished.
    local stage_rc=0
    bash "${SCRIPT_DIR}/${STAGE_SCRIPT[${name}]}" "${full[@]}" || stage_rc=$?
    if [[ "${stage_rc}" -ne 0 ]]; then
        error "${STAGE_TITLE[${name}]} exited ${stage_rc}."
        return "${stage_rc}"
    fi
    success "${STAGE_TITLE[${name}]} finished."
}

apply_all() {
    if [[ "${#RUN_STAGES[@]}" -eq 0 ]]; then
        error "Nothing in the plan was asked for by an option, so there is nothing to do."
        return 1
    fi

    printf 'linux-server-bootstrap will run:\n'
    local name
    for name in "${RUN_STAGES[@]}"; do
        printf '  - %s (%s)\n' "${STAGE_TITLE[${name}]}" "${STAGE_SCRIPT[${name}]}"
    done
    if [[ "${#NOT_REQUESTED[@]}" -gt 0 ]]; then
        # Joined by hand rather than with ${arr[*]}, because the titles contain
        # spaces and a space joiner reads as one long name.
        local joined
        joined="$(printf '%s, ' "${NOT_REQUESTED[@]}")"
        printf '\nNot asked for by any option, so left out: %s\n' "${joined%, }"
    fi
    printf '\n'
    if plan_includes ssh; then
        printf 'SSH will be restricted to: %s\n' "${SSH_ALLOW_USERS[*]}"
        printf 'SSH port: %s\n' "${SSH_PORT}"
    fi
    printf 'Backups: %s\n\n' "${BACKUP_ROOT}"
    printf 'Open a second SSH session before you start, and do not close this one\n'
    printf 'until bash tests/verify.sh succeeds.\n'
    confirm "Apply the full bootstrap?" || return 1

    if dry_run; then
        warn "Dry run: no stage will change the host, so verification is skipped."
    fi

    for name in "${RUN_STAGES[@]}"; do
        if ! run_stage "${name}"; then
            error "${STAGE_TITLE[${name}]} failed."
            error "The run stopped. Earlier stages are still applied and --rollback undoes them."
            return 1
        fi
    done

    if dry_run; then
        success "Dry run finished. Nothing was applied."
        return 0
    fi

    if [[ "${#ONLY_STAGES[@]}" -gt 0 || "${#SKIP_STAGES[@]}" -gt 0 ]]; then
        info "Skipping verification: the run covered only part of the baseline."
    else
        local -a verify_args=(--port "${SSH_PORT}")
        local user_name
        if [[ "${#SSH_ALLOW_USERS[@]}" -gt 0 ]]; then
            for user_name in "${SSH_ALLOW_USERS[@]}"; do
                verify_args+=(--user "${user_name}")
            done
        fi
        info "Checking the result..."
        bash "${SCRIPT_DIR}/tests/verify.sh" "${verify_args[@]}"
    fi
    success "Bootstrap completed."
}

rollback_all() {
    local index name link
    warn "Rollback goes in the reverse of the apply order."
    for (( index=${#STAGE_ORDER[@]}-1; index>=0; index-- )); do
        name="${STAGE_ORDER[index]}"
        link="${BACKUP_ROOT}/${name}/latest"
        if [[ -L "${link}" ]]; then
            info "Rolling back ${STAGE_TITLE[${name}]}..."
            bash "${SCRIPT_DIR}/${STAGE_SCRIPT[${name}]}" --rollback --yes || return 1
        else
            info "No ${name} backup to restore."
        fi
    done
    success "Rollback pass finished."
}

stage_backup_dir() {
    local link="${BACKUP_ROOT}/$1/latest"
    if [[ -L "${link}" ]]; then
        readlink -f -- "${link}"
    fi
}

collect_status() {
    # A backup directory is what makes a stage "applied": it is the thing a
    # rollback would put back. The state file alone cannot say that.
    local name dir
    STATUS_RECORDS=()
    for name in "${STAGE_ORDER[@]}"; do
        dir="$(stage_backup_dir "${name}")"
        STATUS_RECORDS+=("${name}|${STAGE_TITLE[${name}]}|${dir}")
    done
}

status_field() {
    local record="$1" field="$2"
    case "${field}" in
        1) printf '%s' "${record%%|*}" ;;
        2) local rest="${record#*|}"; printf '%s' "${rest%%|*}" ;;
        *) printf '%s' "${record##*|}" ;;
    esac
}

show_status() {
    printf 'host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf 'system: %s %s (family %s, driver %s, packages %s)\n' \
        "${OS_ID}" "${OS_VERSION}" "${OS_FAMILY}" "${DRIVER}" "${PKG_MGR}"
    printf 'service manager: %s\n' "${INIT_SYSTEM}"
    printf 'ssh port: %s\n' "${SSH_PORT}"
    printf 'allowed users: %s\n' "$(state_value SSH_ALLOW_USERS_LINE)"
    printf 'state file: %s\n' "${STATE_FILE}"
    printf 'backups: %s\n' "${BACKUP_ROOT}"
    printf '\n%-10s %-28s %s\n' "STAGE" "WHAT IT DOES" "LAST BACKUP"
    local record
    for record in "${STATUS_RECORDS[@]}"; do
        local dir
        dir="$(status_field "${record}" 3)"
        if [[ -n "${dir}" ]]; then
            printf '%-10s %-28s %s\n' "$(status_field "${record}" 1)" \
                "$(status_field "${record}" 2)" "${dir}"
        else
            printf '%-10s %-28s %s\n' "$(status_field "${record}" 1)" \
                "$(status_field "${record}" 2)" "not applied"
        fi
    done
}

show_report() {
    local record name title dir applied count=0
    printf '{\n'
    printf '  "generated": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "host": "%s",\n' "$(json_escape "$(hostname 2>/dev/null || printf unknown)")"
    printf '  "os": {"id": "%s", "version": "%s", "family": "%s", "driver": "%s", "packages": "%s"},\n' \
        "$(json_escape "${OS_ID}")" "$(json_escape "${OS_VERSION}")" \
        "$(json_escape "${OS_FAMILY}")" "$(json_escape "${DRIVER}")" "$(json_escape "${PKG_MGR}")"
    printf '  "init": "%s",\n' "$(json_escape "${INIT_SYSTEM}")"
    printf '  "ssh_port": %s,\n' "${SSH_PORT}"
    printf '  "allowed_users": "%s",\n' "$(json_escape "$(state_value SSH_ALLOW_USERS_LINE)")"
    printf '  "state_file": "%s",\n' "$(json_escape "${STATE_FILE}")"
    printf '  "backup_root": "%s",\n' "$(json_escape "${BACKUP_ROOT}")"
    printf '  "stages": [\n'
    for record in "${STATUS_RECORDS[@]}"; do
        name="$(status_field "${record}" 1)"
        title="$(status_field "${record}" 2)"
        dir="$(status_field "${record}" 3)"
        applied=false
        if [[ -n "${dir}" ]]; then
            applied=true
        fi
        count=$((count + 1))
        printf '    {"name": "%s", "title": "%s", "applied": %s, "backup": "%s"}' \
            "$(json_escape "${name}")" "$(json_escape "${title}")" "${applied}" \
            "$(json_escape "${dir}")"
        if [[ "${count}" -lt "${#STATUS_RECORDS[@]}" ]]; then
            printf ',\n'
        else
            printf '\n'
        fi
    done
    printf '  ]\n'
    printf '}\n'
}

# Everything a read-only presentation needs. It is one function because a report
# has to run it with stdout redirected, leaving only the document behind.
gather_status() {
    apply_port_default
    validate_port
    detect_os
    detect_init
    collect_status
}

main() {
    parse_bootstrap_args "$@" || {
        usage >&2
        exit 2
    }
    if [[ "${SHOW_HELP}" -eq 1 ]]; then
        usage
        exit 0
    fi

    # Status and a report only read, so they work for any user and do not take
    # the lock a changing run holds.
    if [[ "${SHOW_STATUS}" -eq 1 || "${SHOW_REPORT}" -eq 1 ]]; then
        if [[ "${SHOW_REPORT}" -eq 1 ]]; then
            # Another program parses the report, so the progress chatter goes to
            # stderr and stdout carries nothing but JSON.
            gather_status >&2
            show_report
        else
            gather_status
            show_status
        fi
        exit 0
    fi

    build_plan

    require_root
    detect_os
    detect_init

    if [[ "${ACTION}" == "rollback" ]]; then
        confirm "Roll back every stage, in the reverse of the apply order?" || exit 1
        take_run_lock || exit 1
        rollback_all
        exit 0
    fi

    if [[ "${#RUN_PLAN[@]}" -eq 0 ]]; then
        error "Every stage was skipped, so there is nothing to do."
        exit 1
    fi
    # Only the SSH stage can lock an operator out, so only it needs a named
    # account; a run limited to sysctl or permissions does not. A previous run's
    # state is accepted so a re-run does not have to repeat --user.
    if plan_includes ssh; then
        load_saved_users_if_empty
        require_allow_users
    fi
    take_run_lock || exit 1
    apply_all
}

main "$@"
