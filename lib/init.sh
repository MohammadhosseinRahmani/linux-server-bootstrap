#!/usr/bin/env bash
# Service manager abstraction for systemd and sysvinit hosts.
# Source this file. Do not execute it.
#
# Devuan, container images, and WSL without systemd all fall back to the
# SysV path, so a stage can still reload sshd or start a firewall there.

INIT_SYSTEM="${INIT_SYSTEM:-}"

detect_init() {
    # A value already in the environment is an override, the same seam OS_RELEASE_FILE
    # is: it lets a test describe a systemd host from inside a container or a sysv host
    # from a VM. Probing would silently replace it with the runner's own answer.
    if [[ -n "${INIT_SYSTEM}" ]]; then
        info "Service manager is ${INIT_SYSTEM} (override)."
        return 0
    fi

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        INIT_SYSTEM="systemd"
    elif command -v service >/dev/null 2>&1; then
        INIT_SYSTEM="sysv"
    else
        INIT_SYSTEM="none"
    fi
    info "Service manager is ${INIT_SYSTEM}."
}

require_init() {
    if [[ "${INIT_SYSTEM}" == "none" ]]; then
        error "No usable service manager was found (systemd or service(8) is required)."
        return 1
    fi
}

# SysV has no unit suffix.
init_unit_name() {
    local unit="${1%.service}"
    printf '%s' "${unit}"
}

svc_daemon_reload() {
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl daemon-reload
    fi
}

# unit files are re-read on daemon-reload, but the [Manager] section of
# system.conf.d is only read again when systemd replaces itself.
svc_daemon_reexec() {
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl daemon-reexec
    fi
}

svc_is_active() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        systemctl is-active --quiet "${unit}"
    else
        service "${unit}" status >/dev/null 2>&1
    fi
}

svc_unit_exists() {
    local unit="${1%.service}"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        systemctl list-unit-files --no-pager --no-legend --type="${2:-service}" "${unit}" 2>/dev/null \
            | awk -v name="${unit}" '$1 == name { found = 1 } END { exit found ? 0 : 1 }'
    else
        [[ -x "/etc/init.d/${unit}" ]]
    fi
}

svc_enable_now() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl enable --now "${unit}"
    else
        if command -v update-rc.d >/dev/null 2>&1; then
            run_cmd update-rc.d "${unit}" defaults
        elif command -v chkconfig >/dev/null 2>&1; then
            run_cmd chkconfig "${unit}" on
        fi
        run_cmd service "${unit}" start
    fi
}

svc_disable_now() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl disable --now "${unit}"
    else
        if command -v update-rc.d >/dev/null 2>&1; then
            run_cmd update-rc.d -f "${unit}" remove
        elif command -v chkconfig >/dev/null 2>&1; then
            run_cmd chkconfig "${unit}" off
        fi
        run_cmd service "${unit}" stop
    fi
}

svc_mask() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl mask "${unit}"
    fi
}

svc_unmask() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl unmask "${unit}"
    fi
}

# Read-only. An unknown answer means the host cannot report the state, which a
# stage has to treat as unknown rather than as disabled.
svc_is_enabled() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
            printf 'enabled\n'
        else
            printf 'disabled\n'
        fi
    else
        printf 'unknown\n'
    fi
}

svc_reload() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl reload "${unit}"
    else
        run_cmd service "${unit}" reload
    fi
}

svc_restart() {
    local unit
    unit="$(init_unit_name "$1")"
    if [[ "${INIT_SYSTEM}" == "systemd" ]]; then
        run_cmd systemctl restart "${unit}"
    else
        run_cmd service "${unit}" restart
    fi
}
