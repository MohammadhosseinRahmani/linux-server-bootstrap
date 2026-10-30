#!/usr/bin/env bash
# Shared mandatory-access-control helpers for the drivers.
# Source this file from a driver. Do not execute it and do not call it from a
# stage: the stage asks the driver, the driver picks the helper that fits.

# SELinux is live through setenforce and persistent through /etc/selinux/config.
# Going from Disabled to enforcing needs a relabel and a reboot, which cannot be
# done safely over SSH, so this refuses instead of half-doing it.
mac_enforce_selinux() {
    if ! command -v getenforce >/dev/null 2>&1; then
        error "getenforce is not installed, so SELinux cannot be inspected."
        return 1
    fi

    local current
    current="$(getenforce 2>/dev/null || true)"
    case "${current}" in
        Enforcing)
            info "SELinux is already enforcing."
            return 0
            ;;
        Disabled)
            error "SELinux is disabled. Turning it on needs a full relabel and a reboot."
            error "Set SELINUX=enforcing in ${SELINUX_CONFIG:-/etc/selinux/config}, create /.autorelabel and reboot."
            return 1
            ;;
        '')
            error "getenforce returned nothing."
            return 1
            ;;
    esac

    info "SELinux is ${current}. Switching to enforcing."
    run_cmd setenforce 1
    selinux_persist_enforcing || return 1
    success "SELinux is enforcing and set to stay that way."
}

selinux_persist_enforcing() {
    local file="${SELINUX_CONFIG:-/etc/selinux/config}"
    if [[ ! -f "${file}" ]]; then
        error "SELinux configuration file is missing: ${file}"
        return 1
    fi

    local tmp
    tmp="$(mktemp)"
    if ! sed -e 's/^[[:space:]]*SELINUX[[:space:]]*=.*/SELINUX=enforcing/' "${file}" > "${tmp}"; then
        rm -f -- "${tmp}"
        return 1
    fi
    install_file 0644 "${tmp}" "${file}"
    rm -f -- "${tmp}"
}

# AppArmor profiles start in complain mode on a fresh install. Enforcing them is
# the CIS expectation, but a profile that cannot load must not abort the run, so
# every profile is attempted and the failures are counted.
mac_enforce_apparmor() {
    if ! command -v aa-status >/dev/null 2>&1; then
        error "aa-status is not installed, so AppArmor cannot be inspected."
        return 1
    fi
    if ! aa-status --enabled 2>/dev/null; then
        error "AppArmor is not enabled on this host."
        return 1
    fi

    local dir="${APPARMOR_PROFILE_DIR:-/etc/apparmor.d}"
    if [[ ! -d "${dir}" ]]; then
        error "No AppArmor profile directory at ${dir}"
        return 1
    fi

    local profile base loaded=0 failed=0
    for profile in "${dir}"/*; do
        [[ -f "${profile}" ]] || continue
        base="$(basename -- "${profile}")"
        # Includes, abstractions and local fragments are not loadable profiles.
        # Only the file name counts: a parent directory with a dot in it, such as
        # a temporary test directory, must not hide a real profile.
        [[ "${base}" == *.* ]] && continue
        [[ "${base}" == "local" ]] && continue
        if run_cmd aa-enforce "${profile}"; then
            loaded=$((loaded + 1))
        else
            failed=$((failed + 1))
        fi
    done

    info "AppArmor: ${loaded} profile(s) set to enforce, ${failed} refused."
    if [[ "${loaded}" -eq 0 ]]; then
        error "No AppArmor profile could be set to enforce."
        return 1
    fi
}
