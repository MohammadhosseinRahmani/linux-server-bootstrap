#!/usr/bin/env bash
# Operating system detection and driver selection.
# Source this file. Do not execute it.
#
# detect_os reads an os-release file, picks the driver family from the ID and
# ID_LIKE tokens, and loads lib/drivers/<family>.sh. Matching is on whole
# tokens so that an ID such as "ol" cannot be matched by an unrelated
# substring. OS_RELEASE_FILE can be pointed at a fixture for testing.

OS_ID="${OS_ID:-}"
OS_VERSION="${OS_VERSION:-}"
OS_FAMILY="${OS_FAMILY:-}"
PKG_MGR="${PKG_MGR:-}"
DRIVER="${DRIVER:-}"
DRIVER_PATH="${DRIVER_PATH:-}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

os_release_value() {
    local key="$1"
    awk -F= -v want="${key}" '
        $1 == want {
            value = substr($0, index($0, "=") + 1)
            gsub(/^["'"'"']|["'"'"']$/, "", value)
            print value
            exit
        }
    ' "${OS_RELEASE_FILE}"
}

# Every function a driver must provide. Checked at load time, because a missing
# function would otherwise abort a stage halfway through its changes.
DRIVER_CONTRACT=(
    drv_pkg_install drv_pkg_install_remote drv_updates_apply
    drv_fw_backend drv_fw_install drv_fw_backup_paths drv_fw_snapshot
    drv_fw_record_state drv_fw_restore_runtime drv_fw_apply_port
    drv_fw_deny_others drv_fw_enable drv_fw_is_active drv_fw_port_is_open
    drv_fw_status_text drv_fw_close
    drv_ssh_unit drv_ssh_socket_setup
    drv_f2b_action drv_f2b_prepare_repo
    drv_mac_name drv_mac_install drv_mac_status drv_mac_enforce
    drv_sysctl_dir drv_sysctl_file drv_audit_pkg
    drv_audit_rules_file drv_audit_apply drv_legacy_services
    drv_timesync_pkg drv_timesync_unit
    drv_timezone_apply drv_timezone_file
    drv_locale_apply drv_locale_files
    drv_lockout_files drv_lockout_apply drv_pwquality_pkg
    drv_unattended_setup drv_crypto_policy
)

# Lowercase ID and ID_LIKE words, so drivers match on whole tokens.
os_release_tokens() {
    local raw
    raw="$(os_release_value ID) $(os_release_value ID_LIKE)"
    tr '[:upper:]' '[:lower:]' <<< "${raw}" | tr -s '[:space:]' ' '
    printf '\n'
}

os_has_token() {
    case " ${OS_TOKENS} " in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

os_token_list_for_family() {
    # Each family owns the ID and ID_LIKE words that identify it.
    case "$1" in
        debian) printf 'debian ubuntu\n' ;;
        rhel)   printf 'rhel centos fedora rocky almalinux ol amzn anolis alibaba-cloud-linux tencentos azurelinux\n' ;;
        suse)   printf 'suse opensuse sles sled microos\n' ;;
        *)      printf '\n' ;;
    esac
}

os_pick_family() {
    local family candidate
    for family in debian rhel suse; do
        while read -r candidate; do
            [[ -z "${candidate}" ]] && continue
            if os_has_token "${candidate}"; then
                printf '%s' "${family}"
                return 0
            fi
        done < <(os_token_list_for_family "${family}" | tr ' ' '\n')
    done
    return 1
}

# The command lookup is a function so a test can describe a host that has only yum
# without editing the runner's PATH, which on an RPM machine also holds awk and grep.
os_has_command() {
    command -v "$1" >/dev/null 2>&1
}

# The package manager a stage installs with. Debian and SUSE have one answer; the
# RPM family prefers dnf, falls back to yum, and defaults to dnf when neither is
# installed yet, because require_pkg_mgr re-checks before anything is installed and
# so read-only runs still work on a minimal system.
os_pkg_mgr() {
    case "$1" in
        debian) printf 'apt\n' ;;
        rhel)
            if os_has_command dnf; then
                printf 'dnf\n'
            elif os_has_command yum; then
                printf 'yum\n'
            else
                printf 'dnf\n'
            fi
            ;;
        suse) printf 'zypper\n' ;;
    esac
}

detect_os() {
    if [[ ! -r "${OS_RELEASE_FILE}" ]]; then
        error "${OS_RELEASE_FILE} is missing. This script supports Debian, RPM, and SUSE Linux only."
        return 1
    fi

    OS_ID="$(os_release_value ID)"
    OS_VERSION="$(os_release_value VERSION_ID)"
    OS_TOKENS="$(os_release_tokens)"
    [[ -n "${OS_ID}" ]] || OS_ID="unknown"

    if ! OS_FAMILY="$(os_pick_family)"; then
        error "Unsupported distribution: ${OS_ID} (${OS_VERSION}). Use a Debian-family, RPM-family, or SUSE server."
        return 1
    fi

    PKG_MGR="$(os_pkg_mgr "${OS_FAMILY}")"

    DRIVER="${OS_FAMILY}"
    DRIVER_PATH="${PROJECT_DIR}/lib/drivers/${DRIVER}.sh"
    if [[ ! -r "${DRIVER_PATH}" ]]; then
        error "Driver file is missing: ${DRIVER_PATH}"
        return 1
    fi
    # shellcheck disable=SC1090
    source "${DRIVER_PATH}"
    if ! driver_requires "${DRIVER_CONTRACT[@]}"; then
        return 1
    fi

    info "Detected ${OS_ID} ${OS_VERSION} (family ${OS_FAMILY}, packages ${PKG_MGR}, driver ${DRIVER})."
}

# Major version as an integer, so drivers can compare instead of matching
# release strings. Empty or unparsable input returns 0.
os_major_version() {
    local major
    major="${OS_VERSION%%.*}"
    [[ "${major}" =~ ^[0-9]+$ ]] || major=0
    printf '%s' "${major}"
}

os_is_id() {
    local lower
    lower="$(tr '[:upper:]' '[:lower:]' <<< "${OS_ID}")"
    [[ " ${lower} " == *" $1 "* ]]
}

driver_requires() {
    local fn
    for fn in "$@"; do
        if ! declare -F "${fn}" >/dev/null 2>&1; then
            error "Driver ${DRIVER:-unset} does not define ${fn}."
            return 1
        fi
    done
}
