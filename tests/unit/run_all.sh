#!/usr/bin/env bash
# Runs every unit test in tests/unit. Usage: bash tests/unit/run_all.sh
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

status=0
failed_suites=()
for test_file in "${SCRIPT_DIR}"/test_*.sh; do
    echo "=============================================="
    echo "$(basename "${test_file}")"
    echo "=============================================="
    if ! bash "${test_file}"; then
        status=1
        failed_suites+=("$(basename "${test_file}")")
    fi
    echo
done

if [[ "${status}" -eq 0 ]]; then
    echo "All unit tests passed."
else
    # One line a wrapper can grep for. The suites print a lot of output between
    # them, and a runner that only tails the transcript otherwise reports whichever
    # suite finished last instead of the one that failed.
    printf 'FAILED_SUITES %s\n' "${failed_suites[*]}"
fi
exit "${status}"
