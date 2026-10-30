#!/usr/bin/env bash
# Runs every unit test in tests/unit. Usage: bash tests/unit/run_all.sh
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

status=0
for test_file in "${SCRIPT_DIR}"/test_*.sh; do
    echo "=============================================="
    echo "$(basename "${test_file}")"
    echo "=============================================="
    if ! bash "${test_file}"; then
        status=1
    fi
    echo
done

if [[ "${status}" -eq 0 ]]; then
    echo "All unit tests passed."
else
    echo "At least one unit test failed."
fi
exit "${status}"
