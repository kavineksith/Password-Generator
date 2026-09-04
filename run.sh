#!/usr/bin/env bash
#
# run.sh - Bootstrap script for passforge.
#
# Verifies Python 3.11+, creates/reuses a local virtual environment,
# installs dependencies on first run, then hands off execution to the
# passforge CLI (argparse mode if arguments are given, interactive
# wizard otherwise).
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"
MIN_MAJOR=3
MIN_MINOR=11

log()  { printf '[run.sh] %s\n' "$1"; }
die()  { printf '[run.sh] ERROR: %s\n' "$1" >&2; exit 1; }

find_python() {
    for candidate in python3.12 python3.11 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

check_python_version() {
    local py="$1"
    "$py" - <<'PYCHECK'
import sys
major, minor = sys.version_info[:2]
sys.exit(0 if (major, minor) >= (3, 11) else 1)
PYCHECK
}

main() {
    PYTHON_BIN="$(find_python)" || die "No Python interpreter found on PATH."
    log "Using interpreter: $(command -v "$PYTHON_BIN")"

    if ! check_python_version "$PYTHON_BIN"; then
        die "Python ${MIN_MAJOR}.${MIN_MINOR}+ is required. Found: $("$PYTHON_BIN" --version 2>&1)"
    fi

    if [[ ! -d "$VENV_DIR" ]]; then
        log "Creating virtual environment at ${VENV_DIR}"
        "$PYTHON_BIN" -m venv "$VENV_DIR"
        NEEDS_INSTALL=1
    fi

    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate"

    if [[ "${NEEDS_INSTALL:-0}" -eq 1 ]] || [[ "${1:-}" == "--reinstall" ]]; then
        log "Installing dependencies..."
        pip install --quiet --upgrade pip
        pip install --quiet -r "${PROJECT_ROOT}/requirements.txt"
        pip install --quiet -e "${PROJECT_ROOT}"
        [[ "${1:-}" == "--reinstall" ]] && shift
    fi

    log "Launching passforge..."
    exec python -m passforge.cli.main "$@"
}

main "$@"
