#!/usr/bin/env bash
set -Eeuo pipefail

# Deprecated compatibility wrapper.
# Preferred entrypoint: `bash install.sh` (repo) or `bash /usr/local/sbin/waechter.sh` (installed bootstrap).
# Keep this file only so older docs/bookmarks continue to work during the transition.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SCRIPT="${SCRIPT_DIR}/install.sh"

if [[ ! -f "${BOOTSTRAP_SCRIPT}" && -f "/opt/waechter/install.sh" ]]; then
  BOOTSTRAP_SCRIPT="/opt/waechter/install.sh"
fi

if [[ ! -f "${BOOTSTRAP_SCRIPT}" ]]; then
  echo "ERROR: install.sh not found next to waechter-installsh.sh or in /opt/waechter." >&2
  exit 1
fi

exec bash "${BOOTSTRAP_SCRIPT}" "$@"
