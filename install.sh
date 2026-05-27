#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/waechter"
SCRIPT_INSTALL_PATH="/usr/local/sbin/waechter.sh"
REPO_URL="https://github.com/arnisz/waechter.git"
BRANCH="master"
MODE="${1:-auto}"

# Helper function to parse .env files and export variables
# Handles: KEY=VALUE, KEY="VALUE", KEY='VALUE', KEY=
# Ignores lines starting with # and empty lines.
parse_env_file() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    echo "Loading environment variables from ${env_file}..."
    # Read each line, ignore comments and empty lines
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
      # Remove leading/trailing whitespace from key
      key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      # Remove leading/trailing whitespace and quotes from value
      value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^"\(.*\)"$/\1/;s/^'"'"'\(.*\)'"'"'$/\1/')

      # Only export if key is not empty and not a comment
      if [[ -n "$key" && "${key:0:1}" != '#' ]]; then
        # Export the variable
        export "$key"="$value"
        # echo "Exported: $key" # Uncomment for debugging
      fi
    done < <(grep -v '^\s*#' "$env_file") # Filter out comments and empty lines
  fi
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
  fi
}

ensure_base_dependencies() {
  local -a missing=()
  local pkg
  for pkg in git ca-certificates python3 python3-venv; do
    dpkg -s "$pkg" &>/dev/null || missing+=("$pkg")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Installing bootstrap dependencies: ${missing[*]}"
    apt-get update
    apt-get install -y "${missing[@]}"
  fi
}

refresh_repository() {
  export WAECHTER_BOOTSTRAP_REPO_UPDATED=0

  if [[ ! -d "${APP_DIR}/.git" ]]; then
    if [[ -e "${APP_DIR}" && ! -d "${APP_DIR}" ]]; then
      echo "ERROR: ${APP_DIR} exists but is not a directory." >&2
      exit 1
    fi
    if [[ -d "${APP_DIR}" && -n "$(find "${APP_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
      echo "ERROR: ${APP_DIR} exists but is not a git checkout. Please clean it up first." >&2
      exit 1
    fi

    rm -rf "${APP_DIR}"
    echo "Cloning repository into ${APP_DIR}..."
    git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
    export WAECHTER_BOOTSTRAP_REPO_UPDATED=1
    return
  fi

  local local_commit remote_commit
  echo "Updating repository in ${APP_DIR}..."
  git -C "${APP_DIR}" fetch origin "${BRANCH}"
  local_commit="$(git -C "${APP_DIR}" rev-parse HEAD)"
  remote_commit="$(git -C "${APP_DIR}" rev-parse "origin/${BRANCH}")"

  if [[ "${local_commit}" != "${remote_commit}" ]]; then
  # Safety backup of user-editable files before potentially destructive git operations
  local protected_dir
  protected_dir=$(mktemp -d)
  local -a protected_files=(
    "config/waechter.yaml"
    "data/keywords/heuristic/brand_keywords.csv"
    "data/keywords/heuristic/brand_domains.csv"
    "data/keywords/heuristic/path_keywords.csv"
    "data/keywords/heuristic/url_keywords.csv"
    "data/keywords/heuristic/suspicious_tlds.csv"
    "data/keywords/heuristic/trusted_domains.csv"
    "data/keywords/heuristic/identity_providers.csv"
    "data/keywords/heuristic/hosting_platforms.csv"
  )
  for f in "${protected_files[@]}"; do
    if [[ -f "${APP_DIR}/$f" ]]; then
       mkdir -p "${protected_dir}/$(dirname "$f")"
       cp "${APP_DIR}/$f" "${protected_dir}/$f"
    fi
  done

    echo "Applying update ${local_commit} -> ${remote_commit}..."
    git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
    # Restore protected files if they were backed up
    for f in "${protected_files[@]}"; do
      if [[ -f "${protected_dir}/$f" ]]; then
         mkdir -p "${APP_DIR}/$(dirname "$f")"
         cp "${protected_dir}/$f" "${APP_DIR}/$f"
      fi
    done
    rm -rf "${protected_dir}"

    export WAECHTER_BOOTSTRAP_REPO_UPDATED=1
  else
    echo "Repository already up to date."
  fi
}

ensure_venv_and_package() {
  local python_bin="${APP_DIR}/.venv/bin/python"
  local needs_install=0

  if [[ ! -x "${python_bin}" ]]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "${APP_DIR}/.venv"
    needs_install=1
  fi

  if [[ "${WAECHTER_BOOTSTRAP_REPO_UPDATED:-0}" == "1" ]]; then
    needs_install=1
  fi

  if ! "${python_bin}" -c "import waechter.installer" >/dev/null 2>&1; then
    needs_install=1
  fi

  if [[ "${needs_install}" == "0" ]]; then
    echo "Editable install already usable and repository unchanged; skipping pip refresh."
    return
  fi

  echo "Installing/refreshing Python package in ${APP_DIR}..."
  "${python_bin}" -m pip install --upgrade pip wheel setuptools
  "${python_bin}" -m pip install -e "${APP_DIR}"
}

install_stable_bootstrap() {
  local repo_bootstrap="${APP_DIR}/install.sh"
  if [[ ! -f "${repo_bootstrap}" ]]; then
    echo "ERROR: ${repo_bootstrap} not found after repository sync." >&2
    exit 1
  fi

  install -m 0755 "${repo_bootstrap}" "${SCRIPT_INSTALL_PATH}"
}

run_python_installer() {
  local python_bin="${APP_DIR}/.venv/bin/python"
  if [[ "${MODE}" == "uninstall" && ! -x "${python_bin}" ]]; then
    exec env PYTHONPATH="${APP_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" python3 -m waechter.installer "$@"
  fi

  if [[ "${MODE}" != "uninstall" ]]; then
    install_stable_bootstrap
  fi
  exec "${python_bin}" -m waechter.installer "$@"
}

fallback_uninstall() {
  local unit
  for unit in waechter.service waechter-update.timer waechter-update.service; do
    systemctl stop "${unit}" 2>/dev/null || true
    systemctl disable "${unit}" 2>/dev/null || true
  done
  rm -f "/etc/systemd/system/waechter.service" \
        "/etc/systemd/system/waechter-update.service" \
        "/etc/systemd/system/waechter-update.timer"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed 2>/dev/null || true
  rm -rf "/etc/waechter" "${APP_DIR}"
  rm -f "${SCRIPT_INSTALL_PATH}"
  userdel waechter 2>/dev/null || true
}

main() {
  require_root

  # Load environment variables from .env file if it exists in the script's directory
  local install_script_dir
  install_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
  parse_env_file "${install_script_dir}/.env"

  if [[ "${MODE}" == "uninstall" && ! -d "${APP_DIR}" ]]; then
    echo "No repository checkout found in ${APP_DIR}; removing leftover system files only."
    fallback_uninstall
    exit 0
  fi

  ensure_base_dependencies
  if [[ "${MODE}" != "uninstall" ]]; then
    refresh_repository
    ensure_venv_and_package
  fi
  run_python_installer "$@"
}

main "$@"
