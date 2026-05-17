#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="waechter"
APP_USER="waechter"
APP_DIR="/opt/waechter"
ENV_DIR="/etc/waechter"
ENV_FILE="${ENV_DIR}/waechter.env"
REPO_URL="https://github.com/arnisz/waechter.git"
BRANCH="master"

RESTART_NEEDED=false

# ==============================================================================
# PHASE 1: Existierende Konfiguration laden (falls vorhanden)
# ==============================================================================
if [[ -f "${ENV_FILE}" ]]; then
  echo "Existing configuration found in ${ENV_FILE}. Loading variables..."
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ ! "$line" =~ ^# && "$line" =~ = ]]; then
      eval "export $line"
    fi
  done < "${ENV_FILE}"
fi

# Fallbacks definieren, um 'set -u' (Nounset) zu befriedigen
WORKER_BASE_URL="${WORKER_BASE_URL:-}"
WAECHTER_TOKEN="${WAECHTER_TOKEN:-}"
GOOGLE_SAFE_BROWSING_API_KEY="${GOOGLE_SAFE_BROWSING_API_KEY:-}"
CLAMAV_ENABLED="${CLAMAV_ENABLED:-false}"
CLAMAV_SOCKET_PATH="${CLAMAV_SOCKET_PATH:-}"
SCAN_CONCURRENCY="${SCAN_CONCURRENCY:-10}"
BATCH_SIZE="${BATCH_SIZE:-25}"
MIN_WAIT_MS="${MIN_WAIT_MS:-5000}"
MAX_WAIT_MS="${MAX_WAIT_MS:-60000}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
THRESHOLD_WARNING="${THRESHOLD_WARNING:-0.70}"
THRESHOLD_BLOCK="${THRESHOLD_BLOCK:-0.95}"

# Feststellen, ob es sich um eine Neuinstallation oder ein Update handelt
IS_INSTALLED=false
if [[ -f "/etc/systemd/system/${APP_NAME}.service" ]]; then
  IS_INSTALLED=true
fi

# Validation: Token und URL werden bei Neuinstallation zwingend benötigt
if [[ "${IS_INSTALLED}" == "false" ]]; then
  if [[ -z "${WORKER_BASE_URL}" || -z "${WAECHTER_TOKEN}" ]]; then
    echo "ERROR: WORKER_BASE_URL and WAECHTER_TOKEN are required for a fresh installation!"
    echo "Usage: WORKER_BASE_URL=https://... WAECHTER_TOKEN=... ./waechter.sh"
    exit 1
  fi
fi

# ==============================================================================
# HILFSFUNKTIONEN
# ==============================================================================
detect_clamav_socket() {
  if [[ -f /etc/clamav/clamd.conf ]]; then
    local conf_socket
    conf_socket="$(awk '$1 == "LocalSocket" && $2 != "" { print $2; exit }' /etc/clamav/clamd.conf)"
    if [[ -n "${conf_socket}" ]]; then
      echo "${conf_socket}"
      return 0
    fi
  fi
  for candidate in /var/run/clamav/clamd.ctl /run/clamav/clamd.ctl; do
    if [[ -S "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done
  echo "/var/run/clamav/clamd.ctl"
}

wait_for_clamav_socket() {
  local socket_path="$1"
  for _ in {1..10}; do
    if [[ -S "${socket_path}" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

write_env_file() {
  echo "Writing environment configuration to ${ENV_FILE}..."
  install -d -m 0750 -o root -g "${APP_USER}" "${ENV_DIR}"
  cat > "${ENV_FILE}" <<EOF
WORKER_BASE_URL=${WORKER_BASE_URL}
WAECHTER_TOKEN=${WAECHTER_TOKEN}
GOOGLE_SAFE_BROWSING_API_KEY=${GOOGLE_SAFE_BROWSING_API_KEY}
CLAMAV_ENABLED=${CLAMAV_ENABLED}
CLAMAV_SOCKET_PATH=${CLAMAV_SOCKET_PATH}
SCAN_CONCURRENCY=${SCAN_CONCURRENCY}
BATCH_SIZE=${BATCH_SIZE}
MIN_WAIT_MS=${MIN_WAIT_MS}
MAX_WAIT_MS=${MAX_WAIT_MS}
LOG_LEVEL=${LOG_LEVEL}
THRESHOLD_WARNING=${THRESHOLD_WARNING}
THRESHOLD_BLOCK=${THRESHOLD_BLOCK}
EOF
  chown root:"${APP_USER}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
}

# ==============================================================================
# PHASE 2: Core-Pakete & Edge Cases (ClamAV) absichern
# ==============================================================================
echo "Checking system dependencies..."
# Basis-Pakete sicherstellen (tut auch beim Update nicht weh)
if ! dpkg -s git python3-venv python3-pip >/dev/null 2>&1; then
  apt-get update && apt-get install -y git ca-certificates python3 python3-venv python3-pip
fi

# Edge Case: ClamAV wurde nachträglich aktiviert oder deinstalliert
if [[ "${CLAMAV_ENABLED}" == "true" ]]; then
  if ! dpkg -s clamav-daemon >/dev/null 2>&1 || ! systemctl is-active --quiet clamav-daemon; then
    echo "Edge case detected: ClamAV is enabled, but daemon is missing or inactive. Fixing..."
    apt-get update && apt-get install -y clamav clamav-daemon
    systemctl daemon-reload
    systemctl enable --now clamav-daemon
    RESTART_NEEDED=true
  fi

  CLAMAV_SOCKET_PATH="$(detect_clamav_socket)"

  if ! wait_for_clamav_socket "${CLAMAV_SOCKET_PATH}"; then
    echo "WARNING: ClamAV socket (${CLAMAV_SOCKET_PATH}) is not ready yet."
  fi
fi

# System-User absichern
if ! id "${APP_USER}" >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

# Edge Case: User-Gruppe für ClamAV-Zugriff korrigieren
if [[ "${CLAMAV_ENABLED}" == "true" ]] && getent group clamav >/dev/null 2>&1; then
  if ! id -nG "${APP_USER}" | grep -qw "clamav"; then
    echo "Adding ${APP_USER} to clamav group..."
    usermod -aG clamav "${APP_USER}"
    RESTART_NEEDED=true
  fi
fi

# ==============================================================================
# PHASE 3: Weichenstellung (Update vs. Neuinstallation)
# ==============================================================================
if [[ "${IS_INSTALLED}" == "true" ]]; then
  # ----------------------------------------------------------------------------
  # MODUS: AUTOMATISCHES UPDATE
  # ----------------------------------------------------------------------------
  echo "Target system detected: Switching to UPDATE mode."
  cd "${APP_DIR}"

  # Git-Befehle sicher im Kontext des Besitzers ausführen (verhindert dubious ownership)
  sudo -u "${APP_USER}" git fetch origin "${BRANCH}"

  LOCAL_COMMIT=$(sudo -u "${APP_USER}" git rev-parse HEAD)
  REMOTE_COMMIT=$(sudo -u "${APP_USER}" git rev-parse "origin/${BRANCH}")

  if [[ "${LOCAL_COMMIT}" != "${REMOTE_COMMIT}" ]]; then
    echo "New update found on GitHub! Upgrading from ${LOCAL_COMMIT} to ${REMOTE_COMMIT}..."
    sudo -u "${APP_USER}" git reset --hard "origin/${BRANCH}"
    sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python" -m pip install -e "${APP_DIR}"
    RESTART_NEEDED=true
  else
    echo "Code base is already up to date."
  fi

  # Falls Änderungen an ClamAV oder Code stattgefunden haben: Service-Refresh
  if [[ "${RESTART_NEEDED}" == "true" ]]; then
    write_env_file
    echo "Restarting ${APP_NAME} service to load changes..."
    systemctl restart "${APP_NAME}.service"
    echo "Update complete."
  else
    echo "No service restart required."
  fi

else
  # ----------------------------------------------------------------------------
  # MODUS: NEUINSTALLATION
  # ----------------------------------------------------------------------------
  echo "Target system blank: Switching to FRESH INSTALLATION mode."

  echo "Cloning repository..."
  if [[ ! -d "${APP_DIR}/.git" ]]; then
    git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
  else
    git -C "${APP_DIR}" fetch origin "${BRANCH}"
    git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
  fi
  chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

  echo "Creating Python virtual environment..."
  sudo -u "${APP_USER}" python3 -m venv "${APP_DIR}/.venv"
  sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python" -m pip install --upgrade pip wheel setuptools
  sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python" -m pip install -e "${APP_DIR}"

  write_env_file

  echo "Installing systemd service..."
  cat > "/etc/systemd/system/${APP_NAME}.service" <<EOF
[Unit]
Description=Waechter URL scanning worker
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/main.py
Restart=always
RestartSec=10

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${APP_DIR} ${ENV_DIR}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}.service"
  echo "Fresh installation completed successfully."
fi