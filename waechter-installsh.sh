#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="waechter"
APP_USER="waechter"
APP_DIR="/opt/waechter"
ENV_DIR="/etc/waechter"
ENV_FILE="${ENV_DIR}/waechter.env"
SCRIPT_INSTALL_PATH="/usr/local/sbin/waechter.sh"
# Pfad des Installer-Scripts innerhalb des Repos (für Self-Update)
SCRIPT_REPO_RELATIVE_PATH="waechter.sh"
REPO_URL="https://github.com/arnisz/waechter.git"
BRANCH="master"

RESTART_NEEDED=false

# ==============================================================================
# ROOT-CHECK
# ==============================================================================
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: This script must be run as root."
  exit 1
fi

# ==============================================================================
# ARGUMENT-PARSING
# ==============================================================================
MODE="${1:-auto}"

# ==============================================================================
# MODUS: UNINSTALL
# ==============================================================================
if [[ "${MODE}" == "uninstall" ]]; then
  echo "==> Starting uninstallation of ${APP_NAME}..."

  # Hauptdienst stoppen und deaktivieren
  for unit in "${APP_NAME}.service" "${APP_NAME}-update.timer" "${APP_NAME}-update.service"; do
    if systemctl is-active --quiet "${unit}" 2>/dev/null; then
      echo "Stopping ${unit}..."
      systemctl stop "${unit}"
    fi
    if systemctl is-enabled --quiet "${unit}" 2>/dev/null; then
      systemctl disable "${unit}"
    fi
    rm -f "/etc/systemd/system/${unit}"
  done

  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true

  # Applikationsverzeichnis entfernen
  if [[ -d "${APP_DIR}" ]]; then
    rm -rf "${APP_DIR}"
    echo "Removed ${APP_DIR}"
  fi

  # Konfigurationsverzeichnis entfernen
  if [[ -d "${ENV_DIR}" ]]; then
    rm -rf "${ENV_DIR}"
    echo "Removed ${ENV_DIR}"
  fi

  # Installiertes Script entfernen
  if [[ -f "${SCRIPT_INSTALL_PATH}" ]]; then
    rm -f "${SCRIPT_INSTALL_PATH}"
    echo "Removed ${SCRIPT_INSTALL_PATH}"
  fi

  # System-User entfernen
  if id "${APP_USER}" &>/dev/null; then
    userdel "${APP_USER}"
    echo "Removed system user '${APP_USER}'"
  fi

  echo ""
  echo "==> Uninstallation complete."
  exit 0
fi

# ==============================================================================
# PHASE 1: Existierende Konfiguration laden (falls vorhanden)
# ==============================================================================
if [[ -f "${ENV_FILE}" ]]; then
  echo "Existing configuration found in ${ENV_FILE}. Loading variables..."
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Bereinigt Windows-Zeilenenden (\r) und umgebende Whitespaces
    line="${line//$'\r'/}"
    line="${line#"${line%%[! ]*}"}"
    # Matcht KEY=VALUE; eval-frei (verhindert Code-Injection)
    if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
      local_val="${BASH_REMATCH[2]}"
      # FIX: Umschließende einfache oder doppelte Anführungszeichen entfernen,
      # damit z.B. WAECHTER_TOKEN="abc" nicht als '"abc"' in Python ankommt
      local_val="${local_val%\"}" ; local_val="${local_val#\"}"
      local_val="${local_val%\'}" ; local_val="${local_val#\'}"
      export "${BASH_REMATCH[1]}"="${local_val}"
    fi
  done < "${ENV_FILE}"
fi

# Fallbacks
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
    echo "Usage: WORKER_BASE_URL=https://... WAECHTER_TOKEN=... $0"
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
  local timeout="${2:-10}"
  local elapsed=0
  while [[ "${elapsed}" -lt "${timeout}" ]]; do
    if [[ -S "${socket_path}" ]]; then
      return 0
    fi
    if (( elapsed % 10 == 0 && elapsed > 0 )); then
      echo "  Waiting for ClamAV socket... (${elapsed}/${timeout}s)"
    fi
    sleep 1
    (( elapsed++ )) || true
  done
  return 1
}

write_env_file() {
  echo "Writing environment configuration to ${ENV_FILE}..."
  install -d -m 0750 -o root -g "${APP_USER}" "${ENV_DIR}"
  # FIX: Backup der bestehenden Konfiguration vor dem Überschreiben
  if [[ -f "${ENV_FILE}" ]]; then
    cp "${ENV_FILE}" "${ENV_FILE}.bak"
  fi
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

install_update_timer() {
  echo "Installing systemd auto-update timer..."

  # Script in stabilen Pfad kopieren, damit der Timer es immer findet
  install -m 0750 -o root -g root "$(realpath "$0")" "${SCRIPT_INSTALL_PATH}"

  cat > "/etc/systemd/system/${APP_NAME}-update.service" <<EOF
[Unit]
Description=Waechter auto-update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_INSTALL_PATH}
StandardOutput=journal
StandardError=journal
EOF

  cat > "/etc/systemd/system/${APP_NAME}-update.timer" <<EOF
[Unit]
Description=Daily auto-update timer for Waechter

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}-update.timer"
  echo "Auto-update timer enabled (runs daily, randomized by up to 1h)."
}

# ==============================================================================
# PHASE 2: System-User erstellen
# FIX: Vor der ClamAV-Gruppenlogik, damit usermod -aG clamav garantiert klappt
# ==============================================================================
if ! id "${APP_USER}" &>/dev/null; then
  useradd --system --home "${APP_DIR}" --create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

# ==============================================================================
# PHASE 3: Core-Pakete & Edge Cases (ClamAV) absichern
# ==============================================================================
echo "Checking system dependencies..."

# FIX: Pakete einzeln prüfen statt alle auf einmal (dpkg -s <multi> unzuverlässig)
MISSING_PKGS=()
for pkg in git ca-certificates python3 python3-venv python3-pip; do
  dpkg -s "$pkg" &>/dev/null || MISSING_PKGS+=("$pkg")
done
if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
  apt-get update && apt-get install -y "${MISSING_PKGS[@]}"
fi

# Edge Case: ClamAV
if [[ "${CLAMAV_ENABLED}" == "true" ]]; then
  if ! dpkg -s clamav-daemon &>/dev/null || ! systemctl is-active --quiet clamav-daemon; then
    echo "Edge case detected: ClamAV is enabled, but daemon is missing or inactive. Fixing..."
    # FIX: clamav-freshclam explizit installieren und aktivieren
    apt-get update && apt-get install -y clamav clamav-daemon clamav-freshclam
    systemctl daemon-reload
    systemctl enable --now clamav-freshclam
    systemctl enable --now clamav-daemon
    RESTART_NEEDED=true
  fi

  CLAMAV_SOCKET_PATH="$(detect_clamav_socket)"

  # FIX: Erststart braucht bis zu 90s zum Laden der Signaturdatenbank;
  # bei einem bereits laufenden Daemon reichen 10s (Standard)
  clamav_timeout=10
  if [[ "${RESTART_NEEDED}" == "true" ]]; then
    echo "Waiting up to 90s for ClamAV to load signature database on first start..."
    clamav_timeout=90
  fi

  if ! wait_for_clamav_socket "${CLAMAV_SOCKET_PATH}" "${clamav_timeout}"; then
    echo "WARNING: ClamAV socket (${CLAMAV_SOCKET_PATH}) is not ready after ${clamav_timeout}s."
  fi

  # FIX: Gruppenlogik nach User-Erstellung (Phase 2), kein Race-Condition mehr
  if getent group clamav &>/dev/null; then
    if ! id -nG "${APP_USER}" | grep -qw "clamav"; then
      echo "Adding ${APP_USER} to clamav group..."
      usermod -aG clamav "${APP_USER}"
      RESTART_NEEDED=true
    fi
  fi
fi

# ==============================================================================
# PHASE 4: Weichenstellung (Update vs. Neuinstallation)
# ==============================================================================
if [[ "${IS_INSTALLED}" == "true" ]]; then
  # ----------------------------------------------------------------------------
  # MODUS: AUTOMATISCHES UPDATE
  # ----------------------------------------------------------------------------
  echo "Target system detected: Switching to UPDATE mode."

  # FIX: Expliziter Sanity-Check — Service-Datei vorhanden, aber APP_DIR fehlt
  if [[ ! -d "${APP_DIR}/.git" ]]; then
    echo "ERROR: Service file exists but ${APP_DIR} is missing or not a git repo."
    echo "       Run '${SCRIPT_INSTALL_PATH} uninstall' and reinstall."
    exit 1
  fi

  cd "${APP_DIR}"
  sudo -u "${APP_USER}" git fetch origin "${BRANCH}"

  LOCAL_COMMIT=$(sudo -u "${APP_USER}" git rev-parse HEAD)
  REMOTE_COMMIT=$(sudo -u "${APP_USER}" git rev-parse "origin/${BRANCH}")

  if [[ "${LOCAL_COMMIT}" != "${REMOTE_COMMIT}" ]]; then
    echo "New update found! Upgrading from ${LOCAL_COMMIT} to ${REMOTE_COMMIT}..."
    sudo -u "${APP_USER}" git reset --hard "origin/${BRANCH}"
    sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python" -m pip install -e "${APP_DIR}"

    # FIX: Self-Update — Installer-Script aus dem Repo über sich selbst schreiben,
    # damit Bugfixes am Skript beim nächsten Timer-Durchlauf aktiv sind.
    repo_script="${APP_DIR}/${SCRIPT_REPO_RELATIVE_PATH}"
    if [[ -f "${repo_script}" ]]; then
      echo "Self-update: refreshing installer at ${SCRIPT_INSTALL_PATH}..."
      install -m 0750 -o root -g root "${repo_script}" "${SCRIPT_INSTALL_PATH}"
    fi

    RESTART_NEEDED=true
  else
    echo "Code base is already up to date."
  fi

  # FIX: Env-Datei immer schreiben — auch wenn keine Code-Änderungen vorliegen,
  # können per Env-Variable neue Werte übergeben worden sein (z.B. neuer Token).
  write_env_file

  if [[ "${RESTART_NEEDED}" == "true" ]]; then
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
StandardOutput=journal
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR} ${ENV_DIR}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}.service"

  install_update_timer

  echo ""
  echo "==> Fresh installation completed successfully."
  echo "    Service status : systemctl status ${APP_NAME}"
  echo "    Live logs      : journalctl -u ${APP_NAME} -f"
  echo "    Update timer   : systemctl status ${APP_NAME}-update.timer"
  echo "    Uninstall      : ${SCRIPT_INSTALL_PATH} uninstall"
fi
