#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="waechter"
APP_USER="waechter"
APP_DIR="/opt/waechter"
ENV_DIR="/etc/waechter"
ENV_FILE="${ENV_DIR}/waechter.env"
REPO_URL="https://github.com/arnisz/waechter.git"
BRANCH="master"

: "${WORKER_BASE_URL:?WORKER_BASE_URL is required}"
: "${WAECHTER_TOKEN:?WAECHTER_TOKEN is required}"

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

detect_clamav_socket() {
  local configured_socket=""

  if [[ -f /etc/clamav/clamd.conf ]]; then
    configured_socket="$(
      awk '
        $1 == "LocalSocket" && $2 != "" {
          print $2
          exit
        }
      ' /etc/clamav/clamd.conf
    )"
  fi

  if [[ -n "${configured_socket}" ]]; then
    echo "${configured_socket}"
    return 0
  fi

  for candidate in \
    /var/run/clamav/clamd.ctl \
    /run/clamav/clamd.ctl
  do
    if [[ -S "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  # Debian/Raspberry Pi OS default fallback
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

echo "[1/8] Installing system packages..."
apt-get update
apt-get install -y \
  git \
  ca-certificates \
  python3 \
  python3-venv \
  python3-pip

if [[ "${CLAMAV_ENABLED}" == "true" ]]; then
  echo "[2/8] Installing and configuring ClamAV..."
  apt-get install -y clamav clamav-daemon

  systemctl enable --now clamav-daemon

  if [[ -z "${CLAMAV_SOCKET_PATH}" ]]; then
    CLAMAV_SOCKET_PATH="$(detect_clamav_socket)"
  fi

  echo "Detected ClamAV socket: ${CLAMAV_SOCKET_PATH}"

  if wait_for_clamav_socket "${CLAMAV_SOCKET_PATH}"; then
    echo "ClamAV socket is available."
  else
    echo "WARNING: ClamAV socket was configured as ${CLAMAV_SOCKET_PATH}, but it is not available yet."
    echo "Check with: systemctl status clamav-daemon"
  fi
else
  echo "[2/8] Skipping ClamAV."
  CLAMAV_SOCKET_PATH="${CLAMAV_SOCKET_PATH:-}"
fi

echo "[3/8] Creating system user..."
if ! id "${APP_USER}" >/dev/null 2>&1; then
  useradd \
    --system \
    --home "${APP_DIR}" \
    --create-home \
    --shell /usr/sbin/nologin \
    "${APP_USER}"
fi

if [[ "${CLAMAV_ENABLED}" == "true" ]] && getent group clamav >/dev/null 2>&1; then
  echo "Adding ${APP_USER} to clamav group..."
  usermod -aG clamav "${APP_USER}"
fi

echo "[4/8] Cloning or updating repository..."
if [[ ! -d "${APP_DIR}/.git" ]]; then
  git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
else
  git -C "${APP_DIR}" fetch origin "${BRANCH}"
  git -C "${APP_DIR}" reset --hard "origin/${BRANCH}"
fi

chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

echo "[5/8] Creating Python virtual environment..."
sudo -u "${APP_USER}" python3 -m venv "${APP_DIR}/.venv"

echo "[6/8] Installing Python package..."
sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python" -m pip install --upgrade pip wheel setuptools

# Besser als requirements.txt für Produktion:
# Die Runtime-Dependencies sind in pyproject.toml definiert.
sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python" -m pip install -e "${APP_DIR}"

echo "[7/8] Writing environment file..."
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

echo "[8/8] Installing systemd service..."
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

echo
echo "Waechter installed."
echo "Status:"
systemctl --no-pager status "${APP_NAME}.service" || true
echo
echo "Logs:"
echo "journalctl -u ${APP_NAME} -f"