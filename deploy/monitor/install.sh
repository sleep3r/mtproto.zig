#!/usr/bin/env bash
set -euo pipefail

# Install/update MTProto Proxy Monitor dashboard.
# Usage: bash deploy/monitor/install.sh  (run on the target server)

INSTALL_DIR="/opt/mtproto-proxy/monitor"
SERVICE_NAME="proxy-monitor"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PORT="61208"

echo "=== MTProto Proxy Monitor — Install ==="

# 1. Python deps
echo "[1/4] Installing Python dependencies..."
pip3 install --break-system-packages --quiet \
  fastapi uvicorn psutil websockets 2>/dev/null || \
pip3 install --quiet \
  fastapi uvicorn psutil websockets

# 2. Verify files
if [ ! -f "${INSTALL_DIR}/server.py" ]; then
  echo "ERROR: ${INSTALL_DIR}/server.py not found."
  exit 1
fi
if [ ! -f "${INSTALL_DIR}/static/index.html" ]; then
  echo "ERROR: ${INSTALL_DIR}/static/index.html not found."
  exit 1
fi
echo "[2/4] Files verified"

# 3. Systemd service
echo "[3/4] Creating systemd service..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=MTProto Proxy Monitor
After=network.target mtproto-proxy.service

[Service]
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/server.py
Restart=on-failure
RestartSec=5
WorkingDirectory=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"

# 4. Start/restart
echo "[4/4] Starting ${SERVICE_NAME}..."
systemctl restart "${SERVICE_NAME}"
sleep 2

if systemctl is-active --quiet "${SERVICE_NAME}"; then
  echo ""
  echo "✅ Monitor started (default: 127.0.0.1:61208, configurable in config.toml under [monitor])"
  echo ""
  echo "If using the default config, access via SSH tunnel:"
  echo "  ssh -L 61208:localhost:61208 root@\$(hostname -I | awk '{print \$1}')"
  echo "  open http://localhost:61208"
else
  echo "❌ Failed to start. Check: journalctl -u ${SERVICE_NAME} --no-pager -n 20"
  exit 1
fi
