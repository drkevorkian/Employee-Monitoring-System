#!/bin/bash

echo "========================================"
echo "Employee Monitoring Server - Startup Installer"
echo "========================================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Installing server as systemd service..."

# Get the current directory
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_PATH="python3"
SERVER_SCRIPT="$CURRENT_DIR/apps/server/main.py"
SERVICE_NAME="employee-monitoring-server"
SERVICE_USER="$SUDO_USER"

# Create systemd service file
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Employee Monitoring Server
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$CURRENT_DIR
ExecStart=$PYTHON_PATH $SERVER_SCRIPT
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions
chmod 644 "$SERVICE_FILE"

# Reload systemd
systemctl daemon-reload

# Enable and start the service
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# Check service status
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo
    echo "========================================"
    echo "Installation completed successfully!"
    echo "========================================"
    echo
    echo "Service: $SERVICE_NAME"
    echo "Status: $(systemctl is-active $SERVICE_NAME)"
    echo "Enabled: $(systemctl is-enabled $SERVICE_NAME)"
    echo
    echo "Service commands:"
    echo "  Start:   sudo systemctl start $SERVICE_NAME"
    echo "  Stop:    sudo systemctl stop $SERVICE_NAME"
    echo "  Restart: sudo systemctl restart $SERVICE_NAME"
    echo "  Status:  sudo systemctl status $SERVICE_NAME"
    echo "  Logs:    sudo journalctl -u $SERVICE_NAME -f"
    echo
    echo "The server will now start automatically on boot."
    echo
else
    echo
    echo "========================================"
    echo "Installation failed!"
    echo "========================================"
    echo
    echo "Service status: $(systemctl is-active $SERVICE_NAME)"
    echo "Check logs with: sudo journalctl -u $SERVICE_NAME -f"
    echo
fi

echo "Press Enter to continue..."
read
