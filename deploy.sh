#!/bin/bash

# Packet Sniffer Deployer
# This script sets up a systemd service to run the packet sniffer in the background.

set -e

# --- Configuration ---
SERVICE_NAME="packet-sniffer"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
APP_DIR=$(pwd)
USER=$(whoami)
VENV_DIR="$APP_DIR/env"

# --- Helper Functions ---
print_info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

print_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

print_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
    exit 1
}

# --- Pre-flight Checks ---
print_info "Starting deployment process..."

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
  print_error "This script must be run with sudo to create a systemd service."
fi

# 2. Check if the application directory and venv exist
if [ ! -d "$APP_DIR" ] || [ ! -d "$VENV_DIR" ]; then
    print_error "Application directory or virtual environment not found. Please run install.sh first."
fi

# --- Deployment Steps ---

# 3. Create the systemd service file
print_info "Creating systemd service file at $SERVICE_FILE..."

# Note: We use ExecStart with the full path to the python executable in the venv.
# This is more reliable than activating the venv.
cat > "$SERVICE_FILE" << EOL
[Unit]
Description=Packet Sniffer Web Application
After=network.target

[Service]
User=$USER
Group=$(id -gn $USER)
WorkingDirectory=$APP_DIR
ExecStart=$VENV_DIR/bin/python3 $APP_DIR/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOL

print_success "Service file created."

# 4. Reload systemd, enable and start the service
print_info "Reloading systemd daemon and starting the service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# --- Final Instructions ---
print_success "Deployment complete!"
echo
echo "The packet sniffer is now running as a background service."
echo "To check the status of the service, run:"
echo -e "  \e[32msudo systemctl status $SERVICE_NAME\e[0m"
echo
echo "To view the application logs, run:"
echo -e "  \e[32msudo journalctl -u $SERVICE_NAME -f\e[0m"
echo
echo "To stop the service, run:"
echo -e "  \e[32msudo systemctl stop $SERVICE_NAME\e[0m"
echo
