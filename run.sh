#!/bin/bash

# Autonomous Packet Sniffer Installer and Runner (Linux)
# This script automates the setup and execution of the packet sniffer application.

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
VENV_DIR="env"
GEO_DB_FILE="GeoLite2-City.mmdb"
GEO_DB_URL="https://git.io/GeoLite2-City.mmdb"

# --- Helper Functions ---
print_info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

print_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

print_warning() {
    echo -e "\e[33m[WARNING]\e[0m $1"
}

print_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
    exit 1
}

# --- Pre-flight Checks ---
print_info "Starting autonomous installation and execution for Linux..."

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
  print_error "This script requires root privileges. Please run with sudo: sudo ./install.sh"
fi

# 2. Find Python 3 executable
print_info "Locating Python 3 executable..."
PYTHON_CMD=$(which python3)
if [ -z "$PYTHON_CMD" ]; then
    print_error "python3 is not found in your PATH. Please install Python 3."
fi
print_success "Found Python 3 at $PYTHON_CMD"

# 3. Check for other required commands
for cmd in pip3 wget; do
    if ! command -v $cmd &> /dev/null; then
        print_error "$cmd is required but not found. Please install it."
    fi
done

# --- Installation Steps ---

# 4. Create Python virtual environment
if [ ! -d "$VENV_DIR" ]; then
    print_info "Creating Python virtual environment in '$VENV_DIR'..."
    $PYTHON_CMD -m venv $VENV_DIR
else
    print_info "Virtual environment already exists."
fi

# 5. Activate virtual environment and install dependencies
# We use the venv pip directly to avoid sourcing issues with sudo
VENV_PIP="$VENV_DIR/bin/pip"
print_info "Installing dependencies from requirements.txt..."
"$VENV_PIP" install --upgrade pip
"$VENV_PIP" install -r requirements.txt
print_success "Python dependencies installed."

# 6. Download GeoLite2 City database
if [ ! -f "$GEO_DB_FILE" ]; then
    print_info "Downloading GeoLite2 City database from $GEO_DB_URL..."
    wget -q -O "$GEO_DB_FILE" "$GEO_DB_URL"
    print_success "GeoLite2 database installed."
else
    print_info "GeoLite2 database already exists."
fi

# --- Run Application ---
print_success "Installation complete. Starting the application..."

APP_DIR=$(dirname "$(realpath "$0")")
VENV_PYTHON="$APP_DIR/$VENV_DIR/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    print_error "Virtual environment's Python executable not found at $VENV_PYTHON"
    exit 1
fi

# Execute the app using the venv's python directly
"$VENV_PYTHON" "$APP_DIR/app.py"