#!/bin/bash

# Autonomous Packet Sniffer Installer (Linux)
# This script automates the setup for the packet sniffer application.

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
print_info "Starting autonomous installation for Linux..."

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
  print_warning "This script may require root privileges for installing system packages and running the sniffer."
  print_warning "If it fails, please run with sudo: sudo ./install.sh"
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
print_info "Activating virtual environment and installing dependencies from requirements.txt..."
source "$VENV_DIR/bin/activate"
pip3 install --upgrade pip
pip3 install -r requirements.txt
deactivate
print_success "Python dependencies installed."

# 6. Download GeoLite2 City database
if [ ! -f "$GEO_DB_FILE" ]; then
    print_info "Downloading GeoLite2 City database from $GEO_DB_URL..."
    wget -q -O "$GEO_DB_FILE" "$GEO_DB_URL"
    print_success "GeoLite2 database installed."
else
    print_info "GeoLite2 database already exists."
fi

# 7. Create a run script
print_info "Creating 'run.sh' script..."
cat > run.sh << EOL
#!/bin/bash
set -e
# This script must be run with sudo to capture packets.
if [ "\$EUID" -ne 0 ]; then
  echo "Please run this script with sudo: sudo ./run.sh"
  exit 1
fi
echo "Activating virtual environment and starting the application..."
source "$(pwd)/$VENV_DIR/bin/activate"
$PYTHON_CMD app.py
EOL

chmod +x run.sh
print_success "'run.sh' created. Use 'sudo ./run.sh' to start the application."

# --- Final Instructions ---
print_success "Installation complete!"
echo
echo "Next steps:"
echo "1. To start the application, run: sudo ./run.sh"
echo "2. To deploy it as a service, run: sudo ./deploy.sh"
echo