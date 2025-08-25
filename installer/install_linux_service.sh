#!/bin/bash
# Linux Service Installation Script for Employee Monitoring Client
# This script installs the monitoring client as a systemd service.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Service configuration
SERVICE_NAME="EmployeeMonitoringClient"
SERVICE_DISPLAY_NAME="Employee Monitoring Client"
SERVICE_DESCRIPTION="Monitors employee computer activity for security purposes"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to check if systemd is available
check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        print_error "systemd is not available on this system"
        exit 1
    fi
    
    if ! systemctl is-system-running &> /dev/null; then
        print_error "systemd is not running on this system"
        exit 1
    fi
    
    print_info "systemd is available and running"
}

# Function to check if Python is available
check_python() {
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not available on this system"
        print_info "Please install Python 3 first"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version 2>&1)
    print_info "Found $PYTHON_VERSION"
}

# Function to get script directory
get_script_dir() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    print_info "Script directory: $SCRIPT_DIR"
}

# Function to check if service already exists
check_service_exists() {
    if systemctl list-unit-files --type=service | grep -q "^$SERVICE_NAME.service"; then
        return 0
    else
        return 1
    fi
}

# Function to create systemd service file
create_service_file() {
    local service_file="/etc/systemd/system/$SERVICE_NAME.service"
    
    print_info "Creating systemd service file: $service_file"
    
    cat > "$service_file" << EOF
[Unit]
Description=$SERVICE_DESCRIPTION
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/python3 $SCRIPT_DIR/apps/client/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME
Environment=SERVICE_NAME=$SERVICE_NAME
Environment=PYTHONUNBUFFERED=1

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SCRIPT_DIR
ReadWritePaths=/var/log

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    print_success "Service file created successfully"
}

# Function to install service
install_service() {
    print_info "Installing service: $SERVICE_NAME"
    
    # Create service file
    create_service_file
    
    # Reload systemd
    print_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Enable service
    print_info "Enabling service..."
    systemctl enable "$SERVICE_NAME.service"
    
    # Start service
    print_info "Starting service..."
    systemctl start "$SERVICE_NAME.service"
    
    # Check service status
    if systemctl is-active --quiet "$SERVICE_NAME.service"; then
        print_success "Service started successfully"
    else
        print_error "Service failed to start"
        systemctl status "$SERVICE_NAME.service"
        return 1
    fi
    
    return 0
}

# Function to uninstall service
uninstall_service() {
    print_info "Uninstalling service: $SERVICE_NAME"
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME.service"; then
        print_info "Stopping service..."
        systemctl stop "$SERVICE_NAME.service"
    fi
    
    # Disable service
    if systemctl is-enabled --quiet "$SERVICE_NAME.service"; then
        print_info "Disabling service..."
        systemctl disable "$SERVICE_NAME.service"
    fi
    
    # Remove service file
    local service_file="/etc/systemd/system/$SERVICE_NAME.service"
    if [[ -f "$service_file" ]]; then
        print_info "Removing service file..."
        rm -f "$service_file"
    fi
    
    # Reload systemd
    print_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Reset failed units
    systemctl reset-failed
    
    print_success "Service uninstalled successfully"
}

# Function to show service status
show_service_status() {
    print_info "Service status for: $SERVICE_NAME"
    
    if check_service_exists; then
        echo
        systemctl status "$SERVICE_NAME.service" --no-pager -l
    else
        print_warning "Service does not exist"
    fi
}

# Function to show service logs
show_service_logs() {
    print_info "Service logs for: $SERVICE_NAME"
    
    if check_service_exists; then
        echo
        journalctl -u "$SERVICE_NAME.service" --no-pager -n 50
    else
        print_warning "Service does not exist"
    fi
}

# Function to restart service
restart_service() {
    print_info "Restarting service: $SERVICE_NAME"
    
    if check_service_exists; then
        systemctl restart "$SERVICE_NAME.service"
        
        if systemctl is-active --quiet "$SERVICE_NAME.service"; then
            print_success "Service restarted successfully"
        else
            print_error "Service failed to restart"
            systemctl status "$SERVICE_NAME.service"
        fi
    else
        print_warning "Service does not exist"
    fi
}

# Function to check dependencies
check_dependencies() {
    print_info "Checking system dependencies..."
    
    # Check Python packages
    local required_packages=("PIL" "psutil" "pyautogui" "numpy")
    
    for package in "${required_packages[@]}"; do
        if python3 -c "import $package" 2>/dev/null; then
            print_success "✓ $package available"
        else
            print_warning "✗ $package not available"
            print_info "Please install required packages: pip3 install -r requirements.txt"
        fi
    done
}

# Function to create log directory
create_log_directory() {
    local log_dir="/var/log/$SERVICE_NAME"
    
    if [[ ! -d "$log_dir" ]]; then
        print_info "Creating log directory: $log_dir"
        mkdir -p "$log_dir"
        chmod 755 "$log_dir"
    fi
}

# Function to set permissions
set_permissions() {
    print_info "Setting file permissions..."
    
    # Make client.py executable
    chmod +x "$SCRIPT_DIR/apps/client/main.py"
    
    # Set ownership to root
    chown root:root "$SCRIPT_DIR/apps/client/main.py"
    
    print_success "Permissions set successfully"
}

# Main installation function
main_install() {
    print_info "Starting installation process..."
    
    # Check prerequisites
    check_root
    check_systemd
    check_python
    check_dependencies
    
    # Get script directory
    get_script_dir
    
    # Create log directory
    create_log_directory
    
    # Set permissions
    set_permissions
    
    # Check if service already exists
    if check_service_exists; then
        print_warning "Service '$SERVICE_NAME' already exists"
        read -p "Do you want to reinstall it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            uninstall_service
        else
            print_info "Installation cancelled"
            return 1
        fi
    fi
    
    # Install service
    if install_service; then
        print_success "Installation completed successfully!"
        print_info "Service name: $SERVICE_NAME"
        print_info "To check status: systemctl status $SERVICE_NAME"
        print_info "To view logs: journalctl -u $SERVICE_NAME -f"
        print_info "To restart: systemctl restart $SERVICE_NAME"
        print_info "To stop: systemctl stop $SERVICE_NAME"
    else
        print_error "Installation failed!"
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTION]"
    echo
    echo "Options:"
    echo "  install     Install the monitoring client service"
    echo "  uninstall   Uninstall the monitoring client service"
    echo "  status      Show service status"
    echo "  logs        Show service logs"
    echo "  restart     Restart the service"
    echo "  check       Check system dependencies"
    echo "  help        Show this help message"
    echo
    echo "Examples:"
    echo "  $0 install      # Install the service"
    echo "  $0 status       # Check service status"
    echo "  $0 logs         # View service logs"
}

# Main script logic
case "${1:-install}" in
    install)
        main_install
        ;;
    uninstall)
        check_root
        uninstall_service
        ;;
    status)
        show_service_status
        ;;
    logs)
        show_service_logs
        ;;
    restart)
        check_root
        restart_service
        ;;
    check)
        check_dependencies
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown option: $1"
        show_usage
        exit 1
        ;;
esac
