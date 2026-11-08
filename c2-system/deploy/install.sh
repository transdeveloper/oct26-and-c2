#!/bin/bash
# C2 System Installation Script
# Installs C2 server and agent as systemd services

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/c2"
DATA_DIR="/opt/c2/data"
LOG_DIR="/var/log/c2"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Install C2 system as systemd services

Options:
    -s, --server       Install server only
    -a, --agent        Install agent only
    -b, --both         Install both (default)
    -u, --uninstall    Uninstall C2 system
    -h, --help         Show this help

Environment variables:
    C2_SERVER_BIND     Server bind address (default: 0.0.0.0:8080)
    C2_MASTER_KEY      Master encryption key
    C2_AGENT_SERVER    C2 server URL for agent
    C2_AGENT_SLEEP     Agent sleep interval ms (default: 60000)

Examples:
    $0 --server                    # Install server only
    C2_MASTER_KEY="secret" $0      # Install with custom key
    $0 --uninstall                  # Uninstall everything
EOF
}

install_server() {
    log_info "Installing C2 Server..."

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"

    # Copy binaries
    cp "$SCRIPT_DIR/../target/release/c2-server" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/c2-server.service" /etc/systemd/system/

    # Create config
    cat > "$INSTALL_DIR/config.toml" << EOF
[server]
bind_address = "${C2_SERVER_BIND:-0.0.0.0:8080}"
master_key = "${C2_MASTER_KEY:-$(openssl rand -hex 16)}"
log_level = "info"
database_url = "sqlite:///$DATA_DIR/c2.db"

[agent]
name = "c2-server"
sleep_interval = 60000
jitter = 0.3
EOF

    # Set permissions
    chown -R root:root "$INSTALL_DIR"
    chmod 750 "$INSTALL_DIR"

    # Create user if not exists
    if ! id -u c2server > /dev/null 2>&1; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" c2server
    fi

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable c2-server.service
    log_info "C2 Server installed successfully"
}

install_agent() {
    log_info "Installing C2 Agent..."

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"

    # Copy binaries
    cp "$SCRIPT_DIR/../target/release/c2-agent" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/c2-agent.service" /etc/systemd/system/

    # Update service with server URL
    sed -i "s|http://c2server.example.com:8080|${C2_AGENT_SERVER:-http://localhost:8080}|g" /etc/systemd/system/c2-agent.service
    sed -i "s|--sleep 60000|--sleep ${C2_AGENT_SLEEP:-60000}|g" /etc/systemd/system/c2-agent.service

    # Set permissions
    chown -R root:root "$INSTALL_DIR"

    # Create user if not exists
    if ! id -u c2agent > /dev/null 2>&1; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" c2agent
    fi

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable c2-agent.service
    log_info "C2 Agent installed successfully"
}

uninstall() {
    log_info "Uninstalling C2 system..."

    # Stop services
    systemctl stop c2-server.service 2>/dev/null || true
    systemctl stop c2-agent.service 2>/dev/null || true

    # Disable services
    systemctl disable c2-server.service 2>/dev/null || true
    systemctl disable c2-agent.service 2>/dev/null || true

    # Remove service files
    rm -f /etc/systemd/system/c2-server.service
    rm -f /etc/systemd/system/c2-agent.service

    # Reload systemd
    systemctl daemon-reload

    # Remove directories
    rm -rf "$INSTALL_DIR"
    rm -rf "$LOG_DIR"

    # Remove users
    userdel c2server 2>/dev/null || true
    userdel c2agent 2>/dev/null || true

    log_info "C2 system uninstalled successfully"
}

start_services() {
    log_info "Starting C2 services..."
    systemctl start c2-server.service 2>/dev/null || log_warn "c2-server not installed"
    systemctl start c2-agent.service 2>/dev/null || log_warn "c2-agent not installed"
}

stop_services() {
    log_info "Stopping C2 services..."
    systemctl stop c2-server.service 2>/dev/null || log_warn "c2-server not running"
    systemctl stop c2-agent.service 2>/dev/null || log_warn "c2-agent not running"
}

show_status() {
    log_info "C2 System Status:"
    echo ""
    systemctl is-active c2-server.service 2>/dev/null && echo "Server: Running" || echo "Server: Not running"
    systemctl is-active c2-agent.service 2>/dev/null && echo "Agent: Running" || echo "Agent: Not running"
}

# Parse arguments
INSTALL_SERVER=true
INSTALL_AGENT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--server)
            INSTALL_SERVER=true
            INSTALL_AGENT=false
            shift
            ;;
        -a|--agent)
            INSTALL_SERVER=false
            INSTALL_AGENT=true
            shift
            ;;
        -b|--both)
            INSTALL_SERVER=true
            INSTALL_AGENT=true
            shift
            ;;
        -u|--uninstall)
            uninstall
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Install
if [ "$INSTALL_SERVER" = true ]; then
    install_server
fi

if [ "$INSTALL_AGENT" = true ]; then
    install_agent
fi

# Start services
start_services

# Show status
show_status

log_info "Installation complete!"
