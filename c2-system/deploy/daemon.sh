#!/bin/bash
# Simple daemon launcher for C2 server/agent
# Works without systemd

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/../target/release"
PID_DIR="/var/run/c2"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat << EOF
Usage: $0 {start|stop|restart|status} {server|agent} [OPTIONS]

Commands:
    start   Start the service
    stop    Stop the service
    restart Restart the service
    status  Show service status

Services:
    server  C2 Server
    agent   C2 Agent

Options for server:
    --bind ADDRESS      Bind address (default: 0.0.0.0:8080)
    --key KEY           Master key

Options for agent:
    --server URL        C2 server URL (default: http://localhost:8080)
    --sleep MS          Sleep interval ms (default: 60000)

Examples:
    $0 start server --bind 0.0.0.0:8080
    $0 start agent --server http://c2.example.com:8080
    $0 status server
    $0 stop agent
EOF
}

ensure_pid_dir() {
    mkdir -p "$PID_DIR"
}

get_pid() {
    local name=$1
    cat "$PID_DIR/${name}.pid" 2>/dev/null || echo ""
}

is_running() {
    local name=$1
    local pid=$(get_pid "$name")
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

start_server() {
    local bind="0.0.0.0:8080"
    local key=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --bind) bind="$2"; shift 2 ;;
            --key) key="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if is_running "server"; then
        log_info "Server already running (PID: $(get_pid server))"
        return
    fi

    ensure_pid_dir

    local args="--bind $bind"
    [ -n "$key" ] && args="$args --master-key $key"

    log_info "Starting C2 Server on $bind..."
    nohup "$BIN_DIR/c2-server" $args > /var/log/c2-server.log 2>&1 &
    echo $! > "$PID_DIR/server.pid"

    sleep 1
    if is_running "server"; then
        log_info "Server started (PID: $(get_pid server))"
    else
        log_error "Server failed to start"
        return 1
    fi
}

stop_server() {
    local pid=$(get_pid "server")
    if [ -n "$pid" ]; then
        log_info "Stopping C2 Server (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        rm -f "$PID_DIR/server.pid"
        log_info "Server stopped"
    else
        log_info "Server not running"
    fi
}

start_agent() {
    local server="http://localhost:8080"
    local sleep_ms="60000"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --server) server="$2"; shift 2 ;;
            --sleep) sleep_ms="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if is_running "agent"; then
        log_info "Agent already running (PID: $(get_pid agent))"
        return
    fi

    ensure_pid_dir

    log_info "Starting C2 Agent (server: $server)..."
    nohup "$BIN_DIR/c2-agent" --server "$server" --sleep "$sleep_ms" > /var/log/c2-agent.log 2>&1 &
    echo $! > "$PID_DIR/agent.pid"

    sleep 1
    if is_running "agent"; then
        log_info "Agent started (PID: $(get_pid agent))"
    else
        log_error "Agent failed to start"
        return 1
    fi
}

stop_agent() {
    local pid=$(get_pid "agent")
    if [ -n "$pid" ]; then
        log_info "Stopping C2 Agent (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        rm -f "$PID_DIR/agent.pid"
        log_info "Agent stopped"
    else
        log_info "Agent not running"
    fi
}

show_status() {
    local name=$1
    if is_running "$name"; then
        log_info "$1 is running (PID: $(get_pid "$name"))"
    else
        log_info "$1 is not running"
    fi
}

# Main
if [ $# -lt 2 ]; then
    usage
    exit 1
fi

COMMAND=$1
SERVICE=$2
shift 2

case $COMMAND in
    start)
        case $SERVICE in
            server) start_server "$@" ;;
            agent) start_agent "$@" ;;
            *) log_error "Unknown service: $SERVICE"; exit 1 ;;
        esac
        ;;
    stop)
        case $SERVICE in
            server) stop_server ;;
            agent) stop_agent ;;
            *) log_error "Unknown service: $SERVICE"; exit 1 ;;
        esac
        ;;
    restart)
        case $SERVICE in
            server) stop_server; sleep 1; start_server "$@" ;;
            agent) stop_agent; sleep 1; start_agent "$@" ;;
            *) log_error "Unknown service: $SERVICE"; exit 1 ;;
        esac
        ;;
    status)
        show_status "$SERVICE"
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac
