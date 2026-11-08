//! Protocol implementations for C2 communication channels.
//!
//! Each protocol implements the `C2Channel` trait and can be used
//! interchangeably with automatic failover.

pub mod http;
pub mod dns;
pub mod p2p;
pub mod dead_drop;

pub use http::*;
pub use dns::*;
pub use p2p::*;
pub use dead_drop::*;

use crate::common::{MessageEnvelope, ChannelType};
use thiserror::Error;

/// Run a future to completion from synchronous code, even inside a tokio runtime.
// shortcut: block_in_place needs a multi-thread runtime; switch to async trait methods if a current-thread runtime is used.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        Err(_) => tokio::runtime::Runtime::new()
            .expect("create runtime")
            .block_on(fut),
    }
}

/// Blocking read for the sync channel trait methods (safe inside a runtime).
pub(crate) fn read_lock<T>(lock: &tokio::sync::RwLock<T>) -> tokio::sync::RwLockReadGuard<'_, T> {
    block_on(lock.read())
}

/// Blocking write for the sync channel trait methods (safe inside a runtime).
pub(crate) fn write_lock<T>(lock: &tokio::sync::RwLock<T>) -> tokio::sync::RwLockWriteGuard<'_, T> {
    block_on(lock.write())
}

/// Errors from channel operations
#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
    #[error("Authentication failed: {0}")]
    Authentication(String),
    #[error("Channel unavailable")]
    Unavailable,
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type ChannelResult<T> = Result<T, ChannelError>;

/// Trait for all C2 communication channels
pub trait C2Channel: Send + Sync {
    /// Get the channel type
    fn channel_type(&self) -> ChannelType;

    /// Get channel name for logging
    fn name(&self) -> &str;

    /// Check if channel is healthy
    fn health_check(&self) -> ChannelResult<bool>;

    /// Send an encrypted message envelope
    fn send(&self, envelope: &MessageEnvelope) -> ChannelResult<()>;

    /// Receive a message envelope with timeout
    fn receive(&self, timeout_ms: u64) -> ChannelResult<Option<MessageEnvelope>>;

    /// Get channel latency estimate
    fn latency_ms(&self) -> u64;

    /// Get channel reliability score (0.0 to 1.0)
    fn reliability(&self) -> f32;

    /// Close the channel
    fn close(&self);
}

/// Channel health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Channel health metrics
#[derive(Debug, Clone, Default)]
pub struct ChannelHealth {
    pub latency_ms: u64,
    pub success_rate: f32,
    pub packet_loss: f32,
    pub tls_errors: u32,
    pub dns_failures: u32,
    pub consecutive_failures: u32,
    pub total_requests: u32,
    pub successful_requests: u32,
}

impl ChannelHealth {
    /// Calculate overall health score (0.0 to 1.0)
    pub fn score(&self) -> f32 {
        if self.total_requests == 0 {
            return 0.5; // Unknown, assume neutral
        }

        let latency_score = 1.0 - (self.latency_ms as f32 / 5000.0).min(1.0);
        let success_score = self.success_rate;
        let reliability_score = 1.0 - (self.consecutive_failures as f32 / 10.0).min(1.0);

        (latency_score * 0.3) + (success_score * 0.5) + (reliability_score * 0.2)
    }

    /// Get health status based on score
    pub fn status(&self) -> HealthStatus {
        let score = self.score();
        match score {
            s if s >= 0.8 => HealthStatus::Healthy,
            s if s >= 0.5 => HealthStatus::Degraded,
            _ => HealthStatus::Unhealthy,
        }
    }

    /// Record a successful request
    pub fn record_success(&mut self, latency_ms: u64) {
        self.total_requests += 1;
        self.successful_requests += 1;
        self.consecutive_failures = 0;
        self.latency_ms = latency_ms;
        self.success_rate = self.successful_requests as f32 / self.total_requests as f32;
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        self.total_requests += 1;
        self.consecutive_failures += 1;
        self.success_rate = self.successful_requests as f32 / self.total_requests as f32;
    }
}
