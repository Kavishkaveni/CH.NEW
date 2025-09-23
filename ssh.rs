use crate::config::Config;
use crate::logger::Logger;
use crate::{QcmError, Result};
use std::process::{Command, Stdio};

pub struct SshClient {
    config: Config,
    logger: Logger,
}

impl SshClient {
    pub fn new(config: Config, logger: Logger) -> Self {
        Self { config, logger }
    }

    pub async fn connect(&self, host: &str, port: u16, username: &str, password: &str) -> Result<()> {
        let target = format!("{}:{}", host, port);
        
        self.logger.info("SSH", &target, "STARTING", "Initiating SSH connection")?;

        let result = if cfg!(windows) {
            self.connect_with_plink(host, port, username, password).await
        } else {
            self.connect_with_ssh(host, port, username, password).await
        };

        match &result {
            Ok(_) => {
                self.logger.info("SSH", &target, "SUCCESS", "SSH connection established successfully")?;
            }
            Err(e) => {
                self.logger.error("SSH", &target, "FAILED", &format!("SSH connection failed: {}", e))?;
            }
        }

        result
    }

    async fn connect_with_plink(&self, host: &str, port: u16, username: &str, password: &str) -> Result<()> {
        let plink_path = self.config.plink_path.as_ref()
            .ok_or_else(|| QcmError::Ssh("PuTTY plink path not configured".to_string()))?;

        let mut cmd = Command::new(plink_path);
        cmd.args([
            "-ssh",
            &format!("{}@{}", username, host),
            "-P", &port.to_string(),
            "-pw", password,
            "-batch", // Don't prompt for interactive input
            "echo 'SSH connection successful'; exit", // Simple command to test connection
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let output = cmd.output()
            .map_err(|e| QcmError::Ssh(format!("Failed to execute plink: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.logger.debug("SSH", &format!("{}:{}", host, port), "OUTPUT", &stdout)?;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(QcmError::Ssh(format!("plink failed: {}", stderr)))
        }
    }

    async fn connect_with_ssh(&self, host: &str, port: u16, username: &str, password: &str) -> Result<()> {
        // For Unix systems, we'll use sshpass with ssh
        // Note: This requires sshpass to be installed
        let mut cmd = Command::new("sshpass");
        cmd.args([
            "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", &port.to_string(),
            &format!("{}@{}", username, host),
            "echo 'SSH connection successful'; exit",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let output = cmd.output()
            .map_err(|e| QcmError::Ssh(format!("Failed to execute ssh: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.logger.debug("SSH", &format!("{}:{}", host, port), "OUTPUT", &stdout)?;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(QcmError::Ssh(format!("ssh failed: {}", stderr)))
        }
    }
}
