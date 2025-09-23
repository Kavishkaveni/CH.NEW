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

    // ===== Windows (launch plink in the interactive RDP session) =====
    #[cfg(windows)]
    async fn connect_with_plink(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<()> {
        use std::ffi::OsStr;
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;

        use windows::core::PWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TokenPrimary};
        use windows::Win32::System::RemoteDesktop::{
            WTSGetActiveConsoleSessionId, WTSQueryUserToken, WTSEnumerateSessionsW,
            WTS_SESSION_INFOW, WTS_CONNECTSTATE_CLASS,
        };
        use windows::Win32::System::Threading::{
            CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW, CREATE_NEW_CONSOLE,
            STARTF_USESHOWWINDOW,
        };
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

        // Build plink command (interactive login, no remote command)
        let plink_path = self.config.plink_path.as_ref()
            .ok_or_else(|| QcmError::Ssh("PuTTY plink path not configured".to_string()))?;

        let args = format!(
            "\"{}\" -ssh {}@{} -P {} -pw {} -no-antispoof",
            plink_path, username, host, port, password
        );
        let cmd: Vec<u16> = OsStr::new(&args).encode_wide().chain(once(0)).collect();

        // Desktop name MUST be "winsta0\\default" so the window appears in the interactive RDP session
        let desktop_w: Vec<u16> = OsStr::new("winsta0\\default").encode_wide().chain(once(0)).collect();

        unsafe {
            // 1) Find an active session (not just console 0)
            let mut session_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
            let mut count: u32 = 0;
            let mut active_session_id = WTSGetActiveConsoleSessionId();

            if WTSEnumerateSessionsW(None, 0, 1, &mut session_info, &mut count).is_ok() {
                let slice = std::slice::from_raw_parts(session_info, count as usize);
                for s in slice {
                    if s.State == WTS_CONNECTSTATE_CLASS(0) {
                        active_session_id = s.SessionId;
                        break;
                    }
                }
            }

            // 2) Get user token for that active session
            let mut user_token: HANDLE = HANDLE(0);
            if WTSQueryUserToken(active_session_id, &mut user_token).is_err() {
                return Err(QcmError::Ssh("Failed to query user token".to_string()));
            }

            // 3) Duplicate to a primary token
            let mut primary_token: HANDLE = HANDLE(0);
            if DuplicateTokenEx(
                user_token,
                Default::default(),
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut primary_token,
            ).is_err() {
                CloseHandle(user_token);
                return Err(QcmError::Ssh("Failed to duplicate token".to_string()));
            }

            // 4) Startup info pointing at interactive desktop
            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_SHOW.0 as u16;
            si.lpDesktop = PWSTR(desktop_w.as_ptr() as *mut _);

            let mut pi = PROCESS_INFORMATION::default();

            // 5) Launch plink in that user session with a NEW console window
            let res = CreateProcessAsUserW(
                primary_token,
                None,
                PWSTR(cmd.as_ptr() as *mut _),
                None,
                None,
                false,
                CREATE_NEW_CONSOLE,
                None,
                None,
                &si,
                &mut pi,
            );

            // Clean up handles
            CloseHandle(user_token);
            CloseHandle(primary_token);
            if !pi.hThread.is_invalid() {
                CloseHandle(pi.hThread);
            }
            if !pi.hProcess.is_invalid() {
                CloseHandle(pi.hProcess);
            }

            if res.is_err() {
                return Err(QcmError::Ssh("Failed to launch plink in user session".to_string()));
            }
        }

        self.logger.info(
            "SSH",
            &format!("{}:{}", host, port),
            "LAUNCHED",
            "Plink started in interactive RDP session",
        )?;
        Ok(())
    }

    // ===== Linux/macOS path (sshpass) =====
    async fn connect_with_ssh(&self, host: &str, port: u16, username: &str, password: &str) -> Result<()> {
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
