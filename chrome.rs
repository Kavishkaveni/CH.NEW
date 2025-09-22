use crate::config::Config;
use crate::error::QcmError;
use crate::logger::Logger;
use headless_chrome::{Browser, LaunchOptions};
use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio;

#[cfg(target_os = "windows")]
use crate::windows_session::{get_active_session_id, WindowsSessionLauncher};

pub struct ChromeClient {
    config: Config,
    logger: Logger,
    port_counter: Arc<AtomicU16>,
}

impl ChromeClient {
    pub fn new(config: Config, logger: Logger) -> Self {
        Self {
            config,
            logger,
            port_counter: Arc::new(AtomicU16::new(9222)),
        }
    }

    // ---------- helpers ----------

    fn find_available_port(&self) -> Result<u16, QcmError> {
        let start_port = self.port_counter.fetch_add(1, Ordering::SeqCst);
        for offset in 0..100 {
            let port = start_port.wrapping_add(offset);
            if port < 9222 { continue; }
            if port > 65535 { break; }
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
                drop(listener);
                return Ok(port);
            }
        }
        Err(QcmError::Chrome("No available ports found for Chrome debugging".to_string()))
    }

    fn get_chrome_path(&self) -> Result<std::path::PathBuf, QcmError> {
        #[cfg(target_os = "windows")]
        {
            let paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                r"C:\Users\%USERNAME%\AppData\Local\Google\Chrome\Application\chrome.exe",
            ];
            for p in &paths {
                let pb = std::path::PathBuf::from(p);
                if pb.exists() { return Ok(pb); }
            }
            return Err(QcmError::Chrome("Chrome executable not found".to_string()));
        }

        #[cfg(not(target_os = "windows"))]
        {
            let paths = ["/usr/bin/google-chrome", "/usr/bin/chromium-browser", "/usr/bin/chromium"];
            for p in &paths {
                let pb = std::path::PathBuf::from(p);
                if pb.exists() { return Ok(pb); }
            }
            if let Ok(output) = Command::new("which").arg("google-chrome").output() {
                if output.status.success() {
                    let path_str = String::from_utf8_lossy(&output.stdout);
                    return Ok(std::path::PathBuf::from(path_str.trim()));
                }
            }
            Err(QcmError::Chrome("Chrome executable not found".to_string()))
        }
    }

    async fn cleanup_old_profiles(&self) -> Result<(), QcmError> {
        let sessions_dir = Path::new("C:\\PAM\\chrome_sessions");
        if !sessions_dir.exists() { return Ok(()); }

        self.logger.debug("CLEANUP","chrome_sessions","START","Starting Chrome profile cleanup")?;
        let mut cleaned = 0usize;
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(3600);
        if let Ok(entries) = fs::read_dir(sessions_dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if let Ok(md) = e.metadata() {
                        if let Ok(modt) = md.modified() {
                            if modt < cutoff {
                                if fs::remove_dir_all(&p).is_ok() {
                                    cleaned += 1;
                                    self.logger.debug("CLEANUP","chrome_sessions","REMOVED",
                                        &format!("Removed old profile: {:?}", p.file_name()))?;
                                }
                            }
                        }
                    }
                }
            }
        }
        self.logger.info("CLEANUP","chrome_sessions","COMPLETED",&format!("Cleaned up {} old Chrome profiles", cleaned))?;
        Ok(())
    }

    fn ensure_profile_directory(&self, _uuid: Option<&str>, session_id: Option<u32>) -> Result<std::path::PathBuf, QcmError> {
        let user_data_dir = if let Some(sid) = session_id {
            format!("C:\\PAM\\chrome_sessions\\session_{}", sid)
        } else {
            "C:\\PAM\\chrome_sessions\\default".to_string()
        };
        let sessions_root = Path::new("C:\\PAM\\chrome_sessions");
        if !sessions_root.exists() {
            fs::create_dir_all(sessions_root)
                .map_err(|e| QcmError::Chrome(format!("Failed to create sessions directory: {}", e)))?;
        }
        let profile_dir = Path::new(&user_data_dir);
        if !profile_dir.exists() {
            fs::create_dir_all(profile_dir)
                .map_err(|e| QcmError::Chrome(format!("Failed to create profile directory: {}", e)))?;
        }
        Ok(profile_dir.to_path_buf())
    }

    // ---------- launchers ----------

    async fn launch_chrome_standard(&self, profile_dir: &Path, port: u16, url: &str) -> Result<Browser, QcmError> {
        use std::ffi::OsStr;
        let user_data_arg = format!("--user-data-dir={}", profile_dir.display());
        let url_arg = format!("--app={}", url);

        let launch_options = LaunchOptions::default_builder()
            .path(Some(self.get_chrome_path()?))
            .port(Some(port))
            .headless(false)
            .args(vec![
                OsStr::new(&user_data_arg),
                OsStr::new(&url_arg),
                OsStr::new("--disable-web-security"),
                OsStr::new("--disable-features=VizDisplayCompositor"),
                OsStr::new("--start-maximized"),
                OsStr::new("--disable-infobars"),
                OsStr::new("--disable-dev-shm-usage"),
                OsStr::new("--disable-extensions"),
                OsStr::new("--disable-plugins"),
                OsStr::new("--disable-default-apps"),
                OsStr::new("--disable-popup-blocking"),
                OsStr::new("--disable-translate"),
                OsStr::new("--no-first-run"),
                OsStr::new("--no-default-browser-check"),
            ])
            .build()
            .expect("Failed to build Chrome launch options");

        Browser::new(launch_options)
            .map_err(|e| QcmError::Chrome(format!("Failed to launch Chrome: {}", e)))
    }

    #[cfg(target_os = "windows")]
    async fn launch_chrome_in_session(&self, session_id: u32, profile_dir: &Path, port: u16, url: &str) -> Result<Browser, QcmError> {
        let chrome_path = self.get_chrome_path()?;
        let args = vec![
            format!("--remote-debugging-port={}", port),
            format!("--user-data-dir={}", profile_dir.display()),
            format!("--app={}", url),
            "--disable-web-security".to_string(),
            "--disable-features=VizDisplayCompositor".to_string(),
            "--start-maximized".to_string(),
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
        ];

        let launcher = WindowsSessionLauncher::new();
        launcher
            .launch_in_session(session_id, &chrome_path.to_string_lossy(), &args)
            .map_err(|e| QcmError::Chrome(format!("Failed to launch Chrome in session {}: {}", session_id, e)))?;

        // give Chrome a moment to come up
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // connect to the debugging port
        let ws_url = format!("ws://127.0.0.1:{}", port);
        let mut retries = 0;
        const MAX: u32 = 10;
        loop {
            match Browser::connect(ws_url.clone()) {
                Ok(b) => return Ok(b),
                Err(e) if retries < MAX => {
                    retries += 1;
                    log::debug!("Retry {} connecting to Chrome on port {}: {}", retries, port, e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    return Err(QcmError::Chrome(format!("Failed to connect to Chrome after {} retries: {}", MAX, e)));
                }
            }
        }
    }

    // ---------- main entry ----------

    pub async fn auto_login(
        &self,
        url: &str,
        username: &str,
        password: &str,
        session_id: Option<u32>,
        session_user: Option<&str>,
        _uuid: Option<&str>,
    ) -> Result<(), QcmError> {
        // resolve target session (don’t hardcode)
        let final_sid = match session_id {
            Some(s) => s,
            None => {
                #[cfg(target_os = "windows")]
                {
                    get_active_session_id().unwrap_or(0)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    0
                }
            }
        };

        self.logger.info("WEB", url, "STARTING", &format!("Chrome auto-login (session {})", final_sid))?;

        // tidy profiles & pick a debug port
        self.cleanup_old_profiles().await?;
        let debug_port = self.find_available_port()?;
        let profile_dir = self.ensure_profile_directory(session_user, Some(final_sid))?;

        // launch chrome (session-aware on Windows)
        #[cfg(target_os = "windows")]
        let browser = self.launch_chrome_in_session(final_sid, &profile_dir, debug_port, url).await?;
        #[cfg(not(target_os = "windows"))]
        let browser = self.launch_chrome_standard(&profile_dir, debug_port, url).await?;

        // get first tab
        let tab = {
            let tabs = browser.get_tabs();
            let tabs_lock = tabs.lock().unwrap();
            if let Some(first) = tabs_lock.get(0) {
                first.clone()
            } else {
                return Err(QcmError::Chrome("No tab found in Chrome instance".to_string()));
            }
        };

        // let the page load
        tokio::time::sleep(Duration::from_secs(3)).await;
        let _ = tab.wait_until_navigated();
        tokio::time::sleep(Duration::from_secs(2)).await;

        // ---------- inject credentials ----------
        self.logger.debug("WEB", url, "INJECTING", "Trying username selectors")?;

        let username_selectors = [
            "input[name='user']",
            "input[name='username']",
            "input[id='username']",
            "input[type='text'][name*='user']",
            "input[type='email']",
            "#username", ".username", "#login", ".login",
            "input[placeholder*='user' i]", "input[placeholder*='email' i]",
        ];
        let mut username_ok = false;
        for sel in username_selectors.iter() {
            if let Ok(el) = tab.find_element(sel) {
                if el.type_into(username).is_ok() {
                    self.logger.debug("WEB", url, "USERNAME", &format!("Filled via {}", sel))?;
                    username_ok = true;
                    break;
                }
            }
        }
        if !username_ok {
            return Err(QcmError::Chrome("Could not find username field".to_string()));
        }

        self.logger.debug("WEB", url, "INJECTING", "Trying password selectors")?;
        let password_selectors = [
            "input[name='passwd']",
            "input[name='password']",
            "input[id='password']",
            "input[type='password']",
            "#password", ".password",
            "input[placeholder*='password' i]",
        ];
        let mut password_ok = false;
        for sel in password_selectors.iter() {
            if let Ok(el) = tab.find_element(sel) {
                if el.type_into(password).is_ok() {
                    self.logger.debug("WEB", url, "PASSWORD", &format!("Filled via {}", sel))?;
                    password_ok = true;
                    break;
                }
            }
        }
        if !password_ok {
            return Err(QcmError::Chrome("Could not find password field".to_string()));
        }

        // click login
        let login_selectors = [
            "input[type='submit']",
            "button[type='submit']",
            "input[value*='login' i]",
            "input[value*='sign in' i]",
            "#login", ".login", "#signin", ".signin",
            "input[value*='Log In']",
            "button[value*='Log In']",
            "input[name='pda.login']",
        ];
        let mut clicked = false;
        for sel in login_selectors.iter() {
            if let Ok(el) = tab.find_element(sel) {
                if el.click().is_ok() {
                    self.logger.debug("WEB", url, "SUBMIT", &format!("Clicked via {}", sel))?;
                    clicked = true;
                    break;
                }
            }
        }
        if !clicked {
            // fallback: press Enter on password field or submit form via JS
            if tab.find_element("input[type='password']").is_ok() {
                let _ = tab.evaluate(
                    "document.querySelector('input[type=\"password\"]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter'}))",
                    false
                );
                let _ = tab.evaluate(
                    "var f=document.querySelector('input[type=\"password\"]').form; if(f) f.submit();",
                    false
                );
                self.logger.debug("WEB", url, "SUBMIT", "Submitted via JS fallback")?;
            }
        }

        // small wait for redirect
        tokio::time::sleep(Duration::from_secs(5)).await;
        // simple success heuristic: password field gone
        if tab.find_element("input[type='password']").is_ok() {
            self.logger.debug("WEB", url, "LOGIN_STATUS", "Still on login page (may have failed)")?;
        } else {
            self.logger.debug("WEB", url, "LOGIN_STATUS", "Likely logged in (redirected)")?;
        }

        // keep the window alive for a short time so the user can see it
        let mut remaining = 120; // 2 minutes
        while remaining > 0 {
            tokio::time::sleep(Duration::from_secs(15)).await;
            remaining -= 15;
            if browser.get_tabs().lock().unwrap().is_empty() {
                self.logger.debug("WEB", url, "CLEANUP", "Browser closed manually")?;
                break;
            }
        }

        self.logger.info("WEB", url, "COMPLETED", "Auto-login flow finished")?;
        Ok(())
    }
}
