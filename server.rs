use crate::chrome::ChromeClient;
use crate::config::{Config, LoginRequest, LoginResponse};
use crate::logger::Logger;
use crate::ssh::SshClient;
use crate::resource_monitor::ResourceMonitor;
use crate::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct QcmServer {
    config: Arc<Config>,
    logger: Arc<Logger>,
    resource_monitor: Arc<ResourceMonitor>,
}

impl QcmServer {
    pub fn new(config: Config) -> Result<Self> {
        let logger = Logger::new(&config)?;
        
        // Set max concurrent sessions based on system capacity
        // For production: 1000+ users, but limit concurrent Chrome sessions to prevent resource exhaustion
        let max_concurrent_sessions = 100; // Adjust based on server specs
        
        let resource_monitor = Arc::new(ResourceMonitor::new(
            Logger::new(&config)?, 
            max_concurrent_sessions
        ));
        
        Ok(Self {
            config: Arc::new(config),
            logger: Arc::new(logger),
            resource_monitor,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let addr = format!("127.0.0.1:{}", self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;
        
        self.logger.info("SERVER", &addr, "STARTED", 
            &format!("QCM Auto-Login Service started (max {} concurrent sessions)", 
                self.resource_monitor.get_stats().max_sessions))?;
        
        // Start resource monitoring background task
        ResourceMonitor::start_monitoring(Arc::clone(&self.resource_monitor));
        
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let config = Arc::clone(&self.config);
                    let logger = Arc::clone(&self.logger);
                    let monitor = Arc::clone(&self.resource_monitor);
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, config, logger, monitor).await {
                            eprintln!("Error handling connection from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    self.logger.error("SERVER", &addr, "ERROR", &format!("Failed to accept connection: {}", e))?;
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        config: Arc<Config>,
        logger: Arc<Logger>,
        resource_monitor: Arc<ResourceMonitor>,
    ) -> Result<()> {
        let peer_addr = stream.peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        logger.debug("CONNECTION", &peer_addr, "RECEIVED", "New connection established")?;

        // Read the request
        let mut buffer = Vec::new();
        let mut temp_buffer = [0; 1024];
        
        loop {
            match stream.read(&mut temp_buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buffer[..n]);
                    // Check if we have a complete JSON object or HTTP request
                    if let Ok(json_str) = String::from_utf8(buffer.clone()) {
                        if json_str.trim().ends_with('}') || json_str.contains("\r\n\r\n") {
                            break;
                        }
                    }
                    // Also break if buffer gets too large
                    if buffer.len() > 8192 {
                        break;
                    }
                }
                Err(e) => {
                    logger.error("CONNECTION", &peer_addr, "READ_ERROR", &format!("Failed to read from stream: {}", e))?;
                    return Err(e.into());
                }
            }
        }

        let request_str = String::from_utf8(buffer)
            .map_err(|e| crate::QcmError::Other(format!("Invalid UTF-8: {}", e)))?;

        logger.debug("REQUEST", &peer_addr, "RECEIVED", &format!("Raw request: {}", request_str))?;

        // Handle HTTP requests by extracting JSON from body
        let json_payload = if request_str.starts_with("POST") || request_str.starts_with("GET") {
            // HTTP request - extract JSON from body
            if let Some(body_start) = request_str.find("\r\n\r\n") {
                request_str[body_start + 4..].trim()
            } else {
                logger.error("REQUEST", &peer_addr, "PARSE_ERROR", "HTTP request without proper body separator")?;
                return Err(crate::QcmError::Other("Invalid HTTP request format".to_string()));
            }
        } else {
            // Raw JSON request
            request_str.trim()
        };

        // Parse the JSON request
        let login_request: LoginRequest = serde_json::from_str(json_payload)?;
        
        // Acquire resource slot for processing (this will block if system is at capacity)
        let _session_guard = resource_monitor.acquire_session_slot().await?;
        
        // Process the request asynchronously without blocking other connections
        let config_clone = Arc::clone(&config);
        let logger_clone = Arc::clone(&logger);
        
        // Spawn processing task to handle request asynchronously
        if let Err(e) = Self::process_request(login_request, &config_clone, &logger_clone).await {
        log::error!("request processing failed: {e}");
        }
        
        // Set a timeout for request processing (5 minutes max per request)
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(300), 
            processing_task
        ).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                logger.error("REQUEST", &peer_addr, "TASK_ERROR", "Request processing task failed")?;
                LoginResponse::error("Internal processing error".to_string())
            },
            Err(_) => {
                logger.error("REQUEST", &peer_addr, "TIMEOUT", "Request processing timed out after 5 minutes")?;
                LoginResponse::error("Request processing timeout".to_string())
            }
        };

        // Send response with proper headers
        let response_json = serde_json::to_string(&response)?;
        
        let is_http_request = request_str.starts_with("POST") || request_str.starts_with("GET");
        
        if is_http_request {
            // Send HTTP response
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_json.len(),
                response_json
            );
            stream.write_all(http_response.as_bytes()).await?;
        } else {
            // Send raw JSON response
            stream.write_all(response_json.as_bytes()).await?;
        }
        
        stream.flush().await?;

        logger.debug("RESPONSE", &peer_addr, "SENT", &format!("Response: {}", response_json))?;

        Ok(())
    }

    async fn process_request(
        request: LoginRequest,
        config: &Config,
        logger: &Logger,
    ) -> LoginResponse {
        match request {
            LoginRequest::Ssh { host, port, username, password } => {
                let ssh_client = SshClient::new(config.clone(), Logger::new(config).unwrap());
                
                match ssh_client.connect(&host, port, &username, &password).await {
                    Ok(_) => LoginResponse::success(format!("SSH connection to {}:{} successful", host, port)),
                    Err(e) => LoginResponse::error(format!("SSH connection failed: {}", e)),
                }
            }
            LoginRequest::Web { url, username, password, uuid, session_id, session_user, client_ip, session_state } => {
                let chrome_client = ChromeClient::new(config.clone(), Logger::new(config).unwrap());
                
                // Log session information if available
                if let Some(session_id) = session_id {
                    let session_info = format!(
                        "Session {} (user: {}, ip: {}, state: {})",
                        session_id,
                        session_user.as_deref().unwrap_or("unknown"),
                        client_ip.as_deref().unwrap_or("unknown"),
                        session_state.as_deref().unwrap_or("unknown")
                    );
                    let _ = logger.info("SERVER", &url, "SESSION_INFO", &session_info);
                }
                
                match chrome_client.auto_login(
                    &url, 
                    &username, 
                    &password,
                    session_id,
                    session_user.as_deref(),
                    uuid.as_deref()
                ).await {
                    Ok(_) => LoginResponse::success(format!("Web auto-login to {} successful", url)),
                    Err(e) => LoginResponse::error(format!("Web auto-login failed: {}", e)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        // Test creating server with a test-safe config
        let mut config = Config::default();
        config.log_dir = "/tmp/qcm_test_logs".to_string();
        
        let server = QcmServer::new(config);
        assert!(server.is_ok());
    }
}
