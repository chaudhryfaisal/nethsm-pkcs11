//! Mock NetHSM server implementation for testing purposes.
//!
//! This module provides a lightweight mock server that simulates NetHSM API responses
//! for testing the NetHSM backend implementation without requiring a real NetHSM device.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use serde_json::{json, Value};

/// Mock NetHSM server for testing
pub struct MockNetHsmServer {
    port: u16,
    state: Arc<Mutex<ServerState>>,
    shutdown_tx: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Internal server state
#[derive(Debug, Clone)]
struct ServerState {
    provisioned: bool,
    users: HashMap<String, User>,
    keys: HashMap<String, Key>,
    system_info: SystemInfo,
    health_state: String,
}

#[derive(Debug, Clone)]
struct User {
    username: String,
    role: String,
    passphrase: String,
}

#[derive(Debug, Clone)]
struct Key {
    id: String,
    key_type: String,
    mechanisms: Vec<String>,
    length: u32,
}

#[derive(Debug, Clone)]
struct SystemInfo {
    product: String,
    version: String,
    build: String,
}

impl Default for ServerState {
    fn default() -> Self {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), User {
            username: "admin".to_string(),
            role: "Administrator".to_string(),
            passphrase: "Administrator".to_string(),
        });
        users.insert("operator".to_string(), User {
            username: "operator".to_string(),
            role: "Operator".to_string(),
            passphrase: "opPassphrase".to_string(),
        });

        Self {
            provisioned: true,
            users,
            keys: HashMap::new(),
            system_info: SystemInfo {
                product: "NetHSM".to_string(),
                version: "1.0.0".to_string(),
                build: "test".to_string(),
            },
            health_state: "Operational".to_string(),
        }
    }
}

impl MockNetHsmServer {
    /// Create a new mock server on the specified port
    pub fn new(port: u16) -> Self {
        Self {
            port,
            state: Arc::new(Mutex::new(ServerState::default())),
            shutdown_tx: None,
            handle: None,
        }
    }

    /// Start the mock server
    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let state = Arc::clone(&self.state);
        let port = self.port;

        let handle = thread::spawn(move || {
            Self::run_server(port, state, shutdown_rx);
        });

        self.shutdown_tx = Some(shutdown_tx);
        self.handle = Some(handle);

        // Wait a bit for the server to start
        thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    /// Stop the mock server
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Add a key to the mock server
    pub fn add_key(&self, id: &str, key_type: &str, mechanisms: Vec<String>, length: u32) {
        let mut state = self.state.lock().unwrap();
        state.keys.insert(id.to_string(), Key {
            id: id.to_string(),
            key_type: key_type.to_string(),
            mechanisms,
            length,
        });
    }

    /// Remove a key from the mock server
    pub fn remove_key(&self, id: &str) {
        let mut state = self.state.lock().unwrap();
        state.keys.remove(id);
    }

    /// Set the health state
    pub fn set_health_state(&self, health_state: &str) {
        let mut state = self.state.lock().unwrap();
        state.health_state = health_state.to_string();
    }

    /// Set provisioned state
    pub fn set_provisioned(&self, provisioned: bool) {
        let mut state = self.state.lock().unwrap();
        state.provisioned = provisioned;
    }

    fn run_server(
        port: u16,
        state: Arc<Mutex<ServerState>>,
        shutdown_rx: std::sync::mpsc::Receiver<()>,
    ) {
        use std::io::prelude::*;
        use std::net::{TcpListener, TcpStream};

        let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("Failed to bind mock server to port {}: {}", port, e);
                return;
            }
        };

        listener.set_nonblocking(true).unwrap();

        loop {
            // Check for shutdown signal
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            // Accept connections
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = Arc::clone(&state);
                    thread::spawn(move || {
                        Self::handle_connection(stream, state);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                    break;
                }
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, state: Arc<Mutex<ServerState>>) {
        let mut buffer = [0; 4096];
        
        match stream.read(&mut buffer) {
            Ok(size) => {
                let request = String::from_utf8_lossy(&buffer[..size]);
                let response = Self::handle_request(&request, state);
                
                let http_response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response.status_code,
                    response.status_text,
                    response.body.len(),
                    response.body
                );
                
                let _ = stream.write_all(http_response.as_bytes());
            }
            Err(e) => {
                eprintln!("Error reading from connection: {}", e);
            }
        }
    }

    fn handle_request(request: &str, state: Arc<Mutex<ServerState>>) -> HttpResponse {
        let lines: Vec<&str> = request.lines().collect();
        if lines.is_empty() {
            return HttpResponse::bad_request("Invalid request");
        }

        let request_line = lines[0];
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return HttpResponse::bad_request("Invalid request line");
        }

        let method = parts[0];
        let path = parts[1];

        let state = state.lock().unwrap();

        match (method, path) {
            ("GET", "/api/v1/info") => {
                let info = json!({
                    "product": state.system_info.product,
                    "version": state.system_info.version,
                    "build": state.system_info.build
                });
                HttpResponse::ok(info.to_string())
            }
            ("GET", "/api/v1/health/state") => {
                let health = json!({
                    "state": state.health_state
                });
                HttpResponse::ok(health.to_string())
            }
            ("GET", "/api/v1/keys") => {
                let keys: Vec<Value> = state.keys.values().map(|key| {
                    json!({
                        "id": key.id,
                        "type": key.key_type,
                        "mechanisms": key.mechanisms,
                        "length": key.length
                    })
                }).collect();
                HttpResponse::ok(json!(keys).to_string())
            }
            ("POST", "/api/v1/provision") => {
                if state.provisioned {
                    HttpResponse::conflict("Already provisioned")
                } else {
                    HttpResponse::ok("{}".to_string())
                }
            }
            ("GET", path) if path.starts_with("/api/v1/keys/") => {
                let key_id = &path[14..]; // Remove "/api/v1/keys/"
                if let Some(key) = state.keys.get(key_id) {
                    let key_info = json!({
                        "id": key.id,
                        "type": key.key_type,
                        "mechanisms": key.mechanisms,
                        "length": key.length
                    });
                    HttpResponse::ok(key_info.to_string())
                } else {
                    HttpResponse::not_found("Key not found")
                }
            }
            ("POST", "/api/v1/keys") => {
                // Key generation endpoint
                let key_id = format!("key_{}", state.keys.len() + 1);
                let key_info = json!({
                    "id": key_id,
                    "type": "RSA",
                    "mechanisms": ["RSA_PKCS", "RSA_PSS"],
                    "length": 2048
                });
                HttpResponse::created(key_info.to_string())
            }
            ("POST", path) if path.starts_with("/api/v1/keys/") && path.ends_with("/sign") => {
                // Signing endpoint
                let signature = json!({
                    "signature": "mock_signature_data"
                });
                HttpResponse::ok(signature.to_string())
            }
            _ => HttpResponse::not_found("Endpoint not found")
        }
    }
}

impl Drop for MockNetHsmServer {
    fn drop(&mut self) {
        self.stop();
    }
}

struct HttpResponse {
    status_code: u16,
    status_text: &'static str,
    body: String,
}

impl HttpResponse {
    fn ok(body: String) -> Self {
        Self {
            status_code: 200,
            status_text: "OK",
            body,
        }
    }

    fn created(body: String) -> Self {
        Self {
            status_code: 201,
            status_text: "Created",
            body,
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status_code: 400,
            status_text: "Bad Request",
            body: json!({"error": message}).to_string(),
        }
    }

    fn not_found(message: &str) -> Self {
        Self {
            status_code: 404,
            status_text: "Not Found",
            body: json!({"error": message}).to_string(),
        }
    }

    fn conflict(message: &str) -> Self {
        Self {
            status_code: 409,
            status_text: "Conflict",
            body: json!({"error": message}).to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_server_creation() {
        let server = MockNetHsmServer::new(8080);
        assert_eq!(server.port, 8080);
    }

    #[test]
    fn test_mock_server_start_stop() {
        let mut server = MockNetHsmServer::new(8081);
        assert!(server.start().is_ok());
        server.stop();
    }

    #[test]
    fn test_key_management() {
        let server = MockNetHsmServer::new(8082);
        
        server.add_key("test_key", "RSA", vec!["RSA_PKCS".to_string()], 2048);
        
        let state = server.state.lock().unwrap();
        assert!(state.keys.contains_key("test_key"));
        
        drop(state);
        server.remove_key("test_key");
        
        let state = server.state.lock().unwrap();
        assert!(!state.keys.contains_key("test_key"));
    }
}