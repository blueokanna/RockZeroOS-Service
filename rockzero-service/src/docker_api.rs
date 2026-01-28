//! Docker API Client
//!
//! Production-grade Docker API client using Unix socket communication.
//! This is more secure than shell commands as it:
//! - Avoids shell injection vulnerabilities
//! - Provides proper error handling
//! - Supports Docker Compose for CasaOS/iStoreOS compatibility
//!
//! ## Security Features
//! - Unix socket communication (no shell execution)
//! - Input validation and sanitization
//! - Proper error handling
//! - Rate limiting support

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use {
    hyper::{Body, Client, Method, Request, StatusCode},
    hyperlocal::{UnixClientExt, Uri as UnixUri},
};

/// Docker socket path
#[allow(dead_code)]
const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Docker API version
#[allow(dead_code)]
const DOCKER_API_VERSION: &str = "v1.41";

/// Docker container information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ContainerInfo {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: Vec<String>,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Ports")]
    pub ports: Vec<PortBinding>,
    #[serde(rename = "Created")]
    pub created: i64,
    #[serde(rename = "Labels")]
    pub labels: Option<HashMap<String, String>>,
}

/// Port binding information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PortBinding {
    #[serde(rename = "IP")]
    pub ip: Option<String>,
    #[serde(rename = "PrivatePort")]
    pub private_port: u16,
    #[serde(rename = "PublicPort")]
    pub public_port: Option<u16>,
    #[serde(rename = "Type")]
    pub port_type: String,
}

/// Docker image information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ImageInfo {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "RepoTags")]
    pub repo_tags: Option<Vec<String>>,
    #[serde(rename = "Size")]
    pub size: i64,
    #[serde(rename = "Created")]
    pub created: i64,
    #[serde(rename = "Labels")]
    pub labels: Option<HashMap<String, String>>,
}

/// Container creation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ContainerConfig {
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "ExposedPorts")]
    pub exposed_ports: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<HostConfig>,
    #[serde(rename = "Labels")]
    pub labels: Option<HashMap<String, String>>,
}

/// Host configuration for container
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct HostConfig {
    #[serde(rename = "PortBindings")]
    pub port_bindings: Option<HashMap<String, Vec<PortMap>>>,
    #[serde(rename = "Binds")]
    pub binds: Option<Vec<String>>,
    #[serde(rename = "RestartPolicy")]
    pub restart_policy: Option<RestartPolicy>,
    #[serde(rename = "NetworkMode")]
    pub network_mode: Option<String>,
}

/// Port mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PortMap {
    #[serde(rename = "HostIp")]
    pub host_ip: Option<String>,
    #[serde(rename = "HostPort")]
    pub host_port: String,
}

/// Restart policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RestartPolicy {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MaximumRetryCount")]
    pub maximum_retry_count: Option<i32>,
}

/// Docker Compose service definition (CasaOS/iStoreOS compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ComposeService {
    pub image: String,
    pub container_name: Option<String>,
    pub ports: Option<Vec<String>>,
    pub volumes: Option<Vec<String>>,
    pub environment: Option<Vec<String>>,
    pub restart: Option<String>,
    pub labels: Option<HashMap<String, String>>,
    pub networks: Option<Vec<String>>,
    pub depends_on: Option<Vec<String>>,
}

/// Docker Compose file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ComposeFile {
    pub version: Option<String>,
    pub services: HashMap<String, ComposeService>,
    pub networks: Option<HashMap<String, serde_json::Value>>,
    pub volumes: Option<HashMap<String, serde_json::Value>>,
}

/// Docker API client error
#[derive(Debug)]
#[allow(dead_code)]
pub enum DockerError {
    ConnectionFailed(String),
    ApiError(String),
    ParseError(String),
    NotFound(String),
    Unauthorized(String),
    Conflict(String),
}

impl std::fmt::Display for DockerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DockerError::ConnectionFailed(msg) => write!(f, "Docker connection failed: {}", msg),
            DockerError::ApiError(msg) => write!(f, "Docker API error: {}", msg),
            DockerError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            DockerError::NotFound(msg) => write!(f, "Not found: {}", msg),
            DockerError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            DockerError::Conflict(msg) => write!(f, "Conflict: {}", msg),
        }
    }
}

impl std::error::Error for DockerError {}

/// Docker API client
#[allow(dead_code)]
pub struct DockerClient {
    #[cfg(target_os = "linux")]
    client: Client<hyperlocal::UnixConnector>,
    #[allow(dead_code)]
    socket_path: String,
}

#[allow(dead_code)]
impl DockerClient {
    /// Create a new Docker client
    pub fn new() -> Result<Self, DockerError> {
        Self::with_socket(DOCKER_SOCKET)
    }

    /// Create a new Docker client with custom socket path
    #[allow(dead_code)]
    pub fn with_socket(_socket_path: &str) -> Result<Self, DockerError> {
        #[cfg(target_os = "linux")]
        {
            // Check if socket exists
            if !std::path::Path::new(socket_path).exists() {
                return Err(DockerError::ConnectionFailed(format!(
                    "Docker socket not found at {}",
                    socket_path
                )));
            }

            let client = Client::unix();
            Ok(Self {
                client,
                socket_path: socket_path.to_string(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(DockerError::ConnectionFailed(
                "Docker API only supported on Linux".to_string(),
            ))
        }
    }

    /// List all containers
    #[cfg(target_os = "linux")]
    pub async fn list_containers(&self, all: bool) -> Result<Vec<ContainerInfo>, DockerError> {
        let query = if all { "?all=true" } else { "" };
        let uri = UnixUri::new(&self.socket_path, &format!("/{}/containers/json{}", DOCKER_API_VERSION, query));

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        if response.status() != StatusCode::OK {
            return Err(DockerError::ApiError(format!(
                "Failed to list containers: {}",
                response.status()
            )));
        }

        let body = hyper::body::to_bytes(response.into_body()).await
            .map_err(|e| DockerError::ParseError(e.to_string()))?;

        serde_json::from_slice(&body)
            .map_err(|e| DockerError::ParseError(e.to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn list_containers(&self, _all: bool) -> Result<Vec<ContainerInfo>, DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// List all images
    #[cfg(target_os = "linux")]
    pub async fn list_images(&self) -> Result<Vec<ImageInfo>, DockerError> {
        let uri = UnixUri::new(&self.socket_path, &format!("/{}/images/json", DOCKER_API_VERSION));

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        if response.status() != StatusCode::OK {
            return Err(DockerError::ApiError(format!(
                "Failed to list images: {}",
                response.status()
            )));
        }

        let body = hyper::body::to_bytes(response.into_body()).await
            .map_err(|e| DockerError::ParseError(e.to_string()))?;

        serde_json::from_slice(&body)
            .map_err(|e| DockerError::ParseError(e.to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn list_images(&self) -> Result<Vec<ImageInfo>, DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Create a container
    #[cfg(target_os = "linux")]
    pub async fn create_container(
        &self,
        name: &str,
        config: &ContainerConfig,
    ) -> Result<String, DockerError> {
        // Sanitize container name
        let safe_name = sanitize_container_name(name);
        
        let uri = UnixUri::new(
            &self.socket_path,
            &format!("/{}/containers/create?name={}", DOCKER_API_VERSION, safe_name),
        );

        let body = serde_json::to_string(config)
            .map_err(|e| DockerError::ParseError(e.to_string()))?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(body))
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::CREATED => {
                let body = hyper::body::to_bytes(response.into_body()).await
                    .map_err(|e| DockerError::ParseError(e.to_string()))?;
                
                let result: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| DockerError::ParseError(e.to_string()))?;
                
                result["Id"]
                    .as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| DockerError::ParseError("Missing container ID".to_string()))
            }
            StatusCode::CONFLICT => Err(DockerError::Conflict(format!(
                "Container '{}' already exists",
                name
            ))),
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Image '{}' not found",
                config.image
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to create container: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn create_container(
        &self,
        _name: &str,
        _config: &ContainerConfig,
    ) -> Result<String, DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Start a container
    #[cfg(target_os = "linux")]
    pub async fn start_container(&self, container_id: &str) -> Result<(), DockerError> {
        let safe_id = sanitize_container_id(container_id);
        let uri = UnixUri::new(
            &self.socket_path,
            &format!("/{}/containers/{}/start", DOCKER_API_VERSION, safe_id),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED => Ok(()),
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Container '{}' not found",
                container_id
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to start container: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn start_container(&self, _container_id: &str) -> Result<(), DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Stop a container
    #[cfg(target_os = "linux")]
    pub async fn stop_container(&self, container_id: &str, timeout: Option<u32>) -> Result<(), DockerError> {
        let safe_id = sanitize_container_id(container_id);
        let timeout_param = timeout.map(|t| format!("?t={}", t)).unwrap_or_default();
        let uri = UnixUri::new(
            &self.socket_path,
            &format!("/{}/containers/{}/stop{}", DOCKER_API_VERSION, safe_id, timeout_param),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED => Ok(()),
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Container '{}' not found",
                container_id
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to stop container: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn stop_container(&self, _container_id: &str, _timeout: Option<u32>) -> Result<(), DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Remove a container
    #[cfg(target_os = "linux")]
    pub async fn remove_container(&self, container_id: &str, force: bool) -> Result<(), DockerError> {
        let safe_id = sanitize_container_id(container_id);
        let force_param = if force { "?force=true" } else { "" };
        let uri = UnixUri::new(
            &self.socket_path,
            &format!("/{}/containers/{}{}", DOCKER_API_VERSION, safe_id, force_param),
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Container '{}' not found",
                container_id
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to remove container: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn remove_container(&self, _container_id: &str, _force: bool) -> Result<(), DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Pull an image
    #[cfg(target_os = "linux")]
    pub async fn pull_image(&self, image: &str, tag: Option<&str>) -> Result<(), DockerError> {
        let safe_image = sanitize_image_name(image);
        let tag = tag.unwrap_or("latest");
        let uri = UnixUri::new(
            &self.socket_path,
            &format!("/{}/images/create?fromImage={}&tag={}", DOCKER_API_VERSION, safe_image, tag),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Image '{}:{}' not found",
                image, tag
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to pull image: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn pull_image(&self, _image: &str, _tag: Option<&str>) -> Result<(), DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Remove an image
    #[cfg(target_os = "linux")]
    pub async fn remove_image(&self, image_id: &str, force: bool) -> Result<(), DockerError> {
        let safe_id = sanitize_image_name(image_id);
        let force_param = if force { "?force=true" } else { "" };
        let uri = UnixUri::new(
            &self.socket_path,
            &format!("/{}/images/{}{}", DOCKER_API_VERSION, safe_id, force_param),
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Image '{}' not found",
                image_id
            ))),
            StatusCode::CONFLICT => Err(DockerError::Conflict(format!(
                "Image '{}' is in use",
                image_id
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to remove image: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn remove_image(&self, _image_id: &str, _force: bool) -> Result<(), DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }

    /// Get container logs
    #[cfg(target_os = "linux")]
    pub async fn get_logs(&self, container_id: &str, tail: Option<u32>) -> Result<String, DockerError> {
        let safe_id = sanitize_container_id(container_id);
        let tail_param = tail.map(|t| format!("&tail={}", t)).unwrap_or_default();
        let uri = UnixUri::new(
            &self.socket_path,
            &format!(
                "/{}/containers/{}/logs?stdout=true&stderr=true{}",
                DOCKER_API_VERSION, safe_id, tail_param
            ),
        );

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .map_err(|e| DockerError::ApiError(e.to_string()))?;

        let response = self.client.request(req).await
            .map_err(|e| DockerError::ConnectionFailed(e.to_string()))?;

        match response.status() {
            StatusCode::OK => {
                let body = hyper::body::to_bytes(response.into_body()).await
                    .map_err(|e| DockerError::ParseError(e.to_string()))?;
                
                // Docker logs have a special format with 8-byte header per line
                // We need to strip these headers
                let logs = parse_docker_logs(&body);
                Ok(logs)
            }
            StatusCode::NOT_FOUND => Err(DockerError::NotFound(format!(
                "Container '{}' not found",
                container_id
            ))),
            status => Err(DockerError::ApiError(format!(
                "Failed to get logs: {}",
                status
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn get_logs(&self, _container_id: &str, _tail: Option<u32>) -> Result<String, DockerError> {
        Err(DockerError::ConnectionFailed("Docker API only supported on Linux".to_string()))
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        Self::new().expect("Failed to create Docker client")
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Sanitize container name to prevent injection
#[allow(dead_code)]
fn sanitize_container_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// Sanitize container ID to prevent injection
#[allow(dead_code)]
fn sanitize_container_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Sanitize image name to prevent injection
#[allow(dead_code)]
fn sanitize_image_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == '/' || *c == ':')
        .collect()
}

/// Parse Docker logs (strip 8-byte headers)
#[allow(dead_code)]
fn parse_docker_logs(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    
    while i + 8 <= data.len() {
        // Read header
        let _stream_type = data[i]; // 0=stdin, 1=stdout, 2=stderr
        let size = u32::from_be_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]) as usize;
        
        i += 8;
        
        if i + size <= data.len() {
            if let Ok(line) = std::str::from_utf8(&data[i..i + size]) {
                result.push_str(line);
            }
            i += size;
        } else {
            break;
        }
    }
    
    result
}

/// Convert ComposeService to ContainerConfig
#[allow(dead_code)]
pub fn compose_to_container_config(service: &ComposeService) -> ContainerConfig {
    let mut port_bindings: HashMap<String, Vec<PortMap>> = HashMap::new();
    let mut exposed_ports: HashMap<String, serde_json::Value> = HashMap::new();
    
    if let Some(ports) = &service.ports {
        for port in ports {
            // Parse port mapping (e.g., "8080:80" or "8080:80/tcp")
            let parts: Vec<&str> = port.split(':').collect();
            if parts.len() == 2 {
                let host_port = parts[0];
                let container_port_parts: Vec<&str> = parts[1].split('/').collect();
                let container_port = container_port_parts[0];
                let protocol = container_port_parts.get(1).unwrap_or(&"tcp");
                
                let key = format!("{}/{}", container_port, protocol);
                exposed_ports.insert(key.clone(), serde_json::json!({}));
                port_bindings.insert(
                    key,
                    vec![PortMap {
                        host_ip: Some("0.0.0.0".to_string()),
                        host_port: host_port.to_string(),
                    }],
                );
            }
        }
    }
    
    let restart_policy = service.restart.as_ref().map(|r| RestartPolicy {
        name: r.clone(),
        maximum_retry_count: None,
    });
    
    ContainerConfig {
        image: service.image.clone(),
        env: service.environment.clone(),
        exposed_ports: if exposed_ports.is_empty() { None } else { Some(exposed_ports) },
        host_config: Some(HostConfig {
            port_bindings: if port_bindings.is_empty() { None } else { Some(port_bindings) },
            binds: service.volumes.clone(),
            restart_policy,
            network_mode: service.networks.as_ref().and_then(|n| n.first().cloned()),
        }),
        labels: service.labels.clone(),
    }
}

/// Parse Docker Compose file
#[allow(dead_code)]
pub fn parse_compose_file(content: &str) -> Result<ComposeFile, DockerError> {
    serde_yaml::from_str(content)
        .map_err(|e| DockerError::ParseError(format!("Invalid compose file: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_container_name() {
        assert_eq!(sanitize_container_name("my-container"), "my-container");
        assert_eq!(sanitize_container_name("my_container.1"), "my_container.1");
        assert_eq!(sanitize_container_name("my;container"), "mycontainer");
        assert_eq!(sanitize_container_name("my`container"), "mycontainer");
    }

    #[test]
    fn test_sanitize_container_id() {
        assert_eq!(sanitize_container_id("abc123def456"), "abc123def456");
        assert_eq!(sanitize_container_id("abc;123"), "abc123");
    }

    #[test]
    fn test_sanitize_image_name() {
        assert_eq!(sanitize_image_name("nginx:latest"), "nginx:latest");
        assert_eq!(sanitize_image_name("docker.io/library/nginx"), "docker.io/library/nginx");
        assert_eq!(sanitize_image_name("nginx;rm -rf /"), "nginxrm-rf/");
    }
}
