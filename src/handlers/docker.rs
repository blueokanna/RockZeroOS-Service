use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use tracing::{info, warn};

use crate::error::AppError;

/// Docker 容器信息
#[derive(Debug, Serialize, Clone)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_id: String,
    pub status: ContainerStatus,
    pub state: String,
    pub created: String,
    pub ports: Vec<PortBinding>,
    pub volumes: Vec<VolumeBinding>,
    pub networks: Vec<String>,
    pub labels: HashMap<String, String>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<u64>,
    pub memory_limit: Option<u64>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum ContainerStatus {
    Running,
    Paused,
    Restarting,
    Exited,
    Dead,
    Created,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortBinding {
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: String,
    pub host_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VolumeBinding {
    pub source: String,
    pub destination: String,
    pub mode: String,
}

/// Docker 镜像信息
#[derive(Debug, Serialize, Clone)]
pub struct DockerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: u64,
    pub created: String,
}

/// 创建容器请求
#[derive(Debug, Deserialize)]
pub struct CreateContainerRequest {
    pub name: String,
    pub image: String,
    pub tag: Option<String>,
    pub ports: Option<Vec<PortBinding>>,
    pub volumes: Option<Vec<VolumeBinding>>,
    pub environment: Option<HashMap<String, String>>,
    pub restart_policy: Option<String>,
    pub network: Option<String>,
    pub privileged: Option<bool>,
    pub cap_add: Option<Vec<String>>,
    pub devices: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    pub labels: Option<HashMap<String, String>>,
    pub memory_limit: Option<String>,
    pub cpu_limit: Option<f64>,
}

/// Docker Compose 部署请求
#[derive(Debug, Deserialize)]
pub struct ComposeDeployRequest {
    pub name: String,
    pub compose_content: String,
    pub env_vars: Option<HashMap<String, String>>,
}

// ============ Docker 状态检查 ============

/// 检查 Docker 是否可用
pub async fn check_docker_status() -> Result<HttpResponse, AppError> {
    let docker_available = is_docker_available();
    let docker_compose_available = is_docker_compose_available();
    let docker_version = get_docker_version();
    let docker_info = get_docker_info();
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "docker_available": docker_available,
        "docker_compose_available": docker_compose_available,
        "version": docker_version,
        "info": docker_info
    })))
}

fn is_docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_docker_compose_available() -> bool {
    // 先检查 docker compose (v2)
    if Command::new("docker")
        .args(["compose", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }
    
    // 再检查 docker-compose (v1)
    Command::new("docker-compose")
        .args(["version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn get_docker_version() -> Option<String> {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn get_docker_info() -> serde_json::Value {
    let output = Command::new("docker")
        .args(["info", "--format", "{{json .}}"])
        .output();
    
    if let Ok(output) = output {
        if output.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                return serde_json::json!({
                    "containers": json["Containers"],
                    "containers_running": json["ContainersRunning"],
                    "containers_paused": json["ContainersPaused"],
                    "containers_stopped": json["ContainersStopped"],
                    "images": json["Images"],
                    "storage_driver": json["Driver"],
                    "docker_root_dir": json["DockerRootDir"],
                    "os_type": json["OSType"],
                    "architecture": json["Architecture"],
                    "cpus": json["NCPU"],
                    "memory": json["MemTotal"]
                });
            }
        }
    }
    
    serde_json::json!({})
}

// ============ 容器管理 ============

/// 列出所有容器
pub async fn list_containers() -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let containers = get_all_containers()?;
    Ok(HttpResponse::Ok().json(containers))
}

/// 获取容器详情
pub async fn get_container(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    let container = get_container_details(&container_id)?;
    Ok(HttpResponse::Ok().json(container))
}

/// 创建并启动容器
pub async fn create_container(body: web::Json<CreateContainerRequest>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let req = body.into_inner();
    let image_full = format!("{}:{}", req.image, req.tag.as_deref().unwrap_or("latest"));
    
    // 拉取镜像
    info!("Pulling image: {}", image_full);
    let pull_output = Command::new("docker")
        .args(["pull", &image_full])
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to execute docker pull: {}", e)))?;
    
    if !pull_output.status.success() {
        let err = String::from_utf8_lossy(&pull_output.stderr);
        warn!("Failed to pull image: {}", err);
        // 检查本地是否已有镜像
        let check_output = Command::new("docker")
            .args(["image", "inspect", &image_full])
            .output();
        
        if check_output.map(|o| !o.status.success()).unwrap_or(true) {
            return Err(AppError::BadRequest(format!("Failed to pull image and image not found locally: {}", err)));
        }
        info!("Using local image: {}", image_full);
    }
    
    // 构建 docker run 命令
    let mut args = vec!["run".to_string(), "-d".to_string()];
    
    // 容器名称
    args.push("--name".to_string());
    args.push(req.name.clone());
    
    // 重启策略
    if let Some(restart) = &req.restart_policy {
        args.push("--restart".to_string());
        args.push(restart.clone());
    } else {
        args.push("--restart".to_string());
        args.push("unless-stopped".to_string());
    }
    
    // 端口映射
    if let Some(ports) = &req.ports {
        for port in ports {
            let host_ip = port.host_ip.as_deref().unwrap_or("0.0.0.0");
            args.push("-p".to_string());
            args.push(format!("{}:{}:{}/{}", host_ip, port.host_port, port.container_port, port.protocol));
        }
    }
    
    // 卷挂载
    if let Some(volumes) = &req.volumes {
        for vol in volumes {
            args.push("-v".to_string());
            args.push(format!("{}:{}:{}", vol.source, vol.destination, vol.mode));
        }
    }
    
    // 环境变量
    if let Some(env) = &req.environment {
        for (key, value) in env {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }
    }
    
    // 网络
    if let Some(network) = &req.network {
        args.push("--network".to_string());
        args.push(network.clone());
    }
    
    // 特权模式
    if req.privileged.unwrap_or(false) {
        args.push("--privileged".to_string());
    }
    
    // 能力添加
    if let Some(caps) = &req.cap_add {
        for cap in caps {
            args.push("--cap-add".to_string());
            args.push(cap.clone());
        }
    }
    
    // 设备映射
    if let Some(devices) = &req.devices {
        for device in devices {
            args.push("--device".to_string());
            args.push(device.clone());
        }
    }
    
    // 资源限制
    if let Some(mem) = &req.memory_limit {
        args.push("-m".to_string());
        args.push(mem.clone());
    }
    
    if let Some(cpu) = req.cpu_limit {
        args.push("--cpus".to_string());
        args.push(cpu.to_string());
    }
    
    // 标签
    if let Some(labels) = &req.labels {
        for (key, value) in labels {
            args.push("--label".to_string());
            args.push(format!("{}={}", key, value));
        }
    }
    
    // 镜像
    args.push(image_full.clone());
    
    // 命令
    if let Some(cmd) = &req.command {
        args.extend(cmd.clone());
    }
    
    info!("Creating container with args: {:?}", args);
    
    // 执行创建
    let output = Command::new("docker")
        .args(&args)
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to execute docker run: {}", e)))?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to start container: {}", err)));
    }
    
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    info!("Container created: {} ({})", req.name, container_id);
    
    // 等待容器启动
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    // 获取容器详情
    let container = get_container_details(&container_id)?;
    
    Ok(HttpResponse::Created().json(container))
}


/// 启动容器
pub async fn start_container(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    
    let output = Command::new("docker")
        .args(["start", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to start container: {}", err)));
    }
    
    info!("Container started: {}", container_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Container started"
    })))
}

/// 停止容器
pub async fn stop_container(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    
    let output = Command::new("docker")
        .args(["stop", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to stop container: {}", err)));
    }
    
    info!("Container stopped: {}", container_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Container stopped"
    })))
}

/// 重启容器
pub async fn restart_container(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    
    let output = Command::new("docker")
        .args(["restart", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to restart container: {}", err)));
    }
    
    info!("Container restarted: {}", container_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Container restarted"
    })))
}

/// 删除容器
pub async fn remove_container(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    
    // 先停止容器
    let _ = Command::new("docker")
        .args(["stop", &container_id])
        .output();
    
    // 删除容器
    let output = Command::new("docker")
        .args(["rm", "-f", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to remove container: {}", err)));
    }
    
    info!("Container removed: {}", container_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Container removed"
    })))
}

/// 获取容器日志
pub async fn get_container_logs(
    path: web::Path<String>,
    query: web::Query<LogsQuery>,
) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    let mut args = vec!["logs".to_string()];
    
    if let Some(tail) = query.tail {
        args.push("--tail".to_string());
        args.push(tail.to_string());
    }
    
    if query.timestamps.unwrap_or(false) {
        args.push("--timestamps".to_string());
    }
    
    args.push(container_id);
    
    let output = Command::new("docker")
        .args(&args)
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "stdout": stdout,
        "stderr": stderr
    })))
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub tail: Option<u32>,
    pub timestamps: Option<bool>,
}

/// 获取容器统计信息
pub async fn get_container_stats(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    
    let output = Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{json .}}", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        return Err(AppError::NotFound("Container not found or not running".to_string()));
    }
    
    let stats_str = String::from_utf8_lossy(&output.stdout);
    let stats: serde_json::Value = serde_json::from_str(stats_str.trim())
        .unwrap_or(serde_json::json!({}));
    
    Ok(HttpResponse::Ok().json(stats))
}

/// 在容器中执行命令
#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub workdir: Option<String>,
    pub user: Option<String>,
}

pub async fn exec_in_container(
    path: web::Path<String>,
    body: web::Json<ExecRequest>,
) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let container_id = path.into_inner();
    let req = body.into_inner();
    
    let mut args = vec!["exec".to_string()];
    
    if let Some(workdir) = &req.workdir {
        args.push("-w".to_string());
        args.push(workdir.clone());
    }
    
    if let Some(user) = &req.user {
        args.push("-u".to_string());
        args.push(user.clone());
    }
    
    args.push(container_id);
    args.extend(req.command);
    
    let output = Command::new("docker")
        .args(&args)
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
        "stderr": String::from_utf8_lossy(&output.stderr).to_string()
    })))
}

// ============ 镜像管理 ============

/// 列出所有镜像
pub async fn list_images() -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let output = Command::new("docker")
        .args(["images", "--format", "{{json .}}"])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    let mut images = Vec::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            images.push(DockerImage {
                id: json["ID"].as_str().unwrap_or("").to_string(),
                repository: json["Repository"].as_str().unwrap_or("").to_string(),
                tag: json["Tag"].as_str().unwrap_or("").to_string(),
                size: parse_size_string(json["Size"].as_str().unwrap_or("0")),
                created: json["CreatedSince"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    
    Ok(HttpResponse::Ok().json(images))
}

/// 拉取镜像
#[derive(Debug, Deserialize)]
pub struct PullImageRequest {
    pub image: String,
    pub tag: Option<String>,
}

pub async fn pull_image(body: web::Json<PullImageRequest>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let req = body.into_inner();
    let image_full = format!("{}:{}", req.image, req.tag.as_deref().unwrap_or("latest"));
    
    info!("Pulling image: {}", image_full);
    
    let output = Command::new("docker")
        .args(["pull", &image_full])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to pull image: {}", err)));
    }
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("Image {} pulled successfully", image_full)
    })))
}

/// 删除镜像
pub async fn remove_image(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let image_id = path.into_inner();
    
    let output = Command::new("docker")
        .args(["rmi", "-f", &image_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Failed to remove image: {}", err)));
    }
    
    info!("Image removed: {}", image_id);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Image removed"
    })))
}


// ============ Docker Compose 支持 ============

/// 使用 Docker Compose 部署应用
pub async fn compose_deploy(body: web::Json<ComposeDeployRequest>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let req = body.into_inner();
    let compose_dir = format!("./compose/{}", req.name);
    let compose_file = format!("{}/docker-compose.yml", compose_dir);
    
    // 创建目录
    std::fs::create_dir_all(&compose_dir)
        .map_err(|e| AppError::IoError(format!("Failed to create compose directory: {}", e)))?;
    
    // 写入 compose 文件
    std::fs::write(&compose_file, &req.compose_content)
        .map_err(|e| AppError::IoError(format!("Failed to write compose file: {}", e)))?;
    
    // 写入环境变量文件
    if let Some(env_vars) = &req.env_vars {
        let env_content: String = env_vars
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");
        
        std::fs::write(format!("{}/.env", compose_dir), env_content)
            .map_err(|e| AppError::IoError(format!("Failed to write env file: {}", e)))?;
    }
    
    // 执行 docker compose up
    let output = run_docker_compose(&compose_dir, &["up", "-d"])?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Compose deploy failed: {}", err)));
    }
    
    info!("Compose app deployed: {}", req.name);
    
    Ok(HttpResponse::Created().json(serde_json::json!({
        "success": true,
        "name": req.name,
        "message": "Application deployed successfully"
    })))
}

/// 停止 Compose 应用
pub async fn compose_stop(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let app_name = path.into_inner();
    let compose_dir = format!("./compose/{}", app_name);
    
    if !std::path::Path::new(&compose_dir).exists() {
        return Err(AppError::NotFound("Compose app not found".to_string()));
    }
    
    let output = run_docker_compose(&compose_dir, &["stop"])?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Compose stop failed: {}", err)));
    }
    
    info!("Compose app stopped: {}", app_name);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Application stopped"
    })))
}

/// 启动 Compose 应用
pub async fn compose_start(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let app_name = path.into_inner();
    let compose_dir = format!("./compose/{}", app_name);
    
    if !std::path::Path::new(&compose_dir).exists() {
        return Err(AppError::NotFound("Compose app not found".to_string()));
    }
    
    let output = run_docker_compose(&compose_dir, &["start"])?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Compose start failed: {}", err)));
    }
    
    info!("Compose app started: {}", app_name);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Application started"
    })))
}

/// 删除 Compose 应用
pub async fn compose_remove(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    ensure_docker_available()?;
    
    let app_name = path.into_inner();
    let compose_dir = format!("./compose/{}", app_name);
    
    if !std::path::Path::new(&compose_dir).exists() {
        return Err(AppError::NotFound("Compose app not found".to_string()));
    }
    
    // 停止并删除容器
    let _ = run_docker_compose(&compose_dir, &["down", "-v", "--remove-orphans"]);
    
    // 删除 compose 目录
    std::fs::remove_dir_all(&compose_dir)
        .map_err(|e| AppError::IoError(format!("Failed to remove compose directory: {}", e)))?;
    
    info!("Compose app removed: {}", app_name);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Application removed"
    })))
}

/// 列出所有 Compose 应用
pub async fn list_compose_apps() -> Result<HttpResponse, AppError> {
    let compose_base = "./compose";
    std::fs::create_dir_all(compose_base).ok();
    
    let mut apps = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(compose_base) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                let compose_file = format!("{}/{}/docker-compose.yml", compose_base, name);
                
                if std::path::Path::new(&compose_file).exists() {
                    // 获取应用状态
                    let status = get_compose_status(&format!("{}/{}", compose_base, name));
                    
                    apps.push(serde_json::json!({
                        "name": name,
                        "status": status,
                        "compose_file": compose_file
                    }));
                }
            }
        }
    }
    
    Ok(HttpResponse::Ok().json(apps))
}

fn get_compose_status(compose_dir: &str) -> String {
    if let Ok(output) = run_docker_compose(compose_dir, &["ps", "--format", "json"]) {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("running") {
                return "running".to_string();
            } else if stdout.contains("exited") {
                return "stopped".to_string();
            }
        }
    }
    "unknown".to_string()
}

fn run_docker_compose(compose_dir: &str, args: &[&str]) -> Result<std::process::Output, AppError> {
    // 先尝试 docker compose (v2)
    let output = Command::new("docker")
        .current_dir(compose_dir)
        .arg("compose")
        .args(args)
        .output();
    
    if let Ok(output) = output {
        if output.status.success() || !String::from_utf8_lossy(&output.stderr).contains("is not a docker command") {
            return Ok(output);
        }
    }
    
    // 回退到 docker-compose (v1)
    Command::new("docker-compose")
        .current_dir(compose_dir)
        .args(args)
        .output()
        .map_err(|_| AppError::InternalError)
}

// ============ 辅助函数 ============

fn ensure_docker_available() -> Result<(), AppError> {
    if !is_docker_available() {
        return Err(AppError::BadRequest("Docker is not available. Please install Docker first.".to_string()));
    }
    Ok(())
}

fn get_all_containers() -> Result<Vec<Container>, AppError> {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "{{json .}}"])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    let mut containers = Vec::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let status_str = json["State"].as_str().unwrap_or("unknown");
            let status = match status_str {
                "running" => ContainerStatus::Running,
                "paused" => ContainerStatus::Paused,
                "restarting" => ContainerStatus::Restarting,
                "exited" => ContainerStatus::Exited,
                "dead" => ContainerStatus::Dead,
                "created" => ContainerStatus::Created,
                _ => ContainerStatus::Unknown,
            };
            
            containers.push(Container {
                id: json["ID"].as_str().unwrap_or("").to_string(),
                name: json["Names"].as_str().unwrap_or("").to_string(),
                image: json["Image"].as_str().unwrap_or("").to_string(),
                image_id: "".to_string(),
                status,
                state: status_str.to_string(),
                created: json["CreatedAt"].as_str().unwrap_or("").to_string(),
                ports: parse_ports(json["Ports"].as_str().unwrap_or("")),
                volumes: Vec::new(),
                networks: Vec::new(),
                labels: HashMap::new(),
                cpu_usage: None,
                memory_usage: None,
                memory_limit: None,
            });
        }
    }
    
    Ok(containers)
}

fn get_container_details(container_id: &str) -> Result<Container, AppError> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{json .}}", container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;
    
    if !output.status.success() {
        return Err(AppError::NotFound("Container not found".to_string()));
    }
    
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| AppError::InternalError)?;
    
    let state = &json["State"];
    let config = &json["Config"];
    let network_settings = &json["NetworkSettings"];
    let host_config = &json["HostConfig"];
    
    let status = if state["Running"].as_bool().unwrap_or(false) {
        ContainerStatus::Running
    } else if state["Paused"].as_bool().unwrap_or(false) {
        ContainerStatus::Paused
    } else if state["Restarting"].as_bool().unwrap_or(false) {
        ContainerStatus::Restarting
    } else if state["Dead"].as_bool().unwrap_or(false) {
        ContainerStatus::Dead
    } else {
        ContainerStatus::Exited
    };
    
    // 解析端口
    let mut ports = Vec::new();
    if let Some(port_bindings) = network_settings["Ports"].as_object() {
        for (container_port, bindings) in port_bindings {
            if let Some(bindings) = bindings.as_array() {
                for binding in bindings {
                    let parts: Vec<&str> = container_port.split('/').collect();
                    ports.push(PortBinding {
                        container_port: parts[0].parse().unwrap_or(0),
                        host_port: binding["HostPort"].as_str().unwrap_or("0").parse().unwrap_or(0),
                        protocol: parts.get(1).unwrap_or(&"tcp").to_string(),
                        host_ip: binding["HostIp"].as_str().map(|s| s.to_string()),
                    });
                }
            }
        }
    }
    
    // 解析卷
    let mut volumes = Vec::new();
    if let Some(mounts) = json["Mounts"].as_array() {
        for mount in mounts {
            volumes.push(VolumeBinding {
                source: mount["Source"].as_str().unwrap_or("").to_string(),
                destination: mount["Destination"].as_str().unwrap_or("").to_string(),
                mode: mount["Mode"].as_str().unwrap_or("rw").to_string(),
            });
        }
    }
    
    // 解析标签
    let mut labels = HashMap::new();
    if let Some(label_obj) = config["Labels"].as_object() {
        for (key, value) in label_obj {
            labels.insert(key.clone(), value.as_str().unwrap_or("").to_string());
        }
    }
    
    Ok(Container {
        id: json["Id"].as_str().unwrap_or("").to_string(),
        name: json["Name"].as_str().unwrap_or("").trim_start_matches('/').to_string(),
        image: config["Image"].as_str().unwrap_or("").to_string(),
        image_id: json["Image"].as_str().unwrap_or("").to_string(),
        status,
        state: state["Status"].as_str().unwrap_or("unknown").to_string(),
        created: json["Created"].as_str().unwrap_or("").to_string(),
        ports,
        volumes,
        networks: Vec::new(),
        labels,
        cpu_usage: None,
        memory_usage: host_config["Memory"].as_u64(),
        memory_limit: host_config["Memory"].as_u64(),
    })
}

fn parse_ports(ports_str: &str) -> Vec<PortBinding> {
    let mut ports = Vec::new();
    
    for part in ports_str.split(", ") {
        // 格式: 0.0.0.0:8080->80/tcp
        if let Some((host_part, container_part)) = part.split_once("->") {
            let host_parts: Vec<&str> = host_part.split(':').collect();
            let container_parts: Vec<&str> = container_part.split('/').collect();
            
            if host_parts.len() >= 2 && !container_parts.is_empty() {
                ports.push(PortBinding {
                    container_port: container_parts[0].parse().unwrap_or(0),
                    host_port: host_parts.last().unwrap_or(&"0").parse().unwrap_or(0),
                    protocol: container_parts.get(1).unwrap_or(&"tcp").to_string(),
                    host_ip: if host_parts.len() > 1 { Some(host_parts[0].to_string()) } else { None },
                });
            }
        }
    }
    
    ports
}

fn parse_size_string(size_str: &str) -> u64 {
    let size_str = size_str.trim();
    
    if size_str.ends_with("GB") {
        let num: f64 = size_str.trim_end_matches("GB").trim().parse().unwrap_or(0.0);
        (num * 1024.0 * 1024.0 * 1024.0) as u64
    } else if size_str.ends_with("MB") {
        let num: f64 = size_str.trim_end_matches("MB").trim().parse().unwrap_or(0.0);
        (num * 1024.0 * 1024.0) as u64
    } else if size_str.ends_with("KB") {
        let num: f64 = size_str.trim_end_matches("KB").trim().parse().unwrap_or(0.0);
        (num * 1024.0) as u64
    } else {
        size_str.parse().unwrap_or(0)
    }
}

// ============ Docker 安装/卸载 ============

/// 安装 Docker
pub async fn install_docker() -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        info!("Installing Docker...");
        
        // 检测发行版
        let distro = detect_linux_distro();
        
        let result = match distro.as_str() {
            "debian" | "ubuntu" | "armbian" => install_docker_debian(),
            "centos" | "rhel" | "fedora" => install_docker_rhel(),
            "alpine" => install_docker_alpine(),
            _ => install_docker_generic(),
        };
        
        match result {
            Ok(_) => {
                info!("Docker installed successfully");
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Docker installed successfully"
                })))
            }
            Err(e) => Err(e),
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        Err(AppError::BadRequest("Please install Docker Desktop manually on Windows".to_string()))
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_distro() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if line.starts_with("ID=") {
                return line.trim_start_matches("ID=").trim_matches('"').to_lowercase();
            }
        }
    }
    "unknown".to_string()
}

#[cfg(target_os = "linux")]
fn install_docker_debian() -> Result<(), AppError> {
    // 更新包列表
    run_command("apt-get", &["update"])?;
    
    // 安装依赖
    run_command("apt-get", &["install", "-y", "ca-certificates", "curl", "gnupg"])?;
    
    // 添加 Docker GPG 密钥
    run_command("sh", &["-c", "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg"])?;
    
    // 添加 Docker 仓库
    let arch = std::env::consts::ARCH;
    let arch_str = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armhf",
        _ => "amd64",
    };
    
    let repo_line = format!(
        "deb [arch={} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable",
        arch_str
    );
    
    std::fs::write("/etc/apt/sources.list.d/docker.list", repo_line)
        .map_err(|e| AppError::IoError(e.to_string()))?;
    
    // 更新并安装 Docker
    run_command("apt-get", &["update"])?;
    run_command("apt-get", &["install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"])?;
    
    // 启动 Docker
    run_command("systemctl", &["enable", "docker"])?;
    run_command("systemctl", &["start", "docker"])?;
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_docker_rhel() -> Result<(), AppError> {
    run_command("yum", &["install", "-y", "yum-utils"])?;
    run_command("yum-config-manager", &["--add-repo", "https://download.docker.com/linux/centos/docker-ce.repo"])?;
    run_command("yum", &["install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"])?;
    run_command("systemctl", &["enable", "docker"])?;
    run_command("systemctl", &["start", "docker"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_docker_alpine() -> Result<(), AppError> {
    run_command("apk", &["add", "docker", "docker-compose"])?;
    run_command("rc-update", &["add", "docker", "boot"])?;
    run_command("service", &["docker", "start"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_docker_generic() -> Result<(), AppError> {
    // 使用官方安装脚本
    run_command("sh", &["-c", "curl -fsSL https://get.docker.com | sh"])?;
    run_command("systemctl", &["enable", "docker"])?;
    run_command("systemctl", &["start", "docker"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_command(cmd: &str, args: &[&str]) -> Result<(), AppError> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| AppError::BadRequest(format!("Failed to run {}: {}", cmd, e)))?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::BadRequest(format!("Command failed: {}", err)));
    }
    
    Ok(())
}

/// 卸载 Docker
pub async fn uninstall_docker() -> Result<HttpResponse, AppError> {
    #[cfg(target_os = "linux")]
    {
        info!("Uninstalling Docker...");
        
        // 停止所有容器
        let _ = Command::new("docker").args(["stop", "$(docker ps -aq)"]).output();
        
        // 删除所有容器
        let _ = Command::new("docker").args(["rm", "$(docker ps -aq)"]).output();
        
        // 停止 Docker 服务
        let _ = Command::new("systemctl").args(["stop", "docker"]).output();
        
        // 卸载 Docker 包
        let distro = detect_linux_distro();
        
        match distro.as_str() {
            "debian" | "ubuntu" | "armbian" => {
                let _ = Command::new("apt-get")
                    .args(["remove", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"])
                    .output();
                let _ = Command::new("apt-get").args(["autoremove", "-y"]).output();
            }
            "centos" | "rhel" | "fedora" => {
                let _ = Command::new("yum")
                    .args(["remove", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"])
                    .output();
            }
            "alpine" => {
                let _ = Command::new("apk").args(["del", "docker", "docker-compose"]).output();
            }
            _ => {}
        }
        
        info!("Docker uninstalled");
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Docker uninstalled successfully"
        })))
    }
    
    #[cfg(target_os = "windows")]
    {
        Err(AppError::BadRequest("Please uninstall Docker Desktop manually on Windows".to_string()))
    }
}
