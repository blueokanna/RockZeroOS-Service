use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::process::Command;
use tracing::{error, info};
use uuid::Uuid;
use validator::Validate;

use crate::db;
use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DockerApp {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub icon: String,
    pub category: String,
    pub docker_image: String,
    pub docker_tag: String,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMapping>,
    pub environment: Vec<EnvVar>,
    pub status: String,
    pub container_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VolumeMapping {
    pub container_path: String,
    pub host_path: String,
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
    pub required: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InstallAppRequest {
    #[validate(length(min = 1))]
    pub name: String,
    #[validate(length(min = 1))]
    pub docker_image: String,
    pub docker_tag: Option<String>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMapping>,
    pub environment: Vec<EnvVar>,
}

#[derive(Debug, Serialize)]
pub struct AppStoreItem {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub icon: String,
    pub category: String,
    pub docker_image: String,
    pub recommended_tag: String,
    pub default_ports: Vec<PortMapping>,
    pub default_volumes: Vec<VolumeMapping>,
    pub required_env: Vec<String>,
}

pub async fn list_store_apps() -> Result<impl Responder, AppError> {
    let apps = vec![
        AppStoreItem {
            id: "nextcloud".to_string(),
            name: "nextcloud".to_string(),
            display_name: "Nextcloud".to_string(),
            description: "Self-hosted cloud storage and collaboration platform".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/nextcloud.png".to_string(),
            category: "Cloud Storage".to_string(),
            docker_image: "nextcloud".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 80,
                host_port: 8080,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/var/www/html".to_string(),
                    host_path: "/DATA/AppData/nextcloud".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "jellyfin".to_string(),
            name: "jellyfin".to_string(),
            display_name: "Jellyfin".to_string(),
            description: "Free software media system".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/jellyfin.png".to_string(),
            category: "Media".to_string(),
            docker_image: "jellyfin/jellyfin".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 8096,
                host_port: 8096,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/config".to_string(),
                    host_path: "/DATA/AppData/jellyfin/config".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/media".to_string(),
                    host_path: "/DATA/Media".to_string(),
                    mode: "ro".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "portainer".to_string(),
            name: "portainer".to_string(),
            display_name: "Portainer".to_string(),
            description: "Docker container management UI".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/portainer.png".to_string(),
            category: "Management".to_string(),
            docker_image: "portainer/portainer-ce".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 9000,
                    host_port: 9000,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 8000,
                    host_port: 8000,
                    protocol: "tcp".to_string(),
                },
            ],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/data".to_string(),
                    host_path: "/DATA/AppData/portainer".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/var/run/docker.sock".to_string(),
                    host_path: "/var/run/docker.sock".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "homeassistant".to_string(),
            name: "homeassistant".to_string(),
            display_name: "Home Assistant".to_string(),
            description: "Open source home automation platform".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/home-assistant.png".to_string(),
            category: "Smart Home".to_string(),
            docker_image: "homeassistant/home-assistant".to_string(),
            recommended_tag: "stable".to_string(),
            default_ports: vec![PortMapping {
                container_port: 8123,
                host_port: 8123,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/config".to_string(),
                host_path: "/DATA/AppData/homeassistant".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
    ];

    Ok(HttpResponse::Ok().json(apps))
}

pub async fn list_installed_apps(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let apps = db::list_installed_apps(&pool, &claims.sub).await?;
    
    let mut enriched_apps = Vec::new();
    for mut app in apps {
        if let Some(container_id) = &app.container_id {
            let status = get_container_status(container_id).await;
            app.status = status;
        }
        enriched_apps.push(app);
    }

    Ok(HttpResponse::Ok().json(enriched_apps))
}

pub async fn install_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<InstallAppRequest>,
) -> Result<impl Responder, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let tag = body.docker_tag.clone().unwrap_or_else(|| "latest".to_string());
    let full_image = format!("{}:{}", body.docker_image, tag);

    info!("Pulling Docker image: {}", full_image);
    let pull_output = Command::new("docker")
        .args(&["pull", &full_image])
        .output()
        .map_err(|e| {
            error!("Failed to pull image: {}", e);
            AppError::InternalError
        })?;

    if !pull_output.status.success() {
        error!("Docker pull failed: {}", String::from_utf8_lossy(&pull_output.stderr));
        return Err(AppError::BadRequest("Failed to pull Docker image".to_string()));
    }

    let container_name = format!("rockzero-{}-{}", body.name, Uuid::new_v4().to_string()[..8].to_string());
    
    let mut docker_args = vec!["run", "-d", "--name", &container_name, "--restart", "unless-stopped"];

    let port_args: Vec<String> = body.ports.iter()
        .map(|p| format!("-p {}:{}/{}", p.host_port, p.container_port, p.protocol))
        .collect();
    for arg in &port_args {
        docker_args.push(arg);
    }

    let volume_args: Vec<String> = body.volumes.iter()
        .map(|v| format!("-v {}:{}:{}", v.host_path, v.container_path, v.mode))
        .collect();
    for arg in &volume_args {
        docker_args.push(arg);
    }

    let env_args: Vec<String> = body.environment.iter()
        .map(|e| format!("-e {}={}", e.key, e.value))
        .collect();
    for arg in &env_args {
        docker_args.push(arg);
    }

    docker_args.push(&full_image);

    info!("Starting container: {}", container_name);
    let run_output = Command::new("docker")
        .args(&docker_args)
        .output()
        .map_err(|e| {
            error!("Failed to start container: {}", e);
            AppError::InternalError
        })?;

    if !run_output.status.success() {
        error!("Docker run failed: {}", String::from_utf8_lossy(&run_output.stderr));
        return Err(AppError::BadRequest("Failed to start container".to_string()));
    }

    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    let app = DockerApp {
        id: Uuid::new_v4().to_string(),
        name: body.name.clone(),
        display_name: body.name.clone(),
        description: format!("Docker app: {}", body.docker_image),
        icon: "".to_string(),
        category: "Custom".to_string(),
        docker_image: body.docker_image.clone(),
        docker_tag: tag,
        ports: body.ports.clone(),
        volumes: body.volumes.clone(),
        environment: body.environment.clone(),
        status: "running".to_string(),
        container_id: Some(container_id.clone()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    db::create_installed_app(&pool, &app, &claims.sub).await?;

    info!("App installed: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Created().json(app))
}

pub async fn uninstall_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    if let Some(container_id) = &app.container_id {
        info!("Stopping container: {}", container_id);
        Command::new("docker")
            .args(&["stop", container_id])
            .output()
            .ok();

        info!("Removing container: {}", container_id);
        Command::new("docker")
            .args(&["rm", container_id])
            .output()
            .ok();
    }

    db::delete_installed_app(&pool, &app_id, &claims.sub).await?;

    info!("App uninstalled: {}", app.name);

    Ok(HttpResponse::NoContent().finish())
}

pub async fn start_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    let container_id = app.container_id
        .ok_or_else(|| AppError::BadRequest("No container ID".to_string()))?;

    let output = Command::new("docker")
        .args(&["start", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Failed to start container".to_string()));
    }

    info!("App started: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "started"})))
}

pub async fn stop_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    let container_id = app.container_id
        .ok_or_else(|| AppError::BadRequest("No container ID".to_string()))?;

    let output = Command::new("docker")
        .args(&["stop", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Failed to stop container".to_string()));
    }

    info!("App stopped: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "stopped"})))
}

pub async fn restart_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    let container_id = app.container_id
        .ok_or_else(|| AppError::BadRequest("No container ID".to_string()))?;

    let output = Command::new("docker")
        .args(&["restart", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Failed to restart container".to_string()));
    }

    info!("App restarted: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "restarted"})))
}

async fn get_container_status(container_id: &str) -> String {
    let output = Command::new("docker")
        .args(&["inspect", "--format", "{{.State.Status}}", container_id])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}
