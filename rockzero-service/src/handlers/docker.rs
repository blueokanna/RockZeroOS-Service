use actix_web::{web, HttpRequest, HttpResponse};
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DockerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: String,
    pub created: String,
}

#[allow(dead_code)]
pub async fn list_images(req: HttpRequest) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["images", "--format", "{{json .}}"])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to list images".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let images: Vec<DockerImage> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(HttpResponse::Ok().json(images))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().json(Vec::<DockerImage>::new()))
    }
}

#[allow(dead_code)]
pub async fn list_containers(req: HttpRequest) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["ps", "-a", "--format", "{{json .}}"])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::BadRequest("Failed to list containers".to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let containers: Vec<DockerContainer> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(HttpResponse::Ok().json(containers))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().json(Vec::<DockerContainer>::new()))
    }
}

#[allow(dead_code)]
pub async fn inspect_container(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let _container_id = path.into_inner();

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["inspect", &_container_id])
            .output()
            .map_err(|_| AppError::InternalError)?;

        if !output.status.success() {
            return Err(AppError::NotFound("Container not found".to_string()));
        }

        let inspect_json: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| AppError::InternalError)?;

        Ok(HttpResponse::Ok().json(inspect_json))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}

#[allow(dead_code)]
pub async fn prune_system(req: HttpRequest) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("docker")
            .args(&["system", "prune", "-af", "--volumes"])
            .output()
            .map_err(|_| AppError::InternalError)?;

        let result = String::from_utf8_lossy(&output.stdout).to_string();

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "pruned",
            "result": result,
        })))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(HttpResponse::NotImplemented().finish())
    }
}
