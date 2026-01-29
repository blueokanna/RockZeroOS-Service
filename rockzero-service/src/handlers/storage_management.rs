use actix_web::{web, HttpResponse};
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::storage_manager::StorageManager;

pub async fn get_storage_stats(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    let stats = storage_manager.get_storage_stats().await;
    
    Ok(HttpResponse::Ok().json(StorageStatsResponse {
        hls_cache_size: stats.hls_cache_size,
        temp_storage_size: stats.temp_storage_size,
        log_size: stats.log_size,
        video_storage_size: stats.video_storage_size,
        database_size: stats.database_size,
        total_app_usage: stats.total_app_usage,
        available_space: stats.available_space,
        hls_cache_size_mb: stats.hls_cache_size as f64 / 1024.0 / 1024.0,
        temp_storage_size_mb: stats.temp_storage_size as f64 / 1024.0 / 1024.0,
        log_size_mb: stats.log_size as f64 / 1024.0 / 1024.0,
        video_storage_size_mb: stats.video_storage_size as f64 / 1024.0 / 1024.0,
        database_size_mb: stats.database_size as f64 / 1024.0 / 1024.0,
        total_app_usage_mb: stats.total_app_usage as f64 / 1024.0 / 1024.0,
        available_space_gb: stats.available_space as f64 / 1024.0 / 1024.0 / 1024.0,
        total_used_mb: stats.total_app_usage as f64 / 1024.0 / 1024.0,
    }))
}

pub async fn trigger_cleanup(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    info!("Manual cleanup triggered");
    
    storage_manager
        .run_cleanup()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Cleanup failed: {}", e)))?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Cleanup completed successfully"
    })))
}

pub async fn cleanup_hls_cache(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    info!("Manual HLS cache cleanup triggered");
    
    storage_manager
        .cleanup_hls_cache()
        .await
        .map_err(|e| AppError::InternalServerError(format!("HLS cache cleanup failed: {}", e)))?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "HLS cache cleaned successfully"
    })))
}

pub async fn cleanup_temp_files(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    info!("Manual temp files cleanup triggered");
    
    storage_manager
        .cleanup_temp_files()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Temp files cleanup failed: {}", e)))?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Temporary files cleaned successfully"
    })))
}

pub async fn check_storage_space(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    storage_manager
        .check_storage_space()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Storage check failed: {}", e)))?;
    
    let stats = storage_manager.get_storage_stats().await;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "available_space_gb": stats.available_space as f64 / 1024.0 / 1024.0 / 1024.0,
        "message": "Storage space checked successfully"
    })))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageStatsResponse {
    pub hls_cache_size: u64,
    pub temp_storage_size: u64,
    pub log_size: u64,
    pub video_storage_size: u64,
    pub database_size: u64,
    pub total_app_usage: u64,
    pub available_space: u64,
    pub hls_cache_size_mb: f64,
    pub temp_storage_size_mb: f64,
    pub log_size_mb: f64,
    pub video_storage_size_mb: f64,
    pub database_size_mb: f64,
    pub total_app_usage_mb: f64,
    pub available_space_gb: f64,
    #[serde(rename = "total_used_mb")]
    pub total_used_mb: f64,
}

#[derive(Debug, Deserialize)]
pub struct AccurateDiskUsageRequest {
    pub mount_point: String,
}

#[derive(Debug, Serialize)]
pub struct AccurateDiskUsageResponse {
    pub total_space: u64,
    pub available_space: u64,
    pub used_space: u64,
    pub cache_size: u64,
    pub actual_user_data: u64,
    pub usage_percentage: f64,
    pub total_space_gb: f64,
    pub available_space_gb: f64,
    pub used_space_gb: f64,
    pub cache_size_mb: f64,
    pub actual_user_data_gb: f64,
}

pub async fn get_accurate_disk_usage(
    storage_manager: web::Data<Arc<StorageManager>>,
    body: web::Json<AccurateDiskUsageRequest>,
) -> Result<HttpResponse, AppError> {
    let mount_point = PathBuf::from(&body.mount_point);
    
    if !mount_point.exists() {
        return Err(AppError::NotFound(format!(
            "Mount point not found: {}",
            body.mount_point
        )));
    }
    
    let usage = storage_manager
        .get_accurate_disk_usage(&mount_point)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Failed to get disk usage: {}", e)))?;
    
    info!(
        "Accurate disk usage - mount: {}, total: {:.2} GB, used: {:.2} GB, cache: {:.2} MB, user data: {:.2} GB",
        body.mount_point,
        usage.total_space as f64 / 1024.0 / 1024.0 / 1024.0,
        usage.used_space as f64 / 1024.0 / 1024.0 / 1024.0,
        usage.cache_size as f64 / 1024.0 / 1024.0,
        usage.actual_user_data as f64 / 1024.0 / 1024.0 / 1024.0
    );
    
    Ok(HttpResponse::Ok().json(AccurateDiskUsageResponse {
        total_space: usage.total_space,
        available_space: usage.available_space,
        used_space: usage.used_space,
        cache_size: usage.cache_size,
        actual_user_data: usage.actual_user_data,
        usage_percentage: usage.usage_percentage,
        total_space_gb: usage.total_space as f64 / 1024.0 / 1024.0 / 1024.0,
        available_space_gb: usage.available_space as f64 / 1024.0 / 1024.0 / 1024.0,
        used_space_gb: usage.used_space as f64 / 1024.0 / 1024.0 / 1024.0,
        cache_size_mb: usage.cache_size as f64 / 1024.0 / 1024.0,
        actual_user_data_gb: usage.actual_user_data as f64 / 1024.0 / 1024.0 / 1024.0,
    }))
}

pub async fn force_cleanup_all_cache(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    info!("Force cleanup all cache...");
    
    let cleaned_bytes = storage_manager
        .force_cleanup_all_cache()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Cache cleanup failed: {}", e)))?;
    
    let cleaned_mb = cleaned_bytes as f64 / 1024.0 / 1024.0;
    
    info!("Cache cleanup completed, freed {:.2} MB", cleaned_mb);
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("Cache cleanup completed, freed {:.2} MB", cleaned_mb),
        "cleaned_bytes": cleaned_bytes,
        "cleaned_mb": cleaned_mb
    })))
}
