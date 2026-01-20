use actix_web::{web, HttpResponse};
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::storage_manager::StorageManager;

/// 获取存储统计信息
pub async fn get_storage_stats(
    storage_manager: web::Data<Arc<StorageManager>>,
) -> Result<HttpResponse, AppError> {
    let stats = storage_manager.get_storage_stats().await;
    
    Ok(HttpResponse::Ok().json(StorageStatsResponse {
        hls_cache_size_mb: stats.hls_cache_size as f64 / 1024.0 / 1024.0,
        temp_storage_size_mb: stats.temp_storage_size as f64 / 1024.0 / 1024.0,
        log_size_mb: stats.log_size as f64 / 1024.0 / 1024.0,
        available_space_gb: stats.available_space as f64 / 1024.0 / 1024.0 / 1024.0,
        total_used_mb: (stats.hls_cache_size + stats.temp_storage_size + stats.log_size) as f64 / 1024.0 / 1024.0,
    }))
}

/// 手动触发清理
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

/// 清理 HLS 缓存
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

/// 清理临时文件
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

/// 检查存储空间
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
    pub hls_cache_size_mb: f64,
    pub temp_storage_size_mb: f64,
    pub log_size_mb: f64,
    pub available_space_gb: f64,
    pub total_used_mb: f64,
}
