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
        // 原始字节值
        hls_cache_size: stats.hls_cache_size,
        temp_storage_size: stats.temp_storage_size,
        log_size: stats.log_size,
        video_storage_size: stats.video_storage_size,
        database_size: stats.database_size,
        total_app_usage: stats.total_app_usage,
        available_space: stats.available_space,
        // 格式化值（兼容旧接口）
        hls_cache_size_mb: stats.hls_cache_size as f64 / 1024.0 / 1024.0,
        temp_storage_size_mb: stats.temp_storage_size as f64 / 1024.0 / 1024.0,
        log_size_mb: stats.log_size as f64 / 1024.0 / 1024.0,
        video_storage_size_mb: stats.video_storage_size as f64 / 1024.0 / 1024.0,
        database_size_mb: stats.database_size as f64 / 1024.0 / 1024.0,
        total_app_usage_mb: stats.total_app_usage as f64 / 1024.0 / 1024.0,
        available_space_gb: stats.available_space as f64 / 1024.0 / 1024.0 / 1024.0,
        // 兼容旧接口
        total_used_mb: stats.total_app_usage as f64 / 1024.0 / 1024.0,
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
    /// HLS 缓存大小（字节）
    pub hls_cache_size: u64,
    /// 临时文件大小（字节）
    pub temp_storage_size: u64,
    /// 日志文件大小（字节）
    pub log_size: u64,
    /// 视频存储大小（字节）
    pub video_storage_size: u64,
    /// 数据库文件大小（字节）
    pub database_size: u64,
    /// RockZeroOS 应用总占用（字节）
    pub total_app_usage: u64,
    /// 可用空间（字节）
    pub available_space: u64,
    
    // 格式化值（MB/GB）
    pub hls_cache_size_mb: f64,
    pub temp_storage_size_mb: f64,
    pub log_size_mb: f64,
    pub video_storage_size_mb: f64,
    pub database_size_mb: f64,
    pub total_app_usage_mb: f64,
    pub available_space_gb: f64,
    
    /// 兼容旧接口
    #[serde(rename = "total_used_mb")]
    pub total_used_mb: f64,
}
