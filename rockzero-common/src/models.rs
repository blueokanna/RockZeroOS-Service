use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[cfg(feature = "db")]
use sqlx::FromRow;

// ============ 用户模型 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(FromRow))]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(skip_serializing)]
    pub password_commitment: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub is_super_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(
        username: String,
        email: String,
        password_hash: String,
        password_commitment: String,
        is_super_admin: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            email,
            password_hash,
            password_commitment: Some(password_commitment),
            role: if is_super_admin { "admin".to_string() } else { "user".to_string() },
            is_active: true,
            is_super_admin,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
        }
    }
}

// ============ 推荐码模型 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(FromRow))]
pub struct InviteCode {
    pub id: String,
    pub code: String,
    pub created_by: String,
    pub created_at_mono: i64,
    pub expires_at_mono: i64,
    pub created_at: DateTime<Utc>,
    pub is_used: bool,
    pub used_by: Option<String>,
    pub used_at: Option<DateTime<Utc>>,
}

// ============ 认证请求/响应 ============

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 50, message = "用户名长度必须在3-50字符之间"))]
    pub username: String,
    #[validate(email(message = "无效的邮箱格式"))]
    pub email: String,
    #[validate(length(min = 12, max = 128, message = "密码长度必须在12-128字符之间"))]
    pub password: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "无效的邮箱格式"))]
    pub email: String,
    #[validate(length(min = 1, message = "密码不能为空"))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub tokens: TokenResponse,
}

#[derive(Debug, Serialize)]
pub struct InviteCodeResponse {
    pub code: String,
    pub expires_in_seconds: i64,
}

// ============ 文件管理模型 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(FromRow))]
pub struct FileMetadata {
    pub id: String,
    pub user_id: String,
    pub filename: String,
    pub original_filename: String,
    pub file_path: String,
    pub mime_type: String,
    pub file_size: i64,
    pub checksum: String,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub file_size: i64,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub download_url: String,
}

#[derive(Debug, Serialize)]
pub struct FileListResponse {
    pub files: Vec<FileResponse>,
    pub total: i64,
}

// ============ 媒体播放模型 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(FromRow))]
pub struct MediaItem {
    pub id: String,
    pub user_id: String,
    pub file_id: String,
    pub title: String,
    pub media_type: String,
    pub duration: Option<i64>,
    pub thumbnail_id: Option<String>,
    pub metadata_json: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct MediaResponse {
    pub id: String,
    pub title: String,
    pub media_type: String,
    pub duration: Option<i64>,
    pub file_url: String,
    pub thumbnail_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============ 小组件模型 ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(FromRow))]
pub struct Widget {
    pub id: String,
    pub user_id: String,
    pub widget_type: String,
    pub title: String,
    pub config_json: String,
    pub position_x: i32,
    pub position_y: i32,
    pub width: i32,
    pub height: i32,
    pub is_visible: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateWidgetRequest {
    #[validate(length(min = 1, max = 50))]
    pub widget_type: String,
    #[validate(length(min = 1, max = 100))]
    pub title: String,
    pub config: serde_json::Value,
    pub position_x: i32,
    pub position_y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWidgetRequest {
    pub title: Option<String>,
    pub config: Option<serde_json::Value>,
    pub position_x: Option<i32>,
    pub position_y: Option<i32>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub is_visible: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct WidgetResponse {
    pub id: String,
    pub widget_type: String,
    pub title: String,
    pub config: serde_json::Value,
    pub position_x: i32,
    pub position_y: i32,
    pub width: i32,
    pub height: i32,
    pub is_visible: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
