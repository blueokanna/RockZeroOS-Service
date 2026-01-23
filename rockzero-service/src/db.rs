use rockzero_common::AppError;
use rockzero_common::models::{FileMetadata, Widget};
use sqlx::{SqlitePool, Row};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    /// SHA-256 hash of the plaintext password, used for SAE handshake
    /// This is stored separately from password_hash (which is bcrypt/argon2)
    pub sae_secret: Option<String>,
    pub zkp_registration: Option<String>,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Initialize database tables
pub async fn initialize_database(pool: &SqlitePool) -> Result<(), AppError> {
    // Users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            sae_secret TEXT,
            zkp_registration TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    // FIDO sessions table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS fido_sessions (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            session_type TEXT NOT NULL,
            state_json TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    // FIDO credentials table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS fido_credentials (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            credential_id BLOB NOT NULL,
            public_key BLOB NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    // Invite codes table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS invite_codes (
            code TEXT PRIMARY KEY NOT NULL,
            created_by TEXT,
            max_uses INTEGER NOT NULL DEFAULT 1,
            current_uses INTEGER NOT NULL DEFAULT 0,
            expires_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    // Files table for file metadata
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT 0,
            checksum TEXT NOT NULL,
            is_public INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    // Widgets table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS widgets (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            widget_type TEXT NOT NULL,
            title TEXT NOT NULL,
            config_json TEXT NOT NULL,
            position_x INTEGER NOT NULL DEFAULT 0,
            position_y INTEGER NOT NULL DEFAULT 0,
            width INTEGER NOT NULL DEFAULT 1,
            height INTEGER NOT NULL DEFAULT 1,
            is_visible INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    // 数据库迁移：为旧表添加 sae_secret 列（如果不存在）
    // SQLite 不支持 IF NOT EXISTS 语法用于 ADD COLUMN，所以我们需要先检查
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN sae_secret TEXT")
        .execute(pool)
        .await; // 忽略错误（列可能已存在）

    Ok(())
}

/// Create a new user
pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    email: &str,
    password_hash: &str,
    sae_secret: Option<&str>,
    zkp_registration: Option<&str>,
    role: &str,
) -> Result<User, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, sae_secret, zkp_registration, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(sae_secret)
    .bind(zkp_registration)
    .bind(role)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint failed") {
            AppError::BadRequest("Username or email already exists".to_string())
        } else {
            AppError::DatabaseError(e.to_string())
        }
    })?;

    Ok(User {
        id,
        username: username.to_string(),
        email: email.to_string(),
        password_hash: password_hash.to_string(),
        sae_secret: sae_secret.map(|s| s.to_string()),
        zkp_registration: zkp_registration.map(|s| s.to_string()),
        role: role.to_string(),
        created_at: now,
        updated_at: now,
    })
}

/// Find user by ID
pub async fn find_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT id, username, email, password_hash, sae_secret, zkp_registration, role, 
               created_at, updated_at
        FROM users WHERE id = ?
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    match row {
        Some(r) => {
            let user = User {
                id: r.try_get("id").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                username: r.try_get("username").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                email: r.try_get("email").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                password_hash: r.try_get("password_hash").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                sae_secret: r.try_get("sae_secret").ok(),
                zkp_registration: r.try_get("zkp_registration").ok(),
                role: r.try_get("role").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                created_at: r.try_get("created_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                updated_at: r.try_get("updated_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
            };
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

/// Find user by username
pub async fn find_user_by_username(pool: &SqlitePool, username: &str) -> Result<Option<User>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT id, username, email, password_hash, sae_secret, zkp_registration, role,
               created_at, updated_at
        FROM users WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    match row {
        Some(r) => {
            let user = User {
                id: r.try_get("id").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                username: r.try_get("username").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                email: r.try_get("email").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                password_hash: r.try_get("password_hash").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                sae_secret: r.try_get("sae_secret").ok(),
                zkp_registration: r.try_get("zkp_registration").ok(),
                role: r.try_get("role").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                created_at: r.try_get("created_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                updated_at: r.try_get("updated_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
            };
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

/// Find user by email
pub async fn find_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<User>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT id, username, email, password_hash, sae_secret, zkp_registration, role,
               created_at, updated_at
        FROM users WHERE email = ?
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    match row {
        Some(r) => {
            let user = User {
                id: r.try_get("id").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                username: r.try_get("username").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                email: r.try_get("email").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                password_hash: r.try_get("password_hash").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                sae_secret: r.try_get("sae_secret").ok(),
                zkp_registration: r.try_get("zkp_registration").ok(),
                role: r.try_get("role").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                created_at: r.try_get("created_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                updated_at: r.try_get("updated_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
            };
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

/// Count total number of users in the system
pub async fn count_users(pool: &SqlitePool) -> Result<i64, AppError> {
    let row = sqlx::query("SELECT COUNT(*) as count FROM users")
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    
    let count: i64 = row.try_get("count").unwrap_or(0);
    Ok(count)
}

/// Validate an invite code
pub async fn validate_invite_code(pool: &SqlitePool, code: &str) -> Result<bool, AppError> {
    let row = sqlx::query(
        r#"
        SELECT code, max_uses, current_uses, expires_at
        FROM invite_codes 
        WHERE code = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
        "#,
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    
    match row {
        Some(r) => {
            let max_uses: i32 = r.try_get("max_uses").unwrap_or(1);
            let current_uses: i32 = r.try_get("current_uses").unwrap_or(0);
            Ok(current_uses < max_uses)
        }
        None => Ok(false),
    }
}

/// Use an invite code (increment usage count)
pub async fn use_invite_code(pool: &SqlitePool, code: &str) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE invite_codes SET current_uses = current_uses + 1
        WHERE code = ?
        "#,
    )
    .bind(code)
    .execute(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    
    Ok(())
}


pub async fn create_file_metadata(
    _pool: &SqlitePool,
    _metadata: &FileMetadata,
) -> Result<(), AppError> {
    // Placeholder - implement when database tables are created
    Ok(())
}

pub async fn list_files_by_user(
    _pool: &SqlitePool,
    _user_id: &str,
) -> Result<Vec<FileMetadata>, AppError> {
    // Placeholder - implement when database tables are created
    Ok(Vec::new())
}

pub async fn get_file_by_id(
    _pool: &SqlitePool,
    _file_id: &str,
) -> Result<Option<FileMetadata>, AppError> {
    // Placeholder - implement when database tables are created
    Ok(None)
}

/// Find file by ID and verify user ownership
pub async fn find_file_by_id(
    pool: &SqlitePool,
    file_id: &str,
    user_id: &str,
) -> Result<Option<FileMetadata>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT id, user_id, filename, original_filename, file_path, mime_type, file_size, checksum, is_public, created_at, updated_at
        FROM files 
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    match row {
        Some(r) => {
            let file = FileMetadata {
                id: r.try_get("id").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                user_id: r.try_get("user_id").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                filename: r.try_get("filename").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                original_filename: r.try_get("original_filename").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                file_path: r.try_get("file_path").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                mime_type: r.try_get("mime_type").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                file_size: r.try_get("file_size").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                checksum: r.try_get("checksum").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                is_public: r.try_get("is_public").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                created_at: r.try_get("created_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
                updated_at: r.try_get("updated_at").map_err(|e| AppError::DatabaseError(e.to_string()))?,
            };
            Ok(Some(file))
        }
        None => Ok(None),
    }
}

pub async fn delete_file(_pool: &SqlitePool, _file_id: &str) -> Result<(), AppError> {
    // Placeholder - implement when database tables are created
    Ok(())
}

pub async fn create_widget(_pool: &SqlitePool, _widget: &Widget) -> Result<(), AppError> {
    // Placeholder - implement when database tables are created
    Ok(())
}

pub async fn list_widgets_by_user(
    _pool: &SqlitePool,
    _user_id: &str,
) -> Result<Vec<Widget>, AppError> {
    // Placeholder - implement when database tables are created
    Ok(Vec::new())
}

pub async fn update_widget(
    _pool: &SqlitePool,
    _widget_id: &str,
    _user_id: &str,
    _widget: &Widget,
) -> Result<(), AppError> {
    // Placeholder - implement when database tables are created
    Ok(())
}

pub async fn delete_widget(
    _pool: &SqlitePool,
    _widget_id: &str,
    _user_id: &str,
) -> Result<bool, AppError> {
    // Placeholder - implement when database tables are created
    Ok(true)
}
