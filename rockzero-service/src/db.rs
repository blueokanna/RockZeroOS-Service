//! Database operations bridge module

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
    pub zkp_commitment: String,
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
            zkp_commitment TEXT NOT NULL,
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

    Ok(())
}

/// Create a new user
pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    email: &str,
    password_hash: &str,
    zkp_commitment: &str,
    role: &str,
) -> Result<User, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, zkp_commitment, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(zkp_commitment)
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
        zkp_commitment: zkp_commitment.to_string(),
        role: role.to_string(),
        created_at: now,
        updated_at: now,
    })
}

/// Find user by ID
pub async fn find_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT id, username, email, password_hash, zkp_commitment, role, 
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
                zkp_commitment: r.try_get("zkp_commitment").map_err(|e| AppError::DatabaseError(e.to_string()))?,
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
        SELECT id, username, email, password_hash, zkp_commitment, role,
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
                zkp_commitment: r.try_get("zkp_commitment").map_err(|e| AppError::DatabaseError(e.to_string()))?,
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
        SELECT id, username, email, password_hash, zkp_commitment, role,
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
                zkp_commitment: r.try_get("zkp_commitment").map_err(|e| AppError::DatabaseError(e.to_string()))?,
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
    _pool: &SqlitePool,
    _file_id: &str,
    _user_id: &str,
) -> Result<Option<FileMetadata>, AppError> {
    // Placeholder - implement when database tables are created
    // This should query the database for a file with matching id and user_id
    Ok(None)
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
