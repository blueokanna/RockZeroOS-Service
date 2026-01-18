use rockzero_common::{AppError, FileMetadata, InviteCode, MediaItem, User, Widget};
use sqlx::sqlite::SqlitePool;

fn to_app_error(e: sqlx::Error) -> AppError {
    if e.to_string().contains("UNIQUE constraint failed") {
        AppError::Conflict("数据已存在".to_string())
    } else {
        AppError::DatabaseError(e.to_string())
    }
}

pub async fn run_migrations(pool: &SqlitePool) -> Result<(), AppError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_commitment TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            is_super_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_super_admin INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS invite_codes (
            id TEXT PRIMARY KEY NOT NULL,
            code TEXT NOT NULL UNIQUE,
            created_by TEXT NOT NULL,
            created_at_mono INTEGER NOT NULL,
            expires_at_mono INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_by TEXT,
            used_at TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS file_metadata (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            checksum TEXT NOT NULL,
            is_public INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS media_items (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            title TEXT NOT NULL,
            media_type TEXT NOT NULL,
            duration INTEGER,
            thumbnail_id TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (file_id) REFERENCES file_metadata(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS widgets (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            widget_type TEXT NOT NULL,
            title TEXT NOT NULL,
            config_json TEXT NOT NULL,
            position_x INTEGER NOT NULL,
            position_y INTEGER NOT NULL,
            width INTEGER NOT NULL,
            height INTEGER NOT NULL,
            is_visible INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes(code)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_file_metadata_user_id ON file_metadata(user_id)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_media_items_user_id ON media_items(user_id)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_widgets_user_id ON widgets(user_id)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS fido_credentials (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            credential_id BLOB NOT NULL,
            public_key BLOB NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS fido_sessions (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            session_type TEXT NOT NULL,
            state_json TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_fido_credentials_user_id ON fido_credentials(user_id)",
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_fido_sessions_user_id ON fido_sessions(user_id)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS installed_apps (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT NOT NULL,
            icon TEXT NOT NULL,
            category TEXT NOT NULL,
            docker_image TEXT NOT NULL,
            docker_tag TEXT NOT NULL,
            ports_json TEXT NOT NULL,
            volumes_json TEXT NOT NULL,
            environment_json TEXT NOT NULL,
            status TEXT NOT NULL,
            container_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_installed_apps_user_id ON installed_apps(user_id)")
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    Ok(())
}

// ============ 用户操作 ============

pub async fn create_user(pool: &SqlitePool, user: &User) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, password_commitment, role, is_active, is_super_admin, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&user.id)
    .bind(&user.username)
    .bind(&user.email)
    .bind(&user.password_hash)
    .bind(&user.password_commitment)
    .bind(&user.role)
    .bind(user.is_active)
    .bind(user.is_super_admin)
    .bind(user.created_at.to_rfc3339())
    .bind(user.updated_at.to_rfc3339())
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(())
}

pub async fn find_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, email, password_hash, password_commitment, role, is_active, is_super_admin,
               datetime(created_at) as created_at, datetime(updated_at) as updated_at
        FROM users WHERE email = ?
        "#,
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(to_app_error)?;

    Ok(user)
}

pub async fn find_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, email, password_hash, password_commitment, role, is_active, is_super_admin,
               datetime(created_at) as created_at, datetime(updated_at) as updated_at
        FROM users WHERE username = ?
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(to_app_error)?;

    Ok(user)
}

pub async fn find_user_by_id(pool: &SqlitePool, id: &str) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, email, password_hash, password_commitment, role, is_active, is_super_admin,
               datetime(created_at) as created_at, datetime(updated_at) as updated_at
        FROM users WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(to_app_error)?;

    Ok(user)
}

pub async fn count_users(pool: &SqlitePool) -> Result<i64, AppError> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(to_app_error)?;
    Ok(count.0)
}

// ============ 推荐码操作 ============

pub async fn create_invite_code(pool: &SqlitePool, invite: &InviteCode) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO invite_codes (id, code, created_by, created_at_mono, expires_at_mono, created_at, is_used, used_by, used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&invite.id)
    .bind(&invite.code)
    .bind(&invite.created_by)
    .bind(invite.created_at_mono)
    .bind(invite.expires_at_mono)
    .bind(invite.created_at.to_rfc3339())
    .bind(invite.is_used)
    .bind(&invite.used_by)
    .bind(invite.used_at.map(|t| t.to_rfc3339()))
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(())
}

pub async fn find_invite_code(
    pool: &SqlitePool,
    code: &str,
) -> Result<Option<InviteCode>, AppError> {
    let invite = sqlx::query_as::<_, InviteCode>(
        r#"
        SELECT id, code, created_by, created_at_mono, expires_at_mono, 
               datetime(created_at) as created_at, is_used, used_by, 
               datetime(used_at) as used_at
        FROM invite_codes WHERE code = ?
        "#,
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(to_app_error)?;

    Ok(invite)
}

pub async fn mark_invite_code_used(
    pool: &SqlitePool,
    code: &str,
    used_by: &str,
) -> Result<(), AppError> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        UPDATE invite_codes SET is_used = 1, used_by = ?, used_at = ?
        WHERE code = ?
        "#,
    )
    .bind(used_by)
    .bind(&now)
    .bind(code)
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(())
}

pub async fn get_latest_valid_invite(
    pool: &SqlitePool,
    created_by: &str,
) -> Result<Option<InviteCode>, AppError> {
    let invite = sqlx::query_as::<_, InviteCode>(
        r#"
        SELECT id, code, created_by, created_at_mono, expires_at_mono,
               datetime(created_at) as created_at, is_used, used_by,
               datetime(used_at) as used_at
        FROM invite_codes 
        WHERE created_by = ? AND is_used = 0
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(created_by)
    .fetch_optional(pool)
    .await
    .map_err(to_app_error)?;

    Ok(invite)
}

// ============ 文件操作 ============

pub async fn create_file_metadata(pool: &SqlitePool, file: &FileMetadata) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO file_metadata (id, user_id, filename, original_filename, file_path, mime_type, file_size, checksum, is_public, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&file.id)
    .bind(&file.user_id)
    .bind(&file.filename)
    .bind(&file.original_filename)
    .bind(&file.file_path)
    .bind(&file.mime_type)
    .bind(file.file_size)
    .bind(&file.checksum)
    .bind(file.is_public)
    .bind(file.created_at.to_rfc3339())
    .bind(file.updated_at.to_rfc3339())
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(())
}

pub async fn find_file_by_id(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<Option<FileMetadata>, AppError> {
    let file = sqlx::query_as::<_, FileMetadata>(
        r#"
        SELECT id, user_id, filename, original_filename, file_path, mime_type, file_size, checksum, is_public,
               datetime(created_at) as created_at, datetime(updated_at) as updated_at
        FROM file_metadata WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(to_app_error)?;

    Ok(file)
}

pub async fn list_files_by_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<FileMetadata>, AppError> {
    let files = sqlx::query_as::<_, FileMetadata>(
        r#"
        SELECT id, user_id, filename, original_filename, file_path, mime_type, file_size, checksum, is_public,
               datetime(created_at) as created_at, datetime(updated_at) as updated_at
        FROM file_metadata WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(to_app_error)?;

    Ok(files)
}

pub async fn delete_file_metadata(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let result = sqlx::query("DELETE FROM file_metadata WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    Ok(result.rows_affected() > 0)
}

// ============ 媒体操作 ============

pub async fn create_media_item(pool: &SqlitePool, media: &MediaItem) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO media_items (id, user_id, file_id, title, media_type, duration, thumbnail_id, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&media.id)
    .bind(&media.user_id)
    .bind(&media.file_id)
    .bind(&media.title)
    .bind(&media.media_type)
    .bind(media.duration)
    .bind(&media.thumbnail_id)
    .bind(&media.metadata_json)
    .bind(media.created_at.to_rfc3339())
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(())
}

pub async fn list_media_by_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<MediaItem>, AppError> {
    let items = sqlx::query_as::<_, MediaItem>(
        r#"
        SELECT id, user_id, file_id, title, media_type, duration, thumbnail_id, metadata_json,
               datetime(created_at) as created_at
        FROM media_items WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(to_app_error)?;

    Ok(items)
}

// ============ 小组件操作 ============

pub async fn create_widget(pool: &SqlitePool, widget: &Widget) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO widgets (id, user_id, widget_type, title, config_json, position_x, position_y, width, height, is_visible, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&widget.id)
    .bind(&widget.user_id)
    .bind(&widget.widget_type)
    .bind(&widget.title)
    .bind(&widget.config_json)
    .bind(widget.position_x)
    .bind(widget.position_y)
    .bind(widget.width)
    .bind(widget.height)
    .bind(widget.is_visible)
    .bind(widget.created_at.to_rfc3339())
    .bind(widget.updated_at.to_rfc3339())
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(())
}

pub async fn list_widgets_by_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<Widget>, AppError> {
    let widgets = sqlx::query_as::<_, Widget>(
        r#"
        SELECT id, user_id, widget_type, title, config_json, position_x, position_y, width, height, is_visible,
               datetime(created_at) as created_at, datetime(updated_at) as updated_at
        FROM widgets WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(to_app_error)?;

    Ok(widgets)
}

pub async fn update_widget(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    widget: &Widget,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        r#"
        UPDATE widgets SET title = ?, config_json = ?, position_x = ?, position_y = ?, 
                          width = ?, height = ?, is_visible = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&widget.title)
    .bind(&widget.config_json)
    .bind(widget.position_x)
    .bind(widget.position_y)
    .bind(widget.width)
    .bind(widget.height)
    .bind(widget.is_visible)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(to_app_error)?;

    Ok(result.rows_affected() > 0)
}

pub async fn delete_widget(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool, AppError> {
    let result = sqlx::query("DELETE FROM widgets WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(to_app_error)?;

    Ok(result.rows_affected() > 0)
}
