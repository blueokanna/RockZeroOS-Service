use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::error::AppError;

const WEBDAV_BASE: &str = "./webdav";

#[derive(Debug, Serialize)]
pub struct PropfindResponse {
    pub href: String,
    pub display_name: String,
    pub is_collection: bool,
    pub content_length: u64,
    pub content_type: String,
    pub last_modified: String,
    pub creation_date: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LockRequest {
    pub path: String,
    pub timeout: Option<u64>,
}

/// WebDAV OPTIONS - 返回支持的方法
pub async fn webdav_options() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("DAV", "1, 2"))
        .insert_header(("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"))
        .insert_header(("MS-Author-Via", "DAV"))
        .finish()
}

/// WebDAV PROPFIND - 获取资源属性
pub async fn webdav_propfind(
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    let full_path = get_webdav_path(&requested_path)?;

    let depth = req
        .headers()
        .get("Depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("1");

    let mut responses = Vec::new();

    if full_path.exists() {
        responses.push(get_prop_response(&full_path, &requested_path)?);

        if full_path.is_dir() && depth != "0" {
            if let Ok(entries) = fs::read_dir(&full_path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    let relative_path = if requested_path.is_empty() {
                        entry.file_name().to_string_lossy().to_string()
                    } else {
                        format!("{}/{}", requested_path, entry.file_name().to_string_lossy())
                    };
                    if let Ok(prop) = get_prop_response(&entry_path, &relative_path) {
                        responses.push(prop);
                    }
                }
            }
        }
    } else {
        return Err(AppError::NotFound("Resource not found".to_string()));
    }

    // 生成 WebDAV XML 响应
    let xml = generate_multistatus_xml(&responses);

    Ok(HttpResponse::MultiStatus()
        .content_type("application/xml; charset=utf-8")
        .body(xml))
}


/// WebDAV GET - 下载文件
pub async fn webdav_get(path: web::Path<String>) -> Result<actix_files::NamedFile, AppError> {
    let requested_path = path.into_inner();
    let full_path = get_webdav_path(&requested_path)?;

    if !full_path.exists() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    if full_path.is_dir() {
        return Err(AppError::BadRequest("Cannot GET a directory".to_string()));
    }

    actix_files::NamedFile::open(&full_path).map_err(|_| AppError::InternalError)
}

/// WebDAV HEAD - 获取文件元信息
pub async fn webdav_head(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    let full_path = get_webdav_path(&requested_path)?;

    if !full_path.exists() {
        return Err(AppError::NotFound("File not found".to_string()));
    }

    let metadata = fs::metadata(&full_path).map_err(|_| AppError::InternalError)?;
    let content_type = mime_guess::from_path(&full_path)
        .first_or_octet_stream()
        .to_string();

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", content_type))
        .insert_header(("Content-Length", metadata.len().to_string()))
        .finish())
}

/// WebDAV PUT - 上传/更新文件
pub async fn webdav_put(
    path: web::Path<String>,
    body: web::Bytes,
) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    let full_path = get_webdav_path(&requested_path)?;

    // 确保父目录存在
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).map_err(|_| AppError::InternalError)?;
    }

    let is_new = !full_path.exists();

    let mut file = File::create(&full_path).map_err(|_| AppError::InternalError)?;
    file.write_all(&body).map_err(|_| AppError::InternalError)?;

    info!("WebDAV PUT: {}", requested_path);

    if is_new {
        Ok(HttpResponse::Created().finish())
    } else {
        Ok(HttpResponse::NoContent().finish())
    }
}

/// WebDAV DELETE - 删除文件或目录
pub async fn webdav_delete(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    let full_path = get_webdav_path(&requested_path)?;

    if !full_path.exists() {
        return Err(AppError::NotFound("Resource not found".to_string()));
    }

    if full_path.is_dir() {
        fs::remove_dir_all(&full_path).map_err(|_| AppError::InternalError)?;
    } else {
        fs::remove_file(&full_path).map_err(|_| AppError::InternalError)?;
    }

    info!("WebDAV DELETE: {}", requested_path);

    Ok(HttpResponse::NoContent().finish())
}

/// WebDAV MKCOL - 创建目录
pub async fn webdav_mkcol(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    let full_path = get_webdav_path(&requested_path)?;

    if full_path.exists() {
        return Err(AppError::Conflict("Resource already exists".to_string()));
    }

    // 检查父目录是否存在
    if let Some(parent) = full_path.parent() {
        if !parent.exists() {
            return Err(AppError::Conflict("Parent directory does not exist".to_string()));
        }
    }

    fs::create_dir(&full_path).map_err(|_| AppError::InternalError)?;

    info!("WebDAV MKCOL: {}", requested_path);

    Ok(HttpResponse::Created().finish())
}

/// WebDAV COPY - 复制文件或目录
pub async fn webdav_copy(
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let source_path = path.into_inner();
    let source_full = get_webdav_path(&source_path)?;

    let destination = req
        .headers()
        .get("Destination")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing Destination header".to_string()))?;

    let dest_path = extract_path_from_uri(destination);
    let dest_full = get_webdav_path(&dest_path)?;

    let overwrite = req
        .headers()
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("T")
        == "T";

    if !source_full.exists() {
        return Err(AppError::NotFound("Source not found".to_string()));
    }

    let existed = dest_full.exists();
    if existed && !overwrite {
        return Err(AppError::PreconditionFailed("Destination exists".to_string()));
    }

    if source_full.is_dir() {
        copy_dir_recursive(&source_full, &dest_full)?;
    } else {
        if let Some(parent) = dest_full.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::copy(&source_full, &dest_full).map_err(|_| AppError::InternalError)?;
    }

    info!("WebDAV COPY: {} -> {}", source_path, dest_path);

    if existed {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Ok(HttpResponse::Created().finish())
    }
}


/// WebDAV MOVE - 移动文件或目录
pub async fn webdav_move(
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let source_path = path.into_inner();
    let source_full = get_webdav_path(&source_path)?;

    let destination = req
        .headers()
        .get("Destination")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing Destination header".to_string()))?;

    let dest_path = extract_path_from_uri(destination);
    let dest_full = get_webdav_path(&dest_path)?;

    let overwrite = req
        .headers()
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("T")
        == "T";

    if !source_full.exists() {
        return Err(AppError::NotFound("Source not found".to_string()));
    }

    let existed = dest_full.exists();
    if existed && !overwrite {
        return Err(AppError::PreconditionFailed("Destination exists".to_string()));
    }

    if existed {
        if dest_full.is_dir() {
            fs::remove_dir_all(&dest_full).ok();
        } else {
            fs::remove_file(&dest_full).ok();
        }
    }

    if let Some(parent) = dest_full.parent() {
        fs::create_dir_all(parent).ok();
    }

    fs::rename(&source_full, &dest_full).map_err(|_| AppError::InternalError)?;

    info!("WebDAV MOVE: {} -> {}", source_path, dest_path);

    if existed {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Ok(HttpResponse::Created().finish())
    }
}

/// WebDAV LOCK - 锁定资源 (简化实现)
pub async fn webdav_lock(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    let lock_token = format!("opaquelocktoken:{}", uuid::Uuid::new_v4());

    info!("WebDAV LOCK: {}", requested_path);

    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>infinity</D:depth>
      <D:owner><D:href>rockzero</D:href></D:owner>
      <D:timeout>Second-3600</D:timeout>
      <D:locktoken><D:href>{}</D:href></D:locktoken>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>"#,
        lock_token
    );

    Ok(HttpResponse::Ok()
        .insert_header(("Lock-Token", format!("<{}>", lock_token)))
        .content_type("application/xml; charset=utf-8")
        .body(xml))
}

/// WebDAV UNLOCK - 解锁资源
pub async fn webdav_unlock(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    info!("WebDAV UNLOCK: {}", requested_path);
    Ok(HttpResponse::NoContent().finish())
}

/// WebDAV PROPPATCH - 修改属性 (简化实现)
pub async fn webdav_proppatch(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let requested_path = path.into_inner();
    info!("WebDAV PROPPATCH: {}", requested_path);

    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:propstat>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;

    Ok(HttpResponse::MultiStatus()
        .content_type("application/xml; charset=utf-8")
        .body(xml))
}

// 辅助函数

fn get_webdav_path(path: &str) -> Result<PathBuf, AppError> {
    let base = Path::new(WEBDAV_BASE);
    fs::create_dir_all(base).ok();

    let clean_path = path.trim_start_matches('/');
    let full_path = if clean_path.is_empty() {
        base.to_path_buf()
    } else {
        base.join(clean_path)
    };

    // 防止路径遍历攻击
    let canonical = full_path
        .canonicalize()
        .unwrap_or_else(|_| full_path.clone());

    let base_canonical = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());

    if !canonical.starts_with(&base_canonical) && canonical != full_path {
        return Err(AppError::Forbidden("Path traversal detected".to_string()));
    }

    Ok(full_path)
}

fn get_prop_response(path: &Path, href: &str) -> Result<PropfindResponse, AppError> {
    let metadata = fs::metadata(path).map_err(|_| AppError::InternalError)?;
    let is_collection = metadata.is_dir();

    let content_type = if is_collection {
        "httpd/unix-directory".to_string()
    } else {
        mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string()
    };

    let modified = metadata
        .modified()
        .ok()
        .map(|t| {
            chrono::DateTime::<chrono::Utc>::from(t)
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string()
        })
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());

    let created = metadata
        .created()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let display_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string());

    Ok(PropfindResponse {
        href: format!("/webdav/{}", href.trim_start_matches('/')),
        display_name,
        is_collection,
        content_length: if is_collection { 0 } else { metadata.len() },
        content_type,
        last_modified: modified,
        creation_date: created,
    })
}

fn generate_multistatus_xml(responses: &[PropfindResponse]) -> String {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">"#);

    for resp in responses {
        let resource_type = if resp.is_collection {
            "<D:collection/>"
        } else {
            ""
        };

        xml.push_str(&format!(
            r#"
  <D:response>
    <D:href>{}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>{}</D:displayname>
        <D:resourcetype>{}</D:resourcetype>
        <D:getcontentlength>{}</D:getcontentlength>
        <D:getcontenttype>{}</D:getcontenttype>
        <D:getlastmodified>{}</D:getlastmodified>
        <D:creationdate>{}</D:creationdate>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>"#,
            resp.href,
            resp.display_name,
            resource_type,
            resp.content_length,
            resp.content_type,
            resp.last_modified,
            resp.creation_date
        ));
    }

    xml.push_str("\n</D:multistatus>");
    xml
}

fn extract_path_from_uri(uri: &str) -> String {
    // 从完整 URI 中提取路径部分
    if let Some(pos) = uri.find("/webdav/") {
        uri[pos + 8..].to_string()
    } else if let Some(pos) = uri.find("/webdav") {
        uri[pos + 7..].trim_start_matches('/').to_string()
    } else {
        uri.trim_start_matches('/').to_string()
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), AppError> {
    fs::create_dir_all(dst).map_err(|_| AppError::InternalError)?;

    for entry in fs::read_dir(src).map_err(|_| AppError::InternalError)? {
        let entry = entry.map_err(|_| AppError::InternalError)?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|_| AppError::InternalError)?;
        }
    }

    Ok(())
}
