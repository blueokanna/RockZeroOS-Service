use actix_web::{HttpResponse, Responder};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    name: String,
    icon_url: String,
}

pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        name: "RockZero OS".to_string(),
        icon_url: "/api/v1/assets/logo".to_string(),
    })
}

/// 提供RockZero Logo图标
pub async fn serve_logo() -> impl Responder {
    // 尝试从根目录读取 RockZero.png
    let logo_paths = [
        "RockZero.png",
        "./RockZero.png",
        "/app/RockZero.png",
        "/opt/rockzero/RockZero.png",
    ];
    
    for path in logo_paths {
        if let Ok(data) = std::fs::read(path) {
            return HttpResponse::Ok()
                .content_type("image/png")
                .insert_header(("Cache-Control", "public, max-age=86400"))
                .body(data);
        }
    }
    
    // 如果找不到文件，返回404
    HttpResponse::NotFound().body("Logo not found")
}

/// 提供README.md内容
pub async fn serve_readme() -> impl Responder {
    let readme_paths = [
        "README.md",
        "./README.md",
        "/app/README.md",
        "/opt/rockzero/README.md",
    ];
    
    for path in readme_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return HttpResponse::Ok()
                .content_type("text/markdown; charset=utf-8")
                .insert_header(("Cache-Control", "public, max-age=3600"))
                .body(content);
        }
    }
    
    // 如果找不到文件，返回默认内容
    HttpResponse::Ok()
        .content_type("text/markdown; charset=utf-8")
        .body(r#"# RockZero OS

## Secure Private Cloud NAS Operating System

RockZero OS is a high-performance, secure cross-platform private cloud NAS operating system.

### Features

- Military-grade encryption (WPA3-SAE, EdDSA, Bulletproofs)
- Hardware-accelerated video transcoding
- Professional storage management
- Cross-platform Flutter client

For more information, visit [GitHub](https://github.com/blueokanna/rockzero-service).
"#)
}

/// 提供关于信息
#[derive(Serialize)]
struct AboutInfo {
    name: String,
    version: String,
    description: String,
    author: String,
    email: String,
    github: String,
    license: String,
    readme_url: String,
    logo_url: String,
}

pub async fn get_about() -> impl Responder {
    HttpResponse::Ok().json(AboutInfo {
        name: "RockZero OS".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "Secure Private Cloud NAS Operating System".to_string(),
        author: "blueokanna".to_string(),
        email: "blueokanna@gmail.com".to_string(),
        github: "https://github.com/blueokanna/rockzero-service".to_string(),
        license: "AGPL-3.0".to_string(),
        readme_url: "/api/v1/assets/readme".to_string(),
        logo_url: "/api/v1/assets/logo".to_string(),
    })
}
