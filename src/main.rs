mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod fido;
mod handlers;
mod hardware;
mod invite;
mod media_processor;
mod middleware;
mod models;
mod tls;
mod zkp;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AppConfig;
use crate::crypto::CryptoContext;
use crate::fido::FidoManager;
use crate::invite::InviteCodeManager;
use crate::media_processor::MediaProcessor;
use crate::zkp::ZkpContext;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,actix_web=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env();
    info!("Starting RockZero Secure Service...");
    info!("Listening on: {}:{}", config.host, config.port);
    info!("TLS Status: {}", if config.tls_enabled { "Enabled" } else { "Disabled" });
    info!("Zero-Knowledge Proof: Enabled");
    info!("Invite Code System: Monotonic Clock Anti-Tampering");

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to database");

    db::run_migrations(&pool).await.expect("Database migration failed");
    info!("Database initialized successfully");

    let crypto_ctx = Arc::new(CryptoContext::new(&config.encryption_key));
    let zkp_ctx = Arc::new(ZkpContext::new());
    let invite_manager = Arc::new(InviteCodeManager::new());
    
    let fido_manager = Arc::new(
        FidoManager::new(&config.host, &format!("https://{}:{}", config.host, config.port))
            .expect("Failed to initialize FIDO2 manager")
    );
    
    let media_processor = Arc::new(MediaProcessor::new());
    if media_processor.is_available() {
        info!("FFmpeg available - Media processing enabled");
        let hw_caps = media_processor.detect_hardware_capabilities();
        info!("Hardware acceleration: {:?}", hw_caps);
    } else {
        info!("FFmpeg not available - Media processing disabled");
    }
    
    let hardware_info = hardware::detect_hardware();
    info!("Hardware detected: {} - {} cores - {} GB RAM", 
        hardware_info.architecture, 
        hardware_info.cpu_cores,
        hardware_info.total_memory / 1024 / 1024 / 1024
    );
    
    info!("Security modules initialized successfully");

    let pool_data = web::Data::new(pool);
    let crypto_data = web::Data::new(crypto_ctx);
    let zkp_data = web::Data::new(zkp_ctx);
    let invite_data = web::Data::new(invite_manager);
    let fido_data = web::Data::new(fido_manager);
    let media_data = web::Data::new(media_processor);
    let config_data = web::Data::new(config.clone());

    let bind_addr = format!("{}:{}", config.host, config.port);

    info!("Service ready, waiting for connections...");

    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                let origin_str = origin.to_str().unwrap_or("");
                origin_str.starts_with("http://localhost")
                    || origin_str.starts_with("https://localhost")
                    || origin_str.starts_with("http://127.0.0.1")
                    || origin_str.starts_with("https://127.0.0.1")
                    || origin_str.starts_with("http://100.")
                    || origin_str.starts_with("https://100.")
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::ACCEPT,
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(pool_data.clone())
            .app_data(crypto_data.clone())
            .app_data(zkp_data.clone())
            .app_data(invite_data.clone())
            .app_data(fido_data.clone())
            .app_data(media_data.clone())
            .app_data(config_data.clone())
            .wrap(Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(handlers::health::health_check))
            .service(
                web::scope("/api/v1/auth")
                    .route("/register", web::post().to(handlers::auth::register))
                    .route("/login", web::post().to(handlers::auth::login))
                    .route("/login/zkp", web::post().to(handlers::auth::login_zkp))
                    .route("/refresh", web::post().to(handlers::auth::refresh_token))
                    .service(
                        web::scope("")
                            .wrap(middleware::JwtAuth)
                            .route("/invite", web::post().to(handlers::auth::generate_invite_code)),
                    ),
            )
            .service(
                web::scope("/api/v1/fido")
                    .route("/auth/start", web::post().to(fido::start_fido_authentication))
                    .route("/auth/finish", web::post().to(fido::finish_fido_authentication))
                    .service(
                        web::scope("")
                            .wrap(middleware::JwtAuth)
                            .route("/register/start", web::post().to(fido::start_fido_registration))
                            .route("/register/finish", web::post().to(fido::finish_fido_registration))
                            .route("/credentials", web::get().to(fido::list_fido_credentials))
                            .route("/credentials/{id}", web::delete().to(fido::delete_fido_credential)),
                    ),
            )
            .service(
                web::scope("/api/v1/files")
                    .wrap(middleware::JwtAuth)
                    .route("", web::post().to(handlers::files::upload_file))
                    .route("", web::get().to(handlers::files::list_files))
                    .route("/{id}/download", web::get().to(handlers::files::download_file))
                    .route("/{id}", web::delete().to(handlers::files::delete_file)),
            )
            .service(
                web::scope("/api/v1/media")
                    .wrap(middleware::JwtAuth)
                    .route("", web::get().to(handlers::media::list_media))
                    .route("", web::post().to(handlers::media::create_media)),
            )
            .service(
                web::scope("/api/v1/widgets")
                    .wrap(middleware::JwtAuth)
                    .route("", web::get().to(handlers::widgets::list_widgets))
                    .route("", web::post().to(handlers::widgets::create_widget))
                    .route("/{id}", web::put().to(handlers::widgets::update_widget))
                    .route("/{id}", web::delete().to(handlers::widgets::delete_widget)),
            )
            .service(
                web::scope("/api/v1/appstore")
                    .wrap(middleware::JwtAuth)
                    .route("/apps", web::get().to(handlers::appstore::list_store_apps))
                    .route("/installed", web::get().to(handlers::appstore::list_installed_apps))
                    .route("/install", web::post().to(handlers::appstore::install_app))
                    .route("/uninstall/{id}", web::delete().to(handlers::appstore::uninstall_app))
                    .route("/start/{id}", web::post().to(handlers::appstore::start_app))
                    .route("/stop/{id}", web::post().to(handlers::appstore::stop_app))
                    .route("/restart/{id}", web::post().to(handlers::appstore::restart_app)),
            )
            .service(
                web::scope("/api/v1/filemanager")
                    .wrap(middleware::JwtAuth)
                    .route("/list", web::get().to(handlers::filemanager::list_directory))
                    .route("/mkdir", web::post().to(handlers::filemanager::create_directory))
                    .route("/upload", web::post().to(handlers::filemanager::upload_files))
                    .route("/download", web::get().to(handlers::filemanager::download_file))
                    .route("/rename", web::post().to(handlers::filemanager::rename_file))
                    .route("/move", web::post().to(handlers::filemanager::move_files))
                    .route("/copy", web::post().to(handlers::filemanager::copy_files))
                    .route("/delete", web::post().to(handlers::filemanager::delete_files))
                    .route("/storage", web::get().to(handlers::filemanager::get_storage_info)),
            )
            .service(
                web::scope("/api/v1/system")
                    .wrap(middleware::JwtAuth)
                    .route("/info", web::get().to(handlers::system::get_system_info))
                    .route("/cpu", web::get().to(handlers::system::get_cpu_info))
                    .route("/memory", web::get().to(handlers::system::get_memory_info))
                    .route("/disks", web::get().to(handlers::system::get_disk_info))
                    .route("/usb", web::get().to(handlers::system::get_usb_devices))
                    .route("/hardware", web::get().to(handlers::system::get_hardware_info)),
            )
            .service(
                web::scope("/api/v1/media")
                    .wrap(middleware::JwtAuth)
                    .route("", web::get().to(handlers::media::list_media))
                    .route("", web::post().to(handlers::media::create_media))
                    .route("/codecs", web::get().to(handlers::media::get_codec_info))
                    .route("/transcode", web::post().to(handlers::media::transcode_media)),
            )
    });

    if config.tls_enabled {
        let tls_config = tls::load_rustls_config(&config)?;
        info!("TLS enabled");
        server
            .bind_rustls_021(&bind_addr, tls_config)?
            .workers(4)
            .run()
            .await
    } else {
        info!("TLS disabled, development mode only");
        server
            .bind(&bind_addr)?
            .workers(4)
            .run()
            .await
    }
}
