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
use crate::invite::InviteCodeManager;
use crate::media_processor::MediaProcessor;
use crate::zkp::ZkpContext;

#[cfg(feature = "fido")]
use crate::fido::FidoManager;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Check for --help argument
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help") {
        AppConfig::print_usage();
        return Ok(());
    }

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
    
    #[cfg(feature = "fido")]
    let fido_manager = Arc::new(
        FidoManager::new(&config.host, &format!("https://{}:{}", config.host, config.port))
            .expect("Failed to initialize FIDO2 manager")
    );
    
    #[cfg(feature = "fido")]
    info!("FIDO2/WebAuthn: Enabled");
    
    #[cfg(not(feature = "fido"))]
    info!("FIDO2/WebAuthn: Disabled (compile with --features fido to enable)");
    
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
    #[cfg(feature = "fido")]
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
                    // 允许常见局域网网段
                    || origin_str.starts_with("http://192.168.")
                    || origin_str.starts_with("https://192.168.")
                    || origin_str.starts_with("http://10.")
                    || origin_str.starts_with("https://10.")
                    || origin_str.starts_with("http://172.16.")
                    || origin_str.starts_with("https://172.16.")
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::ACCEPT,
            ])
            .supports_credentials()
            .max_age(3600);

        let app = App::new()
            .app_data(pool_data.clone())
            .app_data(crypto_data.clone())
            .app_data(zkp_data.clone())
            .app_data(invite_data.clone())
            .app_data(media_data.clone())
            .app_data(config_data.clone());
        
        #[cfg(feature = "fido")]
        let app = app.app_data(fido_data.clone());
        
        app
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
                    .route("", web::post().to(handlers::media::create_media))
                    .route("/codecs", web::get().to(handlers::media::get_codec_info))
                    .route("/transcode", web::post().to(handlers::media::transcode_media)),
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
                    .route("/storage", web::get().to(handlers::filemanager::get_storage_info))
                    // File preview and media streaming APIs
                    .route("/preview", web::get().to(handlers::filemanager::preview_text_file))
                    .route("/media/info", web::get().to(handlers::filemanager::get_media_info))
                    .route("/media/stream", web::get().to(handlers::filemanager::stream_media))
                    .route("/media/image", web::get().to(handlers::filemanager::serve_image))
                    .route("/media/thumbnail", web::get().to(handlers::filemanager::get_thumbnail)),
            )
            .service(
                web::scope("/api/v1/system")
                    .wrap(middleware::JwtAuth)
                    .route("/info", web::get().to(handlers::system::get_system_info))
                    .route("/cpu", web::get().to(handlers::system::get_cpu_info))
                    .route("/memory", web::get().to(handlers::system::get_memory_info))
                    .route("/disks", web::get().to(handlers::system::get_disk_info))
                    .route("/usb", web::get().to(handlers::system::get_usb_devices))
                    .route("/network", web::get().to(handlers::system::get_network_interfaces))
                    .route("/blocks", web::get().to(handlers::system::get_block_devices))
                    .route("/hardware", web::get().to(handlers::system::get_hardware_info)),
            )
            .service(
                web::scope("/api/v1/disk")
                    .wrap(middleware::JwtAuth)
                    .route("/list", web::get().to(handlers::disk_manager::list_disks))
                    .route("/partitions", web::get().to(handlers::disk_manager::list_partitions))
                    .route("/io-stats", web::get().to(handlers::disk_manager::get_disk_io_stats))
                    .route("/filesystems", web::get().to(handlers::disk_manager::get_supported_filesystems))
                    .route("/mount", web::post().to(handlers::disk_manager::mount_disk))
                    .route("/unmount", web::post().to(handlers::disk_manager::unmount_disk))
                    .route("/format", web::post().to(handlers::disk_manager::format_disk))
                    .route("/eject/{device:.*}", web::post().to(handlers::disk_manager::eject_disk))
                    .route("/health/{device:.*}", web::get().to(handlers::disk_manager::check_disk_health)),
            )
            // WebDAV 支持
            .service(
                web::scope("/webdav")
                    .route("", web::method(actix_web::http::Method::OPTIONS).to(handlers::webdav::webdav_options))
                    .route("/{path:.*}", web::method(actix_web::http::Method::OPTIONS).to(handlers::webdav::webdav_options))
                    .route("", web::method(actix_web::http::Method::from_bytes(b"PROPFIND").unwrap()).to(handlers::webdav::webdav_propfind))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"PROPFIND").unwrap()).to(handlers::webdav::webdav_propfind))
                    .route("/{path:.*}", web::get().to(handlers::webdav::webdav_get))
                    .route("/{path:.*}", web::head().to(handlers::webdav::webdav_head))
                    .route("/{path:.*}", web::put().to(handlers::webdav::webdav_put))
                    .route("/{path:.*}", web::delete().to(handlers::webdav::webdav_delete))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"MKCOL").unwrap()).to(handlers::webdav::webdav_mkcol))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"COPY").unwrap()).to(handlers::webdav::webdav_copy))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"MOVE").unwrap()).to(handlers::webdav::webdav_move))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"LOCK").unwrap()).to(handlers::webdav::webdav_lock))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"UNLOCK").unwrap()).to(handlers::webdav::webdav_unlock))
                    .route("/{path:.*}", web::method(actix_web::http::Method::from_bytes(b"PROPPATCH").unwrap()).to(handlers::webdav::webdav_proppatch)),
            )
            // 媒体流播放
            .service(
                web::scope("/api/v1/streaming")
                    .wrap(middleware::JwtAuth)
                    .route("/formats", web::get().to(handlers::streaming::get_supported_formats))
                    .route("/library", web::get().to(handlers::streaming::list_media_library))
                    .route("/info/{path:.*}", web::get().to(handlers::streaming::get_media_info))
                    .route("/play/{path:.*}", web::get().to(handlers::streaming::stream_media))
                    .route("/hls/{path:.*}", web::get().to(handlers::streaming::generate_hls_playlist))
                    .route("/thumbnail/{path:.*}", web::get().to(handlers::streaming::get_thumbnail)),
            )
            // 存储管理 (底层硬件访问)
            .service(
                web::scope("/api/v1/storage")
                    .wrap(middleware::JwtAuth)
                    .route("/devices", web::get().to(handlers::storage::list_storage_devices))
                    .route("/devices/{id}", web::get().to(handlers::storage::get_storage_device))
                    .route("/mount", web::post().to(handlers::storage::mount_storage))
                    .route("/unmount/{device:.*}", web::post().to(handlers::storage::unmount_storage))
                    .route("/format", web::post().to(handlers::storage::format_storage))
                    .route("/eject/{device:.*}", web::post().to(handlers::storage::eject_storage))
                    .route("/read/{path:.*}", web::get().to(handlers::storage::read_file))
                    .route("/write", web::post().to(handlers::storage::write_file))
                    .route("/delete/{path:.*}", web::delete().to(handlers::storage::delete_path)),
            )
            // Docker 容器管理
            .service(
                web::scope("/api/v1/docker")
                    .wrap(middleware::JwtAuth)
                    .route("/status", web::get().to(handlers::docker::check_docker_status))
                    .route("/install", web::post().to(handlers::docker::install_docker))
                    .route("/uninstall", web::post().to(handlers::docker::uninstall_docker))
                    // 容器管理
                    .route("/containers", web::get().to(handlers::docker::list_containers))
                    .route("/containers", web::post().to(handlers::docker::create_container))
                    .route("/containers/{id}", web::get().to(handlers::docker::get_container))
                    .route("/containers/{id}", web::delete().to(handlers::docker::remove_container))
                    .route("/containers/{id}/start", web::post().to(handlers::docker::start_container))
                    .route("/containers/{id}/stop", web::post().to(handlers::docker::stop_container))
                    .route("/containers/{id}/restart", web::post().to(handlers::docker::restart_container))
                    .route("/containers/{id}/logs", web::get().to(handlers::docker::get_container_logs))
                    .route("/containers/{id}/stats", web::get().to(handlers::docker::get_container_stats))
                    .route("/containers/{id}/exec", web::post().to(handlers::docker::exec_in_container))
                    // 镜像管理
                    .route("/images", web::get().to(handlers::docker::list_images))
                    .route("/images/pull", web::post().to(handlers::docker::pull_image))
                    .route("/images/{id}", web::delete().to(handlers::docker::remove_image))
                    // Docker Compose
                    .route("/compose", web::get().to(handlers::docker::list_compose_apps))
                    .route("/compose", web::post().to(handlers::docker::compose_deploy))
                    .route("/compose/{name}/start", web::post().to(handlers::docker::compose_start))
                    .route("/compose/{name}/stop", web::post().to(handlers::docker::compose_stop))
                    .route("/compose/{name}", web::delete().to(handlers::docker::compose_remove)),
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
