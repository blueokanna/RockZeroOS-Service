mod crypto;
mod db;
mod docker_api;
mod event_notifier;
mod ffmpeg_manager;
mod fido;
mod file_transfer;
mod handlers;
mod hardware;
mod invite;
mod media_processor;
mod middleware;
mod secure_db;
mod secure_video_access;
mod storage_manager;

use rockzero_common::{self as _, AppConfig};
use rockzero_crypto as _;
use rockzero_sae as _;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use sqlx::SqlitePool;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::handlers::secure_storage::SecureStorageManager;
use crate::invite::InviteCodeManager;
use crate::media_processor::MediaProcessor;
use crate::storage_manager::{StorageConfig, StorageManager};

async fn hardware_info_endpoint() -> actix_web::Result<impl actix_web::Responder> {
    let info = hardware::detect_hardware();
    Ok(actix_web::HttpResponse::Ok().json(info))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,actix_web=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting RockZero Service...");

    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    std::fs::create_dir_all(&data_dir).ok();

    info!("Initializing FFmpeg manager...");
    
    // 确定 assets 目录路径
    let assets_path = std::env::var("FFMPEG_ASSETS_PATH").unwrap_or_else(|_| {
        // 尝试多个可能的 assets 路径
        let candidates = [
            "./assets",
            "../assets",
            "/app/assets",
            "/opt/rockzero/assets",
        ];
        for candidate in &candidates {
            let path = std::path::Path::new(candidate);
            if path.exists() && path.is_dir() {
                info!("Found assets directory at: {}", candidate);
                return candidate.to_string();
            }
        }
        "./assets".to_string()
    });
    
    info!("Using assets path: {}", assets_path);
    
    let mut ffmpeg_manager = ffmpeg_manager::FfmpegManager::with_assets_path(&data_dir, &assets_path);
    match ffmpeg_manager.ensure_available().await {
        Ok(_) => {
            if let Some(path) = ffmpeg_manager.ffmpeg_path() {
                let ffmpeg_path_str = path.to_string_lossy().to_string();
                info!("FFmpeg ready: {}", ffmpeg_path_str);
                ffmpeg_manager::set_global_ffmpeg_path(Some(ffmpeg_path_str.clone()));
                // 同时设置环境变量，确保其他模块也能找到
                std::env::set_var("FFMPEG_PATH", &ffmpeg_path_str);
            }
            if let Some(path) = ffmpeg_manager.ffprobe_path() {
                let ffprobe_path_str = path.to_string_lossy().to_string();
                ffmpeg_manager::set_global_ffprobe_path(Some(ffprobe_path_str.clone()));
                std::env::set_var("FFPROBE_PATH", &ffprobe_path_str);
            }
            if let Some(version) = ffmpeg_manager.get_version() {
                info!("FFmpeg version: {}", version);
            }
        }
        Err(e) => {
            info!(
                "FFmpeg setup failed: {}. Media processing will be limited.",
                e
            );
        }
    }

    let media_processor = Arc::new(MediaProcessor::new());
    if media_processor.is_available() {
        info!("FFmpeg available - Media processing enabled");
        let hw_caps = media_processor.detect_hardware_capabilities();
        info!("Hardware acceleration: {:?}", hw_caps);
    } else {
        info!("FFmpeg not available - Media processing disabled");
    }

    let hardware_info = hardware::detect_hardware();
    info!(
        "Hardware detected: {} - {} cores - {} GB RAM",
        hardware_info.architecture,
        hardware_info.cpu_cores,
        hardware_info.total_memory / 1024 / 1024 / 1024
    );

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    let bind_addr = format!("{}:{}", host, port);
    info!("Listening on: {}", bind_addr);

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| format!("{}/rockzero.db", data_dir));

    info!("Connecting to database: {}", database_url);
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Initialize database tables
    info!("Initializing database tables...");
    db::initialize_database(&pool)
        .await
        .expect("Failed to initialize database");
    info!("Database initialized successfully");

    let secure_base = std::env::var("SECURE_STORAGE_PATH")
        .unwrap_or_else(|_| "./data/secure_storage".to_string());
    let _ = std::fs::create_dir_all(&secure_base);
    let secure_storage = Arc::new(SecureStorageManager::new(PathBuf::from(&secure_base)));
    info!("Secure Storage: ZKP + WPA3-SAE + CRC32 enabled");

    // Initialize secure HLS manager
    let secure_hls_manager = Arc::new(RwLock::new(rockzero_media::HlsSessionManager::new()));
    info!("Secure HLS streaming: WPA3-SAE + ZKP + AES-256-GCM enabled");

    // Initialize storage manager
    let storage_config = StorageConfig::from_env();
    storage_config.init_directories().await?;
    let storage_manager = Arc::new(StorageManager::new(storage_config));
    info!("Storage Manager initialized");

    // Start background cleanup tasks
    storage_manager.clone().start_cleanup_tasks();
    info!("Storage cleanup tasks started");

    let invite_manager = Arc::new(InviteCodeManager::new());

    // Initialize AppConfig
    let app_config = Arc::new(AppConfig::from_env());
    info!("App configuration loaded");

    // Initialize event notifier (200ms debounce)
    let _event_notifier = event_notifier::init_global_notifier(200);
    info!("Event notifier initialized");

    info!("WASM store initialized");

    // Initialize video access manager
    let _video_access_manager = secure_video_access::init_global_video_access_manager();
    info!("Video access manager initialized");

    // Auto-mount all disks
    info!("Auto-mounting disks...");
    handlers::disk_manager::auto_mount_all_disks();
    info!("Disk auto-mount completed");

    HttpServer::new(move || {
        let pool = pool.clone();
        let secure_storage = secure_storage.clone();
        let invite_manager = invite_manager.clone();
        let media_processor_data = media_processor.clone();
        let secure_hls_manager_data = secure_hls_manager.clone();
        let storage_manager_data = storage_manager.clone();
        let app_config_data = app_config.clone();
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec![
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "OPTIONS",
                "PROPFIND",
                "PROPPATCH",
                "MKCOL",
                "COPY",
                "MOVE",
                "LOCK",
                "UNLOCK",
            ])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::HeaderName::from_static("destination"),
                actix_web::http::header::HeaderName::from_static("overwrite"),
                actix_web::http::header::HeaderName::from_static("depth"),
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(web::PayloadConfig::default().limit(1000 * 1024 * 1024 * 1024))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(secure_storage.clone()))
            .app_data(web::Data::new(invite_manager.clone()))
            .app_data(web::Data::new(media_processor_data))
            .app_data(web::Data::new(secure_hls_manager_data))
            .app_data(web::Data::new(storage_manager_data))
            .app_data(web::Data::from(app_config_data))
            .app_data(web::Data::new(std::sync::Arc::new(
                handlers::zkp_auth::ZkpAuthManager::new(),
            )))
            .route("/health", web::get().to(handlers::health::health_check))
            .service(
                web::scope("/api/v1")
                    // 静态资源路由（Logo等）
                    .service(
                        web::scope("/assets")
                            .route("/logo", web::get().to(handlers::health::serve_logo))
                            .route("/readme", web::get().to(handlers::health::serve_readme))
                            .route("/about", web::get().to(handlers::health::get_about)),
                    )
                    .service(
                        web::scope("/auth")
                            .route("/register", web::post().to(handlers::auth::register))
                            .route("/login", web::post().to(handlers::auth::login))
                            .route("/refresh", web::post().to(handlers::auth::refresh_token))
                            // ZKP zero-knowledge proof authentication
                            .route("/zkp/login", web::post().to(handlers::zkp_auth::zkp_login))
                            .route(
                                "/zkp/registration",
                                web::post().to(handlers::zkp_auth::get_zkp_registration),
                            )
                            // Protected auth endpoints (require JWT)
                            .service(
                                web::scope("")
                                    .wrap(middleware::JwtAuth)
                                    .route("/me", web::get().to(handlers::auth::me)),
                            ),
                    )
                    .service(
                        web::scope("/zkp")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/search/token",
                                web::post().to(handlers::zkp_auth::create_search_token),
                            )
                            .route(
                                "/search/execute",
                                web::post().to(handlers::zkp_auth::execute_encrypted_search),
                            )
                            .route(
                                "/share/proof",
                                web::post().to(handlers::zkp_auth::create_share_proof),
                            )
                            .route(
                                "/share/verify",
                                web::post().to(handlers::zkp_auth::verify_share_proof),
                            )
                            .route(
                                "/range-proof/create",
                                web::post().to(handlers::zkp_auth::create_range_proof),
                            )
                            .route(
                                "/range-proof/verify",
                                web::post().to(handlers::zkp_auth::verify_range_proof),
                            )
                            .route(
                                "/video/proof",
                                web::post().to(handlers::zkp_auth::create_video_stream_proof),
                            )
                            .route(
                                "/video/verify",
                                web::post().to(handlers::zkp_auth::verify_video_stream_proof),
                            )
                            .route(
                                "/proof/generate",
                                web::post().to(handlers::zkp_auth::generate_zkp_proof),
                            ),
                    )
                    .service(
                        web::scope("/system")
                            .wrap(middleware::JwtAuth)
                            .route("/hardware", web::get().to(hardware_info_endpoint))
                            .route("/info", web::get().to(handlers::system::get_system_info))
                            .route("/cpu", web::get().to(handlers::system::get_cpu_info))
                            .route("/memory", web::get().to(handlers::system::get_memory_info))
                            .route("/disks", web::get().to(handlers::system::get_disk_info))
                            .route("/usb", web::get().to(handlers::system::get_usb_devices))
                            .route(
                                "/network",
                                web::get().to(handlers::system::get_network_interfaces),
                            )
                            .route(
                                "/blocks",
                                web::get().to(handlers::system::get_block_devices),
                            )
                            .route("/all", web::get().to(handlers::system::get_hardware_info))
                            .route(
                                "/capabilities",
                                web::get().to(handlers::system::get_hardware_capabilities),
                            ),
                    )
                    .service(
                        web::scope("/storage")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/devices",
                                web::get().to(handlers::storage::list_storage_devices),
                            )
                            .route(
                                "/stats",
                                web::get().to(handlers::storage::get_external_storage_stats),
                            )
                            .route(
                                "/config",
                                web::get().to(handlers::storage::get_external_storage_config),
                            )
                            .route(
                                "/device/{id}",
                                web::get().to(handlers::storage::get_storage_device),
                            )
                            .route("/mount", web::post().to(handlers::storage::mount_storage))
                            .route(
                                "/unmount/{device}",
                                web::post().to(handlers::storage::unmount_storage),
                            )
                            .route("/format", web::post().to(handlers::storage::format_storage))
                            .route(
                                "/eject/{device}",
                                web::post().to(handlers::storage::eject_storage),
                            )
                            .route(
                                "/file/{path:.*}",
                                web::get().to(handlers::storage::read_file),
                            )
                            .route("/file", web::post().to(handlers::storage::write_file))
                            .route(
                                "/delete/{path:.*}",
                                web::delete().to(handlers::storage::delete_path),
                            ),
                    )
                    .service(
                        web::scope("/storage-management")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/stats",
                                web::get().to(handlers::storage_management::get_storage_stats),
                            )
                            .route(
                                "/cleanup",
                                web::post().to(handlers::storage_management::trigger_cleanup),
                            )
                            .route(
                                "/cleanup/hls",
                                web::post().to(handlers::storage_management::cleanup_hls_cache),
                            )
                            .route(
                                "/cleanup/temp",
                                web::post().to(handlers::storage_management::cleanup_temp_files),
                            )
                            .route(
                                "/check",
                                web::get().to(handlers::storage_management::check_storage_space),
                            )
                            .route(
                                "/accurate-usage",
                                web::post()
                                    .to(handlers::storage_management::get_accurate_disk_usage),
                            )
                            .route(
                                "/force-cleanup",
                                web::post()
                                    .to(handlers::storage_management::force_cleanup_all_cache),
                            ),
                    )
                    .service(
                        web::scope("/speedtest")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/download",
                                web::get().to(handlers::speedtest::download_test),
                            )
                            .route("/upload", web::post().to(handlers::speedtest::upload_test))
                            .route("/ping", web::get().to(handlers::speedtest::ping_test))
                            .route("/info", web::get().to(handlers::speedtest::server_info))
                            .route("/empty", web::get().to(handlers::speedtest::empty_response)),
                    )
                    .service(
                        web::scope("/invite")
                            .wrap(middleware::JwtAuth)
                            .route("/create", web::post().to(invite::create_invite))
                            .route("/validate/{code}", web::get().to(invite::validate_invite))
                            .route("/remaining", web::post().to(invite::invite_remaining_time)),
                    )
                    .service(
                        web::scope("/fido")
                            // FIDO2 authentication (public - used for passwordless login)
                            .route(
                                "/auth/start",
                                web::post().to(fido::start_fido_authentication),
                            )
                            .route(
                                "/auth/finish",
                                web::post().to(fido::finish_fido_authentication),
                            )
                            // FIDO2 registration and credential management (requires JWT)
                            .service(
                                web::scope("")
                                    .wrap(middleware::JwtAuth)
                                    .route(
                                        "/register/start",
                                        web::post().to(fido::start_fido_registration),
                                    )
                                    .route(
                                        "/register/finish",
                                        web::post().to(fido::finish_fido_registration),
                                    )
                                    .route("/credentials", web::get().to(fido::list_fido_credentials))
                                    .route(
                                        "/credentials/{id}",
                                        web::delete().to(fido::delete_fido_credential),
                                    ),
                            ),
                    )
                    .service(
                        web::scope("/filemanager")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/list",
                                web::get().to(handlers::filemanager::list_directory),
                            )
                            .route(
                                "/mkdir",
                                web::post().to(handlers::filemanager::create_directory),
                            )
                            .route(
                                "/storage",
                                web::get().to(handlers::filemanager::get_storage_info),
                            )
                            .route(
                                "/upload",
                                web::post().to(handlers::filemanager::upload_files),
                            )
                            .route(
                                "/download",
                                web::get().to(handlers::filemanager::download_file),
                            )
                            .route(
                                "/rename",
                                web::post().to(handlers::filemanager::rename_file),
                            )
                            .route("/move", web::post().to(handlers::filemanager::move_files))
                            .route("/copy", web::post().to(handlers::filemanager::copy_files))
                            .route(
                                "/delete",
                                web::post().to(handlers::filemanager::delete_files),
                            )
                            .route(
                                "/preview",
                                web::get().to(handlers::filemanager::preview_text_file),
                            )
                            .route(
                                "/media/info",
                                web::get().to(handlers::filemanager::get_media_info),
                            )
                            .route(
                                "/media/stream",
                                web::get().to(handlers::filemanager::stream_media),
                            )
                            .route(
                                "/media/image",
                                web::get().to(handlers::filemanager::serve_image),
                            )
                            .route(
                                "/media/thumbnail",
                                web::get().to(handlers::filemanager::get_thumbnail),
                            ),
                    )
                    // ============ WASM 商店 (纯 WASM 应用) ============
                    // 旧的 /appstore 路径（向后兼容，仅 WASM 包管理）
                    .service(
                        web::scope("/appstore")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/packages",
                                web::get().to(handlers::appstore::list_packages),
                            )
                            .route(
                                "/packages/install",
                                web::post().to(handlers::appstore::install_package),
                            )
                            .route(
                                "/packages/{id}",
                                web::delete().to(handlers::appstore::remove_package),
                            )
                            .route(
                                "/packages/{id}/run",
                                web::post().to(handlers::appstore::run_wasm_package),
                            ),
                    )
                    .service(
                        web::scope("/wasm-store")
                            .wrap(middleware::JwtAuth)
                            // 商店概览
                            .route(
                                "/overview",
                                web::get().to(handlers::wasm_store::get_store_overview),
                            )
                            // WASM 应用搜索
                            .route(
                                "/search",
                                web::get().to(handlers::wasm_store::search_wasm_apps),
                            )
                            // WASM 应用管理
                            .route(
                                "/wasm/apps",
                                web::get().to(handlers::wasm_store::list_wasm_apps),
                            )
                            .route(
                                "/wasm/apps/{app_id}",
                                web::get().to(handlers::wasm_store::get_wasm_app_details),
                            )
                            .route(
                                "/wasm/install",
                                web::post().to(handlers::wasm_store::install_wasm_app),
                            )
                            .route(
                                "/wasm/{app_id}/run",
                                web::post().to(handlers::wasm_store::run_wasm_app),
                            )
                            .route(
                                "/wasm/{app_id}",
                                web::delete().to(handlers::wasm_store::uninstall_wasm_app),
                            )
                            // 插件系统
                            .route(
                                "/plugins",
                                web::get().to(handlers::wasm_store::list_plugins),
                            )
                            .route(
                                "/plugins/register",
                                web::post().to(handlers::wasm_store::register_plugin),
                            )
                            .route(
                                "/plugins/{plugin_id}",
                                web::delete().to(handlers::wasm_store::unregister_plugin),
                            ),
                    )
                    .service(
                        web::scope("/disk")
                            .wrap(middleware::JwtAuth)
                            .route("/list", web::get().to(handlers::disk_manager::list_disks))
                            .route(
                                "/{id}/details",
                                web::get().to(handlers::disk_manager::get_disk_details),
                            )
                            .route(
                                "/{id}/partitions",
                                web::get().to(handlers::disk_manager::list_partitions),
                            )
                            // Add routes without ID for direct device parameter passing
                            .route("/mount", web::post().to(handlers::disk_manager::mount_disk))
                            .route(
                                "/unmount",
                                web::post().to(handlers::disk_manager::unmount_disk),
                            )
                            .route(
                                "/format",
                                web::post().to(handlers::disk_manager::format_disk),
                            )
                            // Keep routes with ID for backward compatibility
                            .route(
                                "/{id}/mount",
                                web::post().to(handlers::disk_manager::mount_disk),
                            )
                            .route(
                                "/{id}/unmount",
                                web::post().to(handlers::disk_manager::unmount_disk),
                            )
                            .route(
                                "/{id}/format",
                                web::post().to(handlers::disk_manager::format_disk),
                            )
                            .route(
                                "/{id}/health",
                                web::get().to(handlers::disk_manager::check_disk_health),
                            )
                            .route(
                                "/{id}/eject",
                                web::post().to(handlers::disk_manager::eject_disk),
                            )
                            .route("/scan", web::post().to(handlers::disk_manager::scan_disks))
                            .route(
                                "/io-stats",
                                web::get().to(handlers::disk_manager::get_disk_io_stats),
                            )
                            .route(
                                "/filesystems",
                                web::get().to(handlers::disk_manager::get_supported_filesystems),
                            )
                            .route(
                                "/{id}/initialize",
                                web::post().to(handlers::disk_manager::initialize_disk),
                            )
                            .route(
                                "/{id}/rename",
                                web::post().to(handlers::disk_manager::rename_disk),
                            )
                            .route(
                                "/{id}/smart-test",
                                web::post().to(handlers::disk_manager::run_smart_test),
                            )
                            .route(
                                "/{id}/wipe",
                                web::post().to(handlers::disk_manager::wipe_disk),
                            )
                            .route(
                                "/{id}/temperature",
                                web::get().to(handlers::disk_manager::get_disk_temperature),
                            ),
                    )
                    // Professional storage management API
                    .service(
                        web::scope("/storage")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/devices",
                                web::get().to(handlers::storage::list_storage_devices),
                            )
                            .route(
                                "/stats",
                                web::get().to(handlers::storage::get_external_storage_stats),
                            )
                            .route(
                                "/config",
                                web::get().to(handlers::storage::get_external_storage_config),
                            )
                            .route(
                                "/devices/{id}",
                                web::get().to(handlers::storage::get_storage_device),
                            )
                            .route("/mount", web::post().to(handlers::storage::mount_storage))
                            .route(
                                "/unmount/{device}",
                                web::post().to(handlers::storage::unmount_storage),
                            )
                            .route("/format", web::post().to(handlers::storage::format_storage))
                            .route(
                                "/partition",
                                web::post().to(handlers::storage::partition_and_format),
                            )
                            .route(
                                "/wipe/{device}",
                                web::post().to(handlers::storage::wipe_disk),
                            )
                            .route(
                                "/eject/{device}",
                                web::post().to(handlers::storage::eject_storage),
                            )
                            .route(
                                "/smart-format",
                                web::post().to(handlers::storage::smart_format),
                            )
                            .route("/auto-mount", web::post().to(handlers::storage::auto_mount)),
                    )
                    // Video hardware acceleration API
                    .service(
                        web::scope("/video-hardware")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/capabilities",
                                web::get().to(handlers::video_hardware::get_hardware_capabilities),
                            )
                            .route(
                                "/transcode",
                                web::post().to(handlers::video_hardware::transcode_video),
                            ),
                    )
                    .service(
                        web::scope("/files")
                            .wrap(middleware::JwtAuth)
                            .route("/upload", web::post().to(handlers::files::upload_file))
                            .route("/list", web::get().to(handlers::files::list_files))
                            .route(
                                "/download/{id}",
                                web::get().to(handlers::files::download_file),
                            )
                            .route(
                                "/delete/{id}",
                                web::delete().to(handlers::files::delete_file),
                            ),
                    )
                    .service(
                        web::scope("/widgets")
                            .wrap(middleware::JwtAuth)
                            .route("", web::get().to(handlers::widgets::list_widgets))
                            .route("", web::post().to(handlers::widgets::create_widget))
                            .route("/{id}", web::put().to(handlers::widgets::update_widget))
                            .route("/{id}", web::delete().to(handlers::widgets::delete_widget)),
                    )
                    .service(
                        web::scope("/transfer")
                            .wrap(middleware::JwtAuth)
                            .route("/upload", web::post().to(file_transfer::upload_file))
                            .route(
                                "/download/{id}",
                                web::get().to(file_transfer::download_file),
                            )
                            .route(
                                "/chunked/upload",
                                web::post().to(file_transfer::chunked_upload),
                            )
                            .route(
                                "/chunked/download/{id}",
                                web::get().to(file_transfer::chunked_download),
                            )
                            .route(
                                "/checksum/{id}",
                                web::get().to(file_transfer::get_file_checksum),
                            ),
                    )
                    .service(
                        web::scope("/secure")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/db/init",
                                web::post().to(handlers::secure_storage::init_secure_database),
                            )
                            .route(
                                "/db/store",
                                web::post().to(handlers::secure_storage::store_secure_data),
                            )
                            .route(
                                "/db/retrieve/{key}",
                                web::get().to(handlers::secure_storage::retrieve_secure_data),
                            )
                            .route(
                                "/db/delete/{key}",
                                web::delete().to(handlers::secure_storage::delete_secure_data),
                            )
                            .route(
                                "/db/integrity",
                                web::get().to(handlers::secure_storage::check_integrity),
                            )
                            .route(
                                "/db/repair",
                                web::post().to(handlers::secure_storage::repair_data),
                            )
                            .route(
                                "/db/stats",
                                web::get().to(handlers::secure_storage::get_database_stats),
                            )
                            .route(
                                "/db/close",
                                web::post().to(handlers::secure_storage::close_database),
                            )
                            .route(
                                "/encrypt",
                                web::post().to(handlers::secure_storage::encrypt_data),
                            )
                            .route(
                                "/decrypt",
                                web::post().to(handlers::secure_storage::decrypt_data),
                            )
                            .route(
                                "/key/derive",
                                web::post().to(handlers::secure_storage::derive_key),
                            )
                            .route(
                                "/key/batch",
                                web::post().to(handlers::secure_storage::derive_batch_keys),
                            )
                            .route(
                                "/random",
                                web::post().to(handlers::secure_storage::generate_random),
                            )
                            .route("/hash", web::post().to(handlers::secure_storage::hash_data))
                            .route(
                                "/crc32",
                                web::post().to(handlers::secure_storage::crc32_check),
                            )
                            .route(
                                "/compare",
                                web::post()
                                    .to(handlers::secure_storage::constant_time_compare_endpoint),
                            )
                            .route(
                                "/transfer/{id}",
                                web::get().to(handlers::secure_storage::get_transfer_status),
                            )
                            .route(
                                "/transfer/start",
                                web::post().to(handlers::secure_storage::start_transfer),
                            )
                            .route(
                                "/transfer/{id}/complete",
                                web::post().to(handlers::secure_storage::complete_transfer),
                            )
                            .route(
                                "/transfer/{id}/progress",
                                web::put().to(handlers::secure_storage::update_transfer_progress),
                            )
                            .route(
                                "/transfer/{id}/failed",
                                web::post().to(handlers::secure_storage::mark_encryption_failed),
                            )
                            .route(
                                "/transfer/{id}/remove",
                                web::delete().to(handlers::secure_storage::remove_transfer),
                            )
                            .route(
                                "/file/encrypt",
                                web::post().to(handlers::secure_storage::encrypt_file),
                            )
                            .route(
                                "/file/decrypt",
                                web::post().to(handlers::secure_storage::decrypt_file),
                            )
                            .route(
                                "/file/can-encrypt",
                                web::post().to(handlers::secure_storage::can_safely_encrypt),
                            )
                            .route(
                                "/transfers/active",
                                web::get().to(handlers::secure_storage::list_active_transfers),
                            )
                            .route(
                                "/transfers/cleanup",
                                web::post().to(handlers::secure_storage::cleanup_transfers),
                            )
                            .route(
                                "/erase-demo",
                                web::post().to(handlers::secure_storage::secure_erase_demo),
                            )
                            .route(
                                "/string/encrypt",
                                web::post().to(handlers::secure_storage::encrypt_string),
                            )
                            .route(
                                "/string/decrypt",
                                web::post().to(handlers::secure_storage::decrypt_string),
                            )
                            .route(
                                "/key/wpa3-sae",
                                web::post().to(handlers::secure_storage::derive_wpa3_sae_key),
                            )
                            .route(
                                "/key/specific",
                                web::post().to(handlers::secure_storage::derive_specific_key),
                            ),
                    )
                    // ============ Secure HLS Streaming ============
                    .service(
                        web::scope("/secure-hls")
                            .wrap(middleware::JwtAuth)
                            // SAE handshake and session creation
                            .service(
                                web::scope("/sae")
                                    .route(
                                        "/init",
                                        web::post().to(handlers::secure_hls::init_sae_handshake),
                                    )
                                    .route(
                                        "/commit",
                                        web::post().to(handlers::secure_hls::send_client_commit),
                                    )
                                    .route(
                                        "/confirm",
                                        web::post().to(handlers::secure_hls::send_client_confirm),
                                    )
                                    .route(
                                        "/complete",
                                        web::post()
                                            .to(handlers::secure_hls::complete_sae_handshake),
                                    ),
                            )
                            .service(web::scope("/session").route(
                                "/create",
                                web::post().to(handlers::secure_hls::create_hls_session),
                            ))
                            // Secure HLS playlist and segments (authorized by session_id + JWT)
                            .route(
                                "/{session_id}/playlist.m3u8",
                                web::get().to(handlers::secure_hls::get_secure_playlist),
                            )
                            // Stop HLS session
                            .route(
                                "/{session_id}/stop",
                                web::post().to(handlers::secure_hls::stop_session),
                            )
                            // Prebuffer segment
                            .route(
                                "/{session_id}/prebuffer/{segment}",
                                web::post().to(handlers::secure_hls::prebuffer_segment),
                            )
                            // Video segments (POST with ZKP proof)
                            .route(
                                "/{session_id}/{segment}",
                                web::post().to(handlers::secure_hls::get_secure_segment),
                            ),
                    )
                    .service(
                        web::scope("/media")
                            .wrap(middleware::JwtAuth)
                            .route("/create", web::post().to(handlers::media::create_media))
                            .route("/codecs", web::get().to(handlers::media::get_codec_info)),
                    )
                    .service(
                        web::scope("/streaming")
                            .wrap(middleware::JwtAuth)
                            .route(
                                "/formats",
                                web::get().to(handlers::streaming::get_supported_formats),
                            )
                            .route(
                                "/library",
                                web::get().to(handlers::streaming::list_media_library),
                            )
                            .route(
                                "/info/{path:.*}",
                                web::get().to(handlers::streaming::get_media_info),
                            )
                            .route(
                                "/extended-info/{path:.*}",
                                web::get().to(handlers::streaming::get_extended_media_info),
                            )
                            .route(
                                "/play/{path:.*}",
                                web::get().to(handlers::streaming::stream_media),
                            )
                            .route(
                                "/hls/{path:.*}",
                                web::get().to(handlers::streaming::generate_hls_playlist),
                            )
                            .route(
                                "/thumbnail/{path:.*}",
                                web::get().to(handlers::streaming::get_thumbnail),
                            ),
                    ),
            )
            .service(
                web::scope("/webdav")
                    .wrap(middleware::JwtAuth)
                    .route(
                        "",
                        web::method(actix_web::http::Method::OPTIONS)
                            .to(handlers::webdav::webdav_options),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::OPTIONS)
                            .to(handlers::webdav::webdav_options),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"PROPFIND").unwrap())
                            .to(handlers::webdav::webdav_propfind),
                    )
                    .route("/{path:.*}", web::get().to(handlers::webdav::webdav_get))
                    .route("/{path:.*}", web::head().to(handlers::webdav::webdav_head))
                    .route("/{path:.*}", web::put().to(handlers::webdav::webdav_put))
                    .route(
                        "/{path:.*}",
                        web::delete().to(handlers::webdav::webdav_delete),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"MKCOL").unwrap())
                            .to(handlers::webdav::webdav_mkcol),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"COPY").unwrap())
                            .to(handlers::webdav::webdav_copy),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"MOVE").unwrap())
                            .to(handlers::webdav::webdav_move),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"LOCK").unwrap())
                            .to(handlers::webdav::webdav_lock),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"UNLOCK").unwrap())
                            .to(handlers::webdav::webdav_unlock),
                    )
                    .route(
                        "/{path:.*}",
                        web::method(actix_web::http::Method::from_bytes(b"PROPPATCH").unwrap())
                            .to(handlers::webdav::webdav_proppatch),
                    ),
            )
    })
    .bind(&bind_addr)?
    .run()
    .await
}
