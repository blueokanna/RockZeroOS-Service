mod crypto;
mod db;
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
mod storage_manager;

use rockzero_common::{self as _, AppConfig};
use rockzero_crypto as _;
use rockzero_sae as _;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use sqlx::SqlitePool;
use std::{io::Write, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::error;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::handlers::secure_storage::SecureStorageManager;
use crate::invite::InviteCodeManager;
use crate::media_processor::MediaProcessor;
use crate::storage_manager::{StorageConfig, StorageManager};

#[cfg(target_os = "windows")]
static WINDOWS_RUNTIME_DIAG_LOG: std::sync::OnceLock<std::sync::Mutex<std::fs::File>> =
    std::sync::OnceLock::new();

#[cfg(target_os = "windows")]
extern "C" fn windows_atexit_hook() {
    runtime_diag_log("windows_atexit_hook invoked");
}

#[cfg(target_os = "windows")]
fn runtime_diag_log(message: &str) {
    use std::io::Write;

    let timestamp = chrono::Local::now().to_rfc3339();
    let line = format!("[{}] {}\n", timestamp, message);

    if let Some(lock) = WINDOWS_RUNTIME_DIAG_LOG.get() {
        if let Ok(mut file) = lock.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
            return;
        }
    }

    let _ = std::io::stderr().write_all(line.as_bytes());
    let _ = std::io::stderr().flush();
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_ctrl_handler(ctrl_type: u32) -> i32 {
    runtime_diag_log(&format!("windows_ctrl_handler ctrl_type={}", ctrl_type));
    0
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_vectored_exception_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    if !exception_info.is_null() {
        let record = unsafe { (*exception_info).ExceptionRecord };
        if !record.is_null() {
            let code = unsafe { (*record).ExceptionCode };
            let address = unsafe { (*record).ExceptionAddress };
            runtime_diag_log(&format!(
                "vectored_exception code=0x{:08x} address={:?}",
                code, address
            ));
        } else {
            runtime_diag_log("vectored_exception with null ExceptionRecord");
        }
    } else {
        runtime_diag_log("vectored_exception with null EXCEPTION_POINTERS");
    }

    0
}

#[cfg(target_os = "windows")]
fn install_windows_runtime_diagnostics(data_dir: &str) {
    use std::backtrace::Backtrace;
    use std::fs::OpenOptions;
    use std::path::Path;

    let candidate_paths = [
        Path::new(data_dir)
            .join("logs")
            .join("windows-runtime-diagnostics.log"),
        Path::new("./storage")
            .join("logs")
            .join("windows-runtime-diagnostics.log"),
        Path::new("./windows-runtime-diagnostics.log").to_path_buf(),
    ];

    for path in &candidate_paths {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if let Ok(file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = WINDOWS_RUNTIME_DIAG_LOG.set(std::sync::Mutex::new(file));
            info!("Windows runtime diagnostics log path: {}", path.display());
            break;
        }
    }

    runtime_diag_log(&format!(
        "install_windows_runtime_diagnostics pid={}",
        std::process::id()
    ));

    std::panic::set_hook(Box::new(|panic_info| {
        let backtrace = Backtrace::force_capture();
        runtime_diag_log(&format!("panic_hook info={}\nbacktrace={}", panic_info, backtrace));
    }));

    unsafe {
        let atexit_rc = libc::atexit(windows_atexit_hook);
        runtime_diag_log(&format!("libc::atexit register rc={}", atexit_rc));
    }

    unsafe {
        let ctrl_ok = winapi::um::consoleapi::SetConsoleCtrlHandler(Some(windows_ctrl_handler), 1);
        let ctrl_err = winapi::um::errhandlingapi::GetLastError();
        runtime_diag_log(&format!(
            "SetConsoleCtrlHandler result={} last_error={}",
            ctrl_ok, ctrl_err
        ));

        let veh_handle = winapi::um::errhandlingapi::AddVectoredExceptionHandler(
            1,
            Some(windows_vectored_exception_handler),
        );
        let veh_err = winapi::um::errhandlingapi::GetLastError();
        runtime_diag_log(&format!(
            "AddVectoredExceptionHandler handle={:?} last_error={}",
            veh_handle, veh_err
        ));
    }

    runtime_diag_log("windows diagnostics hooks installed");
}

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

    #[cfg(target_os = "windows")]
    install_windows_runtime_diagnostics(&data_dir);

    info!("Initializing FFmpeg manager...");
    
    let assets_path = std::env::var("FFMPEG_ASSETS_PATH").unwrap_or_else(|_| {
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

    let secure_hls_manager = Arc::new(RwLock::new(rockzero_media::HlsSessionManager::new()));
    info!("Secure HLS streaming: WPA3-SAE + ChaCha20-Poly1305 enabled");

    let external_cache_ready = handlers::secure_hls::initialize_external_cache_startup_guard();
    if external_cache_ready {
        info!(
            "Secure HLS startup guard passed: external cache is ready for production playback"
        );
    } else {
        info!(
            "Secure HLS startup guard failed: playback chain will be blocked until external cache is correctly mounted"
        );
    }

    let stream_config = rockzero_media::secure_transport::StreamConfig::default();
    let secure_transport = Arc::new(
        rockzero_media::SecureStreamTransport::new(stream_config)
            .expect("Failed to initialize secure transport"),
    );
    let hybrid_config = rockzero_media::HybridConfig {
        udp_ratio: 0.70,
        tcp_ratio: 0.30,
        udp_min_ratio: 0.10,
        udp_max_ratio: 0.70,
        chunk_size: 128 * 1024,
        udp_window_size: 96,
        send_buffer_size: 16 * 1024 * 1024,
        udp_loss_threshold: 0.03,
        tcp_max_retries: 5,
        ..rockzero_media::HybridConfig::default()
    };
    let hybrid_transport = Arc::new(rockzero_media::HybridTransport::new(
        secure_transport.clone(),
        hybrid_config,
    ));
    info!(
        "Hybrid transport initialized: UDP {:.0}% + TCP {:.0}%",
        0.7 * 100.0,
        0.3 * 100.0
    );

    let storage_config = StorageConfig::from_env();
    storage_config.init_directories().await?;
    let storage_manager = Arc::new(StorageManager::new(storage_config));
    info!("Storage Manager initialized");

    storage_manager.clone().start_cleanup_tasks();
    info!("Storage cleanup tasks started");

    let invite_manager = Arc::new(InviteCodeManager::new());

    let app_config = Arc::new(AppConfig::from_env());
    info!("App configuration loaded");

    let _event_notifier = event_notifier::init_global_notifier(200);
    info!("Event notifier initialized");

    info!("WASM store initialized");

    let lan_transfer_manager = Arc::new(RwLock::new(
        handlers::lan_transfer::LanTransferManager::new(),
    ));
    info!("LAN transfer manager initialized");

    if cfg!(target_os = "linux") {
        info!("Auto-mounting disks...");
        handlers::disk_manager::auto_mount_all_disks();
        info!("Disk auto-mount completed");

        info!("Scanning for uninitialized disks...");
        handlers::disk_manager::auto_format_and_mount_uninitialized_disks();
        info!("Uninitialized disk scan completed");
    } else {
        info!(
            "Disk management startup routines disabled on {}: exposing disk status and file operations only",
            std::env::consts::OS
        );
    }

    let server = HttpServer::new(move || {
        let pool = pool.clone();
        let secure_storage = secure_storage.clone();
        let invite_manager = invite_manager.clone();
        let media_processor_data = media_processor.clone();
        let secure_hls_manager_data = secure_hls_manager.clone();
        let storage_manager_data = storage_manager.clone();
        let hybrid_transport_data = hybrid_transport.clone();
        let app_config_data = app_config.clone();
        let lan_transfer_data = lan_transfer_manager.clone();
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec![
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "OPTIONS",
                "HEAD",
                "PATCH",
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
                actix_web::http::header::RANGE,
                actix_web::http::header::IF_NONE_MATCH,
                actix_web::http::header::IF_MODIFIED_SINCE,
                actix_web::http::header::IF_RANGE,
                actix_web::http::header::CACHE_CONTROL,
                actix_web::http::header::CONTENT_LENGTH,
                actix_web::http::header::CONTENT_RANGE,
                actix_web::http::header::ORIGIN,
                actix_web::http::header::HeaderName::from_static("x-requested-with"),
                actix_web::http::header::HeaderName::from_static("x-upload-id"),
                actix_web::http::header::HeaderName::from_static("x-chunk-index"),
                actix_web::http::header::HeaderName::from_static("x-total-chunks"),
                actix_web::http::header::HeaderName::from_static("x-file-name"),
                actix_web::http::header::HeaderName::from_static("x-file-size"),
                actix_web::http::header::HeaderName::from_static("destination"),
                actix_web::http::header::HeaderName::from_static("overwrite"),
                actix_web::http::header::HeaderName::from_static("depth"),
            ])
            .expose_headers(vec![
                actix_web::http::header::CONTENT_RANGE,
                actix_web::http::header::CONTENT_LENGTH,
                actix_web::http::header::ACCEPT_RANGES,
                actix_web::http::header::ETAG,
                actix_web::http::header::HeaderName::from_static("x-upload-id"),
                actix_web::http::header::HeaderName::from_static("content-duration"),
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(web::PayloadConfig::default().limit(100 * 1024 * 1024)) // 100 MB max payload for ARM devices
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(secure_storage.clone()))
            .app_data(web::Data::new(invite_manager.clone()))
            .app_data(web::Data::new(media_processor_data))
            .app_data(web::Data::new(secure_hls_manager_data))
            .app_data(web::Data::new(storage_manager_data))
            .app_data(web::Data::new(hybrid_transport_data))
            .app_data(web::Data::from(app_config_data))
            .app_data(web::Data::new(lan_transfer_data))
            .app_data(web::Data::new(std::sync::Arc::new(
                handlers::zkp_auth::ZkpAuthManager::new(),
            )))
            .route("/health", web::get().to(handlers::health::health_check))
            .service(
                web::scope("/api/v1")
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
                            .route("/zkp/login", web::post().to(handlers::zkp_auth::zkp_login))
                            .route(
                                "/zkp/registration",
                                web::post().to(handlers::zkp_auth::get_zkp_registration),
                            )
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
                                "/proof/generate",
                                web::post().to(handlers::zkp_auth::generate_zkp_proof),
                            )
                            .route(
                                "/proof/generate-batch",
                                web::post().to(handlers::zkp_auth::generate_zkp_proof_batch),
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
                            )
                            .route(
                                "/public-ip",
                                web::get().to(handlers::system::get_public_ip),
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
                            )
                            .route(
                                "/auto-cleanup-status",
                                web::get()
                                    .to(handlers::storage_management::get_auto_cleanup_status),
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
                            .route(
                                "/auth/start",
                                web::post().to(fido::start_fido_authentication),
                            )
                            .route(
                                "/auth/finish",
                                web::post().to(fido::finish_fido_authentication),
                            )
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
                                "/scope/status",
                                web::get().to(handlers::filemanager::get_storage_scope_status),
                            )
                            .route(
                                "/scope/browse",
                                web::get().to(handlers::filemanager::browse_storage_scope),
                            )
                            .route(
                                "/scope/configure",
                                web::post().to(handlers::filemanager::configure_storage_scope),
                            )
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
                                "/text/save",
                                web::post().to(handlers::filemanager::write_text_file),
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
                            .route(
                                "/overview",
                                web::get().to(handlers::wasm_store::get_store_overview),
                            )
                            .route(
                                "/steam/featured",
                                web::get().to(handlers::wasm_store::get_steam_featured),
                            )
                            .route(
                                "/steam/app/{app_id}",
                                web::get().to(handlers::wasm_store::get_steam_app_details),
                            )
                            .route(
                                "/steam/library",
                                web::get().to(handlers::wasm_store::get_steam_user_library),
                            )
                            .route(
                                "/steam/player",
                                web::get().to(handlers::wasm_store::get_steam_player_summary),
                            )
                            .route(
                                "/epic/free",
                                web::get().to(handlers::wasm_store::get_epic_free_games),
                            )
                            .route(
                                "/platform/games",
                                web::get().to(handlers::wasm_store::get_platform_games),
                            )
                            .route(
                                "/search",
                                web::get().to(handlers::wasm_store::search_wasm_apps),
                            )
                            .route(
                                "/recommendations",
                                web::get().to(handlers::wasm_store::get_daily_recommendations),
                            )
                            .route(
                                "/steam/search",
                                web::get().to(handlers::wasm_store::search_steam_store),
                            )
                            .route(
                                "/github/import",
                                web::post().to(handlers::wasm_store::import_from_github),
                            )
                            .route(
                                "/wasm/run-script",
                                web::post().to(handlers::wasm_store::run_wasm_script),
                            )
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
                            .route(
                                "/builtin/{app_id}/run",
                                web::get().to(handlers::wasm_store::run_builtin_app),
                            )
                            .route(
                                "/builtin/m3u8-downloader/download",
                                web::post().to(handlers::wasm_store::download_m3u8_video),
                            )
                            .route(
                                "/builtin/downloads",
                                web::get().to(handlers::wasm_store::list_downloads),
                            )
                            .route(
                                "/builtin/downloads/{filename}",
                                web::get().to(handlers::wasm_store::serve_download_file),
                            )
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
                            .route(
                                "/capabilities",
                                web::get().to(handlers::disk_manager::get_disk_capabilities),
                            )
                            .route("/list", web::get().to(handlers::disk_manager::list_disks))
                            .route(
                                "/{id}/details",
                                web::get().to(handlers::disk_manager::get_disk_details),
                            )
                            .route(
                                "/{id}/partitions",
                                web::get().to(handlers::disk_manager::list_partitions),
                            )
                            .route("/mount", web::post().to(handlers::disk_manager::mount_disk))
                            .route(
                                "/unmount",
                                web::post().to(handlers::disk_manager::unmount_disk),
                            )
                            .route(
                                "/format",
                                web::post().to(handlers::disk_manager::format_disk),
                            )
                            .route(
                                "/initialize",
                                web::post().to(handlers::disk_manager::initialize_disk),
                            )
                            .route(
                                "/rename",
                                web::post().to(handlers::disk_manager::rename_disk),
                            )
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
                        web::scope("/lan-transfer")
                            .route("/device-info", web::get().to(handlers::lan_transfer::get_device_info))
                            .route("/shared", web::get().to(handlers::lan_transfer::list_shared_items))
                            .route("/download/{item_id}", web::get().to(handlers::lan_transfer::download_shared_item))
                            .route("/share", web::post().to(handlers::lan_transfer::add_shared_item))
                            .route("/share/{id}", web::delete().to(handlers::lan_transfer::remove_shared_item))
                            .route("/scan-games", web::post().to(handlers::lan_transfer::scan_local_games))
                            .route("/receive", web::post().to(handlers::lan_transfer::receive_from_peer))
                            .route("/sessions", web::get().to(handlers::lan_transfer::list_sessions))
                            .route("/sessions/{id}", web::get().to(handlers::lan_transfer::get_session))
                            .route("/sessions/{id}/cancel", web::post().to(handlers::lan_transfer::cancel_session))
                            .route("/sessions/{id}", web::delete().to(handlers::lan_transfer::delete_session))
                            .route("/sessions/cleanup", web::post().to(handlers::lan_transfer::cleanup_sessions)),
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
                    .service(
                        web::scope("/secure-hls")
                            .service(
                                web::scope("/sae")
                                    .wrap(middleware::JwtAuth)
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
                            .service(
                                web::scope("/transport")
                                    .wrap(middleware::JwtAuth)
                                    .route(
                                        "/stats",
                                        web::get().to(handlers::secure_hls::get_transport_stats),
                                    ),
                            )
                            .service(
                                web::scope("/session")
                                    .wrap(middleware::JwtAuth)
                                    .route(
                                        "/create",
                                        web::post().to(handlers::secure_hls::create_hls_session),
                                    )
                                    .route(
                                        "/{session_id}/proof-ticket",
                                        web::post()
                                            .to(handlers::secure_hls::create_session_proof_ticket),
                                    ),
                            )
                            .route(
                                "/{session_id}/playlist.m3u8",
                                web::get().to(handlers::secure_hls::get_secure_playlist),
                            )
                            .route(
                                "/{session_id}/stop",
                                web::post().to(handlers::secure_hls::stop_session),
                            )
                            .route(
                                "/{session_id}/{segment}",
                                web::get().to(handlers::secure_hls::get_segment_direct),
                            )
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
                                "/hls/{path:.*}",
                                web::get().to(handlers::streaming::generate_hls_playlist),
                            )
                            .route(
                                "/thumbnail/{path:.*}",
                                web::get().to(handlers::streaming::get_thumbnail),
                            )
                            .route(
                                "/play/{path:.*}",
                                web::get().to(handlers::streaming::stream_media),
                            )
                            .route(
                                "/smart-play/{path:.*}",
                                web::get().to(handlers::streaming::smart_play),
                            )
                            .route(
                                "/transcode/{path:.*}",
                                web::get().to(handlers::streaming::transcode_audio),
                            )
                            .route(
                                "/transcode-video/{path:.*}",
                                web::get().to(handlers::streaming::transcode_video),
                            ),
                    ),
            )
            .service(
                web::scope("/api/v1/edge")
                    .route("/health", web::get().to(handlers::edge_compute::health))
                    .service(
                        web::scope("")
                            .wrap(middleware::JwtAuth)
                            .route("/stats", web::get().to(handlers::edge_compute::edge_stats))
                            .route("/nodes", web::get().to(handlers::edge_compute::list_nodes))
                            .route(
                                "/nodes/register",
                                web::post().to(handlers::edge_compute::register_node),
                            )
                            .route(
                                "/nodes/{node_id}/heartbeat",
                                web::post().to(handlers::edge_compute::node_heartbeat),
                            )
                            .route("/jobs", web::get().to(handlers::edge_compute::list_jobs))
                            .route(
                                "/jobs/submit",
                                web::post().to(handlers::edge_compute::submit_job),
                            )
                            .route(
                                "/wxy/qr/start",
                                web::post().to(handlers::edge_compute::start_wxy_qr_login),
                            )
                            .route(
                                "/wxy/qr/{session_id}",
                                web::get().to(handlers::edge_compute::poll_wxy_qr_login),
                            )
                            .route(
                                "/wxy/auth/bind",
                                web::post().to(handlers::edge_compute::bind_wxy_token),
                            )
                            .route(
                                "/wxy/auth/status",
                                web::get().to(handlers::edge_compute::wxy_auth_status),
                            )
                            .route(
                                "/wxy/auth/refresh",
                                web::post().to(handlers::edge_compute::refresh_wxy_auth_token),
                            )
                            .route(
                                "/wxy/auth/logout",
                                web::post().to(handlers::edge_compute::wxy_logout),
                            )
                            .route(
                                "/wxy/adapter/inspect",
                                web::post().to(handlers::edge_compute::inspect_wxy_adapter),
                            )
                            .route(
                                "/self-check/startup",
                                web::get().to(handlers::edge_compute::get_startup_self_check),
                            )
                            .route(
                                "/self-check/run",
                                web::post().to(handlers::edge_compute::run_startup_self_check_now),
                            )
                            .route("/jobs/{job_id}", web::get().to(handlers::edge_compute::get_job))
                            .route(
                                "/jobs/{job_id}/cancel",
                                web::post().to(handlers::edge_compute::cancel_job),
                            )
                            .route(
                                "/jobs/{job_id}/retry",
                                web::post().to(handlers::edge_compute::retry_job),
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
    .client_request_timeout(std::time::Duration::from_secs(600))
    .client_disconnect_timeout(std::time::Duration::from_secs(30))
    .max_connection_rate(512)
    .bind(&bind_addr)?;

    let result = server.run().await;
    match &result {
        Ok(_) => {
            info!("Actix server exited normally");
            eprintln!("ACTIX_SERVER_EXIT_OK");
            #[cfg(target_os = "windows")]
            runtime_diag_log("ACTIX_SERVER_EXIT_OK");
        }
        Err(e) => {
            error!(
                "Actix server exited with error: {} (raw_os_error={:?})",
                e,
                e.raw_os_error()
            );
            eprintln!(
                "ACTIX_SERVER_EXIT_ERR raw_os_error={:?} err={}",
                e.raw_os_error(),
                e
            );
            #[cfg(target_os = "windows")]
            runtime_diag_log(&format!(
                "ACTIX_SERVER_EXIT_ERR raw_os_error={:?} err={}",
                e.raw_os_error(),
                e
            ));
        }
    }
    let _ = std::io::stderr().flush();

    result
}
