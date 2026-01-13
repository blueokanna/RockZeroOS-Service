use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub refresh_token_expiration_days: i64,
    pub encryption_key: String,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Self {
        // Check for command line arguments first
        let args: Vec<String> = env::args().collect();
        let mut port_override: Option<u16> = None;
        let mut host_override: Option<String> = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-p" | "--port" => {
                    if i + 1 < args.len() {
                        port_override = args[i + 1].parse().ok();
                        i += 1;
                    }
                }
                "-h" | "--host" => {
                    if i + 1 < args.len() {
                        host_override = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                arg if arg.starts_with("--port=") => {
                    port_override = arg.trim_start_matches("--port=").parse().ok();
                }
                arg if arg.starts_with("--host=") => {
                    host_override = Some(arg.trim_start_matches("--host=").to_string());
                }
                _ => {}
            }
            i += 1;
        }

        Self {
            host: host_override.unwrap_or_else(|| {
                env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string())
            }),
            port: port_override.unwrap_or_else(|| {
                env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()
                    .expect("PORT must be a valid number")
            }),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./rockzero.db?mode=rwc".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "default-dev-secret-change-in-production".to_string()),
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .expect("JWT_EXPIRATION_HOURS must be a valid number"),
            refresh_token_expiration_days: env::var("REFRESH_TOKEN_EXPIRATION_DAYS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .expect("REFRESH_TOKEN_EXPIRATION_DAYS must be a valid number"),
            encryption_key: env::var("ENCRYPTION_KEY")
                .unwrap_or_else(|_| "default-dev-key-change-in-production-32b".to_string()),
            tls_enabled: env::var("TLS_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            tls_cert_path: env::var("TLS_CERT_PATH").ok(),
            tls_key_path: env::var("TLS_KEY_PATH").ok(),
        }
    }

    pub fn print_usage() {
        println!("RockZero Secure Service");
        println!();
        println!("USAGE:");
        println!("    rockzero [OPTIONS]");
        println!();
        println!("OPTIONS:");
        println!("    -p, --port <PORT>    Set the server port (default: 8080)");
        println!("    -h, --host <HOST>    Set the server host (default: 0.0.0.0)");
        println!("    --help               Print this help message");
        println!();
        println!("ENVIRONMENT VARIABLES:");
        println!("    PORT                 Server port");
        println!("    HOST                 Server host");
        println!("    DATABASE_URL         SQLite database URL");
        println!("    JWT_SECRET           JWT signing secret");
        println!("    ENCRYPTION_KEY       Data encryption key");
        println!("    TLS_ENABLED          Enable TLS (true/false)");
        println!("    TLS_CERT_PATH        Path to TLS certificate");
        println!("    TLS_KEY_PATH         Path to TLS private key");
    }
}
