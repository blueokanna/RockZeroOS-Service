use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::config::AppConfig;

pub fn load_rustls_config(config: &AppConfig) -> std::io::Result<ServerConfig> {
    let cert_path = config
        .tls_cert_path
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "TLS_CERT_PATH 未配置"))?;

    let key_path = config
        .tls_key_path
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "TLS_KEY_PATH 未配置"))?;

    // 加载证书
    let cert_file = File::open(Path::new(cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<Certificate> = certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    if cert_chain.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "证书文件中没有找到有效证书",
        ));
    }

    let key_file = File::open(Path::new(key_path))?;
    let mut key_reader = BufReader::new(key_file);

    let private_key = load_private_key(&mut key_reader, key_path)?;

    // 构建 TLS 配置
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("TLS 配置错误: {}", e),
            )
        })?;

    Ok(config)
}

fn load_private_key(reader: &mut BufReader<File>, path: &str) -> std::io::Result<PrivateKey> {
    let keys = pkcs8_private_keys(reader)?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }

    let key_file = File::open(Path::new(path))?;
    let mut key_reader = BufReader::new(key_file);
    let keys = rsa_private_keys(&mut key_reader)?;

    if keys.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "私钥文件中没有找到有效私钥 (支持 PKCS8 和 RSA 格式)",
        ));
    }

    Ok(PrivateKey(keys[0].clone()))
}
