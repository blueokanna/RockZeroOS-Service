use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::process::Command;
use tracing::{error, info};
use uuid::Uuid;
use validator::Validate;

use crate::db;
use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DockerApp {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub icon: String,
    pub category: String,
    pub docker_image: String,
    pub docker_tag: String,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMapping>,
    pub environment: Vec<EnvVar>,
    pub status: String,
    pub container_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortMapping {
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VolumeMapping {
    pub container_path: String,
    pub host_path: String,
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
    pub required: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InstallAppRequest {
    #[validate(length(min = 1))]
    pub name: String,
    #[validate(length(min = 1))]
    pub docker_image: String,
    pub docker_tag: Option<String>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMapping>,
    pub environment: Vec<EnvVar>,
}

#[derive(Debug, Serialize)]
pub struct AppStoreItem {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub icon: String,
    pub category: String,
    pub docker_image: String,
    pub recommended_tag: String,
    pub default_ports: Vec<PortMapping>,
    pub default_volumes: Vec<VolumeMapping>,
    pub required_env: Vec<String>,
}

pub async fn list_store_apps() -> Result<impl Responder, AppError> {
    let apps = vec![
        // Cloud Storage
        AppStoreItem {
            id: "nextcloud".to_string(),
            name: "nextcloud".to_string(),
            display_name: "Nextcloud".to_string(),
            description: "Self-hosted cloud storage and collaboration platform".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/nextcloud.png".to_string(),
            category: "Cloud Storage".to_string(),
            docker_image: "nextcloud".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 80,
                host_port: 8080,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/var/www/html".to_string(),
                    host_path: "/DATA/AppData/nextcloud".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "filebrowser".to_string(),
            name: "filebrowser".to_string(),
            display_name: "File Browser".to_string(),
            description: "Web-based file manager with a clean interface".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/filebrowser.png".to_string(),
            category: "Cloud Storage".to_string(),
            docker_image: "filebrowser/filebrowser".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 80,
                host_port: 8081,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/srv".to_string(),
                    host_path: "/DATA".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/database.db".to_string(),
                    host_path: "/DATA/AppData/filebrowser/database.db".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        // Media
        AppStoreItem {
            id: "jellyfin".to_string(),
            name: "jellyfin".to_string(),
            display_name: "Jellyfin".to_string(),
            description: "Free software media system".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/jellyfin.png".to_string(),
            category: "Media".to_string(),
            docker_image: "jellyfin/jellyfin".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 8096,
                host_port: 8096,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/config".to_string(),
                    host_path: "/DATA/AppData/jellyfin/config".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/media".to_string(),
                    host_path: "/DATA/Media".to_string(),
                    mode: "ro".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "plex".to_string(),
            name: "plex".to_string(),
            display_name: "Plex".to_string(),
            description: "Stream movies, TV shows, music and more".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/plex.png".to_string(),
            category: "Media".to_string(),
            docker_image: "plexinc/pms-docker".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 32400,
                host_port: 32400,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/config".to_string(),
                    host_path: "/DATA/AppData/plex/config".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/media".to_string(),
                    host_path: "/DATA/Media".to_string(),
                    mode: "ro".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "navidrome".to_string(),
            name: "navidrome".to_string(),
            display_name: "Navidrome".to_string(),
            description: "Modern music server and streamer".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/navidrome.png".to_string(),
            category: "Media".to_string(),
            docker_image: "deluan/navidrome".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 4533,
                host_port: 4533,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/data".to_string(),
                    host_path: "/DATA/AppData/navidrome".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/music".to_string(),
                    host_path: "/DATA/Music".to_string(),
                    mode: "ro".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "photoprism".to_string(),
            name: "photoprism".to_string(),
            display_name: "PhotoPrism".to_string(),
            description: "AI-powered photo management".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/photoprism.png".to_string(),
            category: "Media".to_string(),
            docker_image: "photoprism/photoprism".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 2342,
                host_port: 2342,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/photoprism/storage".to_string(),
                    host_path: "/DATA/AppData/photoprism".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/photoprism/originals".to_string(),
                    host_path: "/DATA/Photos".to_string(),
                    mode: "ro".to_string(),
                },
            ],
            required_env: vec![],
        },
        // Download
        AppStoreItem {
            id: "qbittorrent".to_string(),
            name: "qbittorrent".to_string(),
            display_name: "qBittorrent".to_string(),
            description: "BitTorrent client with web UI".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/qbittorrent.png".to_string(),
            category: "Download".to_string(),
            docker_image: "linuxserver/qbittorrent".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 8080,
                    host_port: 8082,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 6881,
                    host_port: 6881,
                    protocol: "tcp".to_string(),
                },
            ],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/config".to_string(),
                    host_path: "/DATA/AppData/qbittorrent".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/downloads".to_string(),
                    host_path: "/DATA/Downloads".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "aria2".to_string(),
            name: "aria2".to_string(),
            display_name: "Aria2".to_string(),
            description: "Lightweight multi-protocol download utility".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/ariang.png".to_string(),
            category: "Download".to_string(),
            docker_image: "p3terx/aria2-pro".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 6800,
                    host_port: 6800,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 6888,
                    host_port: 6888,
                    protocol: "tcp".to_string(),
                },
            ],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/config".to_string(),
                    host_path: "/DATA/AppData/aria2".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/downloads".to_string(),
                    host_path: "/DATA/Downloads".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        // Management
        AppStoreItem {
            id: "portainer".to_string(),
            name: "portainer".to_string(),
            display_name: "Portainer".to_string(),
            description: "Docker container management UI".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/portainer.png".to_string(),
            category: "Management".to_string(),
            docker_image: "portainer/portainer-ce".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 9000,
                    host_port: 9000,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 8000,
                    host_port: 8000,
                    protocol: "tcp".to_string(),
                },
            ],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/data".to_string(),
                    host_path: "/DATA/AppData/portainer".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/var/run/docker.sock".to_string(),
                    host_path: "/var/run/docker.sock".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "heimdall".to_string(),
            name: "heimdall".to_string(),
            display_name: "Heimdall".to_string(),
            description: "Application dashboard and launcher".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/heimdall.png".to_string(),
            category: "Management".to_string(),
            docker_image: "linuxserver/heimdall".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 80,
                host_port: 8083,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/config".to_string(),
                host_path: "/DATA/AppData/heimdall".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
        // Smart Home
        AppStoreItem {
            id: "homeassistant".to_string(),
            name: "homeassistant".to_string(),
            display_name: "Home Assistant".to_string(),
            description: "Open source home automation platform".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/home-assistant.png".to_string(),
            category: "Smart Home".to_string(),
            docker_image: "homeassistant/home-assistant".to_string(),
            recommended_tag: "stable".to_string(),
            default_ports: vec![PortMapping {
                container_port: 8123,
                host_port: 8123,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/config".to_string(),
                host_path: "/DATA/AppData/homeassistant".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
        AppStoreItem {
            id: "mqtt".to_string(),
            name: "mqtt".to_string(),
            display_name: "Eclipse Mosquitto".to_string(),
            description: "Lightweight MQTT message broker".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/eclipse-mosquitto.png".to_string(),
            category: "Smart Home".to_string(),
            docker_image: "eclipse-mosquitto".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 1883,
                    host_port: 1883,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 9001,
                    host_port: 9001,
                    protocol: "tcp".to_string(),
                },
            ],
            default_volumes: vec![VolumeMapping {
                container_path: "/mosquitto".to_string(),
                host_path: "/DATA/AppData/mosquitto".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
        // Network
        AppStoreItem {
            id: "adguard".to_string(),
            name: "adguard".to_string(),
            display_name: "AdGuard Home".to_string(),
            description: "Network-wide ad and tracker blocking DNS server".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/adguard-home.png".to_string(),
            category: "Network".to_string(),
            docker_image: "adguard/adguardhome".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 3000,
                    host_port: 3000,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 53,
                    host_port: 53,
                    protocol: "udp".to_string(),
                },
            ],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/opt/adguardhome/work".to_string(),
                    host_path: "/DATA/AppData/adguard/work".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/opt/adguardhome/conf".to_string(),
                    host_path: "/DATA/AppData/adguard/conf".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        AppStoreItem {
            id: "nginx-proxy-manager".to_string(),
            name: "nginx-proxy-manager".to_string(),
            display_name: "Nginx Proxy Manager".to_string(),
            description: "Easy reverse proxy with SSL management".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/nginx-proxy-manager.png".to_string(),
            category: "Network".to_string(),
            docker_image: "jc21/nginx-proxy-manager".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![
                PortMapping {
                    container_port: 80,
                    host_port: 80,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 443,
                    host_port: 443,
                    protocol: "tcp".to_string(),
                },
                PortMapping {
                    container_port: 81,
                    host_port: 81,
                    protocol: "tcp".to_string(),
                },
            ],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/data".to_string(),
                    host_path: "/DATA/AppData/npm/data".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/etc/letsencrypt".to_string(),
                    host_path: "/DATA/AppData/npm/letsencrypt".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        // Database
        AppStoreItem {
            id: "mariadb".to_string(),
            name: "mariadb".to_string(),
            display_name: "MariaDB".to_string(),
            description: "Popular open source relational database".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/mariadb.png".to_string(),
            category: "Database".to_string(),
            docker_image: "mariadb".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 3306,
                host_port: 3306,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/var/lib/mysql".to_string(),
                host_path: "/DATA/AppData/mariadb".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec!["MYSQL_ROOT_PASSWORD".to_string()],
        },
        AppStoreItem {
            id: "redis".to_string(),
            name: "redis".to_string(),
            display_name: "Redis".to_string(),
            description: "In-memory data structure store".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/redis.png".to_string(),
            category: "Database".to_string(),
            docker_image: "redis".to_string(),
            recommended_tag: "alpine".to_string(),
            default_ports: vec![PortMapping {
                container_port: 6379,
                host_port: 6379,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/data".to_string(),
                host_path: "/DATA/AppData/redis".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
        // Productivity
        AppStoreItem {
            id: "vaultwarden".to_string(),
            name: "vaultwarden".to_string(),
            display_name: "Vaultwarden".to_string(),
            description: "Lightweight Bitwarden-compatible password manager".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/vaultwarden.png".to_string(),
            category: "Productivity".to_string(),
            docker_image: "vaultwarden/server".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 80,
                host_port: 8084,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/data".to_string(),
                host_path: "/DATA/AppData/vaultwarden".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
        AppStoreItem {
            id: "code-server".to_string(),
            name: "code-server".to_string(),
            display_name: "Code Server".to_string(),
            description: "VS Code in the browser".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/code-server.png".to_string(),
            category: "Productivity".to_string(),
            docker_image: "linuxserver/code-server".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 8443,
                host_port: 8443,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/config".to_string(),
                host_path: "/DATA/AppData/code-server".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec![],
        },
        // Stash - Media Organizer
        AppStoreItem {
            id: "stash".to_string(),
            name: "stash".to_string(),
            display_name: "Stash".to_string(),
            description: "An organizer for your adult media, written in Go".to_string(),
            icon: "https://raw.githubusercontent.com/stashapp/stash/develop/ui/v2.5/public/favicon.ico".to_string(),
            category: "Media".to_string(),
            docker_image: "stashapp/stash".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 9999,
                host_port: 9999,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/root/.stash".to_string(),
                    host_path: "/DATA/AppData/stash/config".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/data".to_string(),
                    host_path: "/DATA/Media".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/metadata".to_string(),
                    host_path: "/DATA/AppData/stash/metadata".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/cache".to_string(),
                    host_path: "/DATA/AppData/stash/cache".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/blobs".to_string(),
                    host_path: "/DATA/AppData/stash/blobs".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/generated".to_string(),
                    host_path: "/DATA/AppData/stash/generated".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        // Immich - Photo Management
        AppStoreItem {
            id: "immich".to_string(),
            name: "immich".to_string(),
            display_name: "Immich".to_string(),
            description: "High performance self-hosted photo and video backup solution".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/immich.png".to_string(),
            category: "Media".to_string(),
            docker_image: "ghcr.io/immich-app/immich-server".to_string(),
            recommended_tag: "release".to_string(),
            default_ports: vec![PortMapping {
                container_port: 3001,
                host_port: 2283,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![VolumeMapping {
                container_path: "/usr/src/app/upload".to_string(),
                host_path: "/DATA/AppData/immich/upload".to_string(),
                mode: "rw".to_string(),
            }],
            required_env: vec!["DB_PASSWORD".to_string()],
        },
        // Kavita - eBook/Manga Reader
        AppStoreItem {
            id: "kavita".to_string(),
            name: "kavita".to_string(),
            display_name: "Kavita".to_string(),
            description: "A fast, feature rich, cross platform reading server".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/kavita.png".to_string(),
            category: "Media".to_string(),
            docker_image: "kizaing/kavita".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 5000,
                host_port: 5000,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/kavita/config".to_string(),
                    host_path: "/DATA/AppData/kavita/config".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/manga".to_string(),
                    host_path: "/DATA/Media/Manga".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
        // Audiobookshelf
        AppStoreItem {
            id: "audiobookshelf".to_string(),
            name: "audiobookshelf".to_string(),
            display_name: "Audiobookshelf".to_string(),
            description: "Self-hosted audiobook and podcast server".to_string(),
            icon: "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/audiobookshelf.png".to_string(),
            category: "Media".to_string(),
            docker_image: "ghcr.io/advplyr/audiobookshelf".to_string(),
            recommended_tag: "latest".to_string(),
            default_ports: vec![PortMapping {
                container_port: 80,
                host_port: 13378,
                protocol: "tcp".to_string(),
            }],
            default_volumes: vec![
                VolumeMapping {
                    container_path: "/config".to_string(),
                    host_path: "/DATA/AppData/audiobookshelf/config".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/metadata".to_string(),
                    host_path: "/DATA/AppData/audiobookshelf/metadata".to_string(),
                    mode: "rw".to_string(),
                },
                VolumeMapping {
                    container_path: "/audiobooks".to_string(),
                    host_path: "/DATA/Media/Audiobooks".to_string(),
                    mode: "rw".to_string(),
                },
            ],
            required_env: vec![],
        },
    ];

    Ok(HttpResponse::Ok().json(apps))
}

pub async fn list_installed_apps(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let apps = db::list_installed_apps(&pool, &claims.sub).await?;
    
    let mut enriched_apps = Vec::new();
    for mut app in apps {
        if let Some(container_id) = &app.container_id {
            let status = get_container_status(container_id).await;
            app.status = status;
        }
        enriched_apps.push(app);
    }

    Ok(HttpResponse::Ok().json(enriched_apps))
}

pub async fn install_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    body: web::Json<InstallAppRequest>,
) -> Result<impl Responder, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let tag = body.docker_tag.clone().unwrap_or_else(|| "latest".to_string());
    let full_image = format!("{}:{}", body.docker_image, tag);

    info!("Pulling Docker image: {}", full_image);
    let pull_output = Command::new("docker")
        .args(["pull", &full_image])
        .output()
        .map_err(|e| {
            error!("Failed to pull image: {}", e);
            AppError::InternalError
        })?;

    if !pull_output.status.success() {
        error!("Docker pull failed: {}", String::from_utf8_lossy(&pull_output.stderr));
        return Err(AppError::BadRequest("Failed to pull Docker image".to_string()));
    }

    let container_name = format!("rockzero-{}-{}", body.name, &Uuid::new_v4().to_string()[..8]);
    
    let mut docker_args: Vec<String> = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        container_name.clone(),
        "--restart".to_string(),
        "unless-stopped".to_string(),
    ];

    // Add port mappings: -p host_port:container_port/protocol
    for p in &body.ports {
        docker_args.push("-p".to_string());
        docker_args.push(format!("{}:{}/{}", p.host_port, p.container_port, p.protocol));
    }

    // Add volume mappings: -v host_path:container_path:mode
    for v in &body.volumes {
        docker_args.push("-v".to_string());
        docker_args.push(format!("{}:{}:{}", v.host_path, v.container_path, v.mode));
    }

    // Add environment variables: -e key=value
    for e in &body.environment {
        docker_args.push("-e".to_string());
        docker_args.push(format!("{}={}", e.key, e.value));
    }

    docker_args.push(full_image.clone());

    info!("Starting container: {} with args: {:?}", container_name, docker_args);
    let args_refs: Vec<&str> = docker_args.iter().map(|s| s.as_str()).collect();
    let run_output = Command::new("docker")
        .args(&args_refs)
        .output()
        .map_err(|e| {
            error!("Failed to start container: {}", e);
            AppError::InternalError
        })?;

    if !run_output.status.success() {
        error!("Docker run failed: {}", String::from_utf8_lossy(&run_output.stderr));
        return Err(AppError::BadRequest("Failed to start container".to_string()));
    }

    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    let app = DockerApp {
        id: Uuid::new_v4().to_string(),
        name: body.name.clone(),
        display_name: body.name.clone(),
        description: format!("Docker app: {}", body.docker_image),
        icon: "".to_string(),
        category: "Custom".to_string(),
        docker_image: body.docker_image.clone(),
        docker_tag: tag,
        ports: body.ports.clone(),
        volumes: body.volumes.clone(),
        environment: body.environment.clone(),
        status: "running".to_string(),
        container_id: Some(container_id.clone()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    db::create_installed_app(&pool, &app, &claims.sub).await?;

    info!("App installed: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Created().json(app))
}

pub async fn uninstall_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    if let Some(container_id) = &app.container_id {
        info!("Stopping container: {}", container_id);
        Command::new("docker")
            .args(["stop", container_id])
            .output()
            .ok();

        info!("Removing container: {}", container_id);
        Command::new("docker")
            .args(["rm", container_id])
            .output()
            .ok();
    }

    db::delete_installed_app(&pool, &app_id, &claims.sub).await?;

    info!("App uninstalled: {}", app.name);

    Ok(HttpResponse::NoContent().finish())
}

pub async fn start_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    let container_id = app.container_id
        .ok_or_else(|| AppError::BadRequest("No container ID".to_string()))?;

    let output = Command::new("docker")
        .args(["start", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Failed to start container".to_string()));
    }

    info!("App started: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "started"})))
}

pub async fn stop_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    let container_id = app.container_id
        .ok_or_else(|| AppError::BadRequest("No container ID".to_string()))?;

    let output = Command::new("docker")
        .args(["stop", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Failed to stop container".to_string()));
    }

    info!("App stopped: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "stopped"})))
}

pub async fn restart_app(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::auth::Claims>,
    app_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let app = db::find_installed_app(&pool, &app_id, &claims.sub).await?
        .ok_or_else(|| AppError::NotFound("App not found".to_string()))?;

    let container_id = app.container_id
        .ok_or_else(|| AppError::BadRequest("No container ID".to_string()))?;

    let output = Command::new("docker")
        .args(["restart", &container_id])
        .output()
        .map_err(|_| AppError::InternalError)?;

    if !output.status.success() {
        return Err(AppError::BadRequest("Failed to restart container".to_string()));
    }

    info!("App restarted: {} (container: {})", app.name, container_id);

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "restarted"})))
}

async fn get_container_status(container_id: &str) -> String {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", container_id])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}
