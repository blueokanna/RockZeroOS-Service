#![allow(dead_code)]

use actix_web::{web, HttpRequest, HttpResponse};
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ============================================================================
// 响应缓存 — 避免每次请求都调用外部 API（Steam/Epic 等）
// ============================================================================

/// 缓存条目：保存响应数据与过期时间
struct CacheEntry {
    data: Vec<Value>,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// 全局 API 响应缓存（懒初始化，线程安全）
static CACHE: std::sync::OnceLock<Arc<RwLock<HashMap<String, CacheEntry>>>> =
    std::sync::OnceLock::new();

fn get_cache() -> &'static Arc<RwLock<HashMap<String, CacheEntry>>> {
    CACHE.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// 默认缓存 TTL：5 分钟（Steam/Epic 数据不需要实时更新）
const CACHE_TTL_SECS: u64 = 300;

/// 从缓存读取数据；如果过期或不存在返回 None
async fn cache_get(key: &str) -> Option<Vec<Value>> {
    let cache = get_cache().read().await;
    cache.get(key).and_then(|entry| {
        if entry.is_expired() {
            None
        } else {
            Some(entry.data.clone())
        }
    })
}

/// Read cache even if expired. Used as graceful fallback when upstream APIs fail.
async fn cache_get_stale(key: &str) -> Option<Vec<Value>> {
    let cache = get_cache().read().await;
    cache.get(key).map(|entry| entry.data.clone())
}

/// 写入缓存
async fn cache_set(key: &str, data: Vec<Value>, ttl_secs: u64) {
    let mut cache = get_cache().write().await;
    cache.insert(
        key.to_string(),
        CacheEntry {
            data,
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
        },
    );
}

// ============================================================================
// 数据模型
// ============================================================================

/// WASM 应用信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmApp {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub icon_url: String,
    pub wasm_url: String,
    pub category: WasmAppCategory,
    pub size_bytes: u64,
    pub installed: bool,
    pub installed_path: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WasmAppCategory {
    Game,
    Tool,
    Media,
    Web3,
    Social,
    Productivity,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: String,
    pub description: String,
    pub author: String,
    pub entry_point: String,
    pub capabilities: Vec<String>,
    pub config_schema: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreCategory {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub count: i64,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub category: Option<String>,
    pub platform: Option<String>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub sort: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StoreOverview {
    pub categories: Vec<StoreCategory>,
    pub wasm_apps: Vec<WasmApp>,
    pub total_wasm_apps: i64,
    pub available_plugins: Vec<PluginManifest>,
    pub featured_games: Vec<Value>,
    pub free_games: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

#[derive(Debug, Deserialize)]
pub struct InstallWasmAppRequest {
    pub app_id: String,
    pub wasm_url: String,
    pub name: String,
    pub expected_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunWasmAppRequest {
    pub function: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPluginRequest {
    pub manifest: PluginManifest,
    pub wasm_url: String,
}

// ============================================================================
// WASM 应用存储管理
// ============================================================================

fn wasm_store_root() -> PathBuf {
    if let Ok(path) = std::env::var("WASM_STORE_ROOT") {
        return PathBuf::from(path);
    }
    if let Ok(ext) = std::env::var("EXTERNAL_STORAGE_PATH") {
        return PathBuf::from(ext).join("wasm_store");
    }
    PathBuf::from("/mnt/external/wasm_store")
}

fn wasm_registry_path() -> PathBuf {
    wasm_store_root().join("registry.json")
}

fn plugin_registry_path() -> PathBuf {
    wasm_store_root().join("plugins.json")
}

/// 从磁盘加载 WASM 应用注册信息（使用 spawn_blocking 避免阻塞 async 运行时）
async fn load_wasm_registry_async() -> Result<Vec<WasmApp>, AppError> {
    tokio::task::spawn_blocking(load_wasm_registry)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Task join error: {}", e)))?
}

fn load_wasm_registry() -> Result<Vec<WasmApp>, AppError> {
    let path = wasm_registry_path();
    let mut apps: Vec<WasmApp> = if path.exists() {
        let data =
            std::fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
        if data.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&data).unwrap_or_else(|e| {
                warn!("WASM registry JSON parse error: {}, returning empty", e);
                Vec::new()
            })
        }
    } else {
        Vec::new()
    };

    // 注入内置 WASM 应用（如果尚未注册）
    inject_builtin_apps(&mut apps);

    Ok(apps)
}

/// 内置 WASM 应用 — 始终显示在商店中
fn builtin_wasm_apps() -> Vec<WasmApp> {
    vec![
        WasmApp {
            id: "steamdb-viewer".to_string(),
            name: "SteamDB 数据查看器".to_string(),
            description: "查看 Steam 游戏详细数据：历史价格、在线人数、仓库信息、DLC 列表等"
                .to_string(),
            version: "1.0.0".to_string(),
            author: "RockZero".to_string(),
            icon_url: "https://steamdb.info/static/img/steamdb.svg".to_string(),
            wasm_url: String::new(), // 内置应用，不需要远程 URL
            category: WasmAppCategory::Tool,
            size_bytes: 0,
            installed: false,
            installed_path: None,
            permissions: vec![
                "net:https://store.steampowered.com".to_string(),
                "net:https://api.steampowered.com".to_string(),
            ],
            created_at: 0,
            updated_at: 0,
        },
        WasmApp {
            id: "m3u8-downloader".to_string(),
            name: "M3U8 视频下载器".to_string(),
            description:
                "解析 M3U8 播放列表并下载 TS 分片，自动合并为完整视频文件，支持 AES 解密"
                    .to_string(),
            version: "1.0.0".to_string(),
            author: "blueokanna".to_string(),
            icon_url: String::new(),
            wasm_url: String::new(),
            category: WasmAppCategory::Media,
            size_bytes: 0,
            installed: false,
            installed_path: None,
            permissions: vec!["net:*".to_string(), "fs:downloads".to_string()],
            created_at: 0,
            updated_at: 0,
        },
        WasmApp {
            id: "steam-p2p-info".to_string(),
            name: "Steam P2P 连接信息".to_string(),
            description:
                "显示 Steam 游戏中的 P2P 连接详情：对端 IP、延迟、Steam ID、地理位置等"
                    .to_string(),
            version: "1.0.0".to_string(),
            author: "tremwil".to_string(),
            icon_url: String::new(),
            wasm_url: String::new(),
            category: WasmAppCategory::Tool,
            size_bytes: 0,
            installed: false,
            installed_path: None,
            permissions: vec![
                "net:https://api.steampowered.com".to_string(),
                "process:steam".to_string(),
            ],
            created_at: 0,
            updated_at: 0,
        },
        WasmApp {
            id: "wxy-edge-node".to_string(),
            name: "网心云边缘节点".to_string(),
            description: "网心云账号状态、扫码登录与边缘节点运行状态查看".to_string(),
            version: "1.0.0".to_string(),
            author: "RockZero".to_string(),
            icon_url: String::new(),
            wasm_url: String::new(),
            category: WasmAppCategory::Tool,
            size_bytes: 0,
            installed: false,
            installed_path: None,
            permissions: vec!["net:/api/v1/edge/*".to_string()],
            created_at: 0,
            updated_at: 0,
        },
    ]
}

/// 将内置应用注入到注册表中（不覆盖已存在的同 id 应用）
fn inject_builtin_apps(apps: &mut Vec<WasmApp>) {
    for builtin in builtin_wasm_apps() {
        if !apps.iter().any(|a| a.id == builtin.id) {
            apps.push(builtin);
        }
    }
}

fn save_wasm_registry(apps: &[WasmApp]) -> Result<(), AppError> {
    let root = wasm_store_root();
    std::fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = wasm_registry_path();
    let data = serde_json::to_string_pretty(apps)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    std::fs::write(path, data).map_err(|e| AppError::IoError(e.to_string()))
}

fn load_plugin_registry() -> Result<Vec<PluginManifest>, AppError> {
    let path = plugin_registry_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    if data.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
}

fn save_plugin_registry(plugins: &[PluginManifest]) -> Result<(), AppError> {
    let root = wasm_store_root();
    std::fs::create_dir_all(&root).map_err(|e| AppError::IoError(e.to_string()))?;
    let path = plugin_registry_path();
    let data = serde_json::to_string_pretty(plugins)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;
    std::fs::write(path, data).map_err(|e| AppError::IoError(e.to_string()))
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ============================================================================
// HTTP 处理函数
// ============================================================================

/// GET /api/v1/wasm-store/overview - 商店首页概览
///
/// **关键优化**：
///   1. 先立即返回本地 WASM 注册表和插件（无网络延迟）
///   2. Steam/Epic 数据优先从缓存读取；如果缓存命中则 0 网络延迟
///   3. 缓存未命中时并行请求外部 API，设置 5 秒超时
///   4. 外部 API 失败绝不阻塞页面 — 降级为空数组
pub async fn get_store_overview() -> Result<HttpResponse, AppError> {
    info!("获取 WASM 商店概览");

    // 本地数据立即可用
    let wasm_apps = load_wasm_registry_async().await.unwrap_or_default();
    let plugins = tokio::task::spawn_blocking(|| load_plugin_registry().unwrap_or_default())
        .await
        .unwrap_or_default();

    // 优先从缓存获取外部 API 数据
    let cached_steam = cache_get("steam_featured").await;
    let cached_epic = cache_get("epic_free").await;

    let (featured_games, free_games) = match (&cached_steam, &cached_epic) {
        // 两者都有缓存 — 零网络延迟
        (Some(steam), Some(epic)) => (steam.clone(), epic.clone()),
        // 至少一个缓存缺失 — 并行获取，但设置较短超时
        _ => {
            let client = Client::builder()
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(3))
                .build()
                .unwrap_or_default();

            let (steam_result, epic_result) = tokio::join!(
                fetch_steam_featured_cached(&client),
                fetch_epic_free_cached(&client),
            );

            (
                steam_result.unwrap_or_default(),
                epic_result.unwrap_or_default(),
            )
        }
    };

    let categories = vec![
        StoreCategory {
            id: "wasm_apps".to_string(),
            name: "WASM 应用".to_string(),
            icon: "📦".to_string(),
            count: wasm_apps.len() as i64,
        },
        StoreCategory {
            id: "games".to_string(),
            name: "WASM 游戏".to_string(),
            icon: "🎮".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Game)
                .count() as i64,
        },
        StoreCategory {
            id: "tools".to_string(),
            name: "工具".to_string(),
            icon: "🔧".to_string(),
            count: wasm_apps
                .iter()
                .filter(|a| a.category == WasmAppCategory::Tool)
                .count() as i64,
        },
        StoreCategory {
            id: "steam".to_string(),
            name: "Steam".to_string(),
            icon: "🎮".to_string(),
            count: featured_games.len() as i64,
        },
        StoreCategory {
            id: "epic_free".to_string(),
            name: "Epic 免费".to_string(),
            icon: "🎁".to_string(),
            count: free_games.len() as i64,
        },
        StoreCategory {
            id: "plugins".to_string(),
            name: "扩展插件".to_string(),
            icon: "🔌".to_string(),
            count: plugins.len() as i64,
        },
    ];

    let overview = StoreOverview {
        total_wasm_apps: wasm_apps.len() as i64,
        categories,
        wasm_apps,
        available_plugins: plugins,
        featured_games,
        free_games,
    };

    Ok(HttpResponse::Ok().json(overview))
}

// ============================================================================
// Steam / Epic 数据获取（带缓存）
// ============================================================================

/// 获取 Steam 精选，优先走缓存
async fn fetch_steam_featured_cached(client: &Client) -> Result<Vec<Value>, AppError> {
    if let Some(cached) = cache_get("steam_featured").await {
        return Ok(cached);
    }
    let data = fetch_steam_featured_internal(client).await?;
    cache_set("steam_featured", data.clone(), CACHE_TTL_SECS).await;
    Ok(data)
}

/// 获取 Epic 免费游戏，优先走缓存
async fn fetch_epic_free_cached(client: &Client) -> Result<Vec<Value>, AppError> {
    if let Some(cached) = cache_get("epic_free").await {
        return Ok(cached);
    }
    let data = fetch_epic_free_internal(client).await?;
    cache_set("epic_free", data.clone(), CACHE_TTL_SECS).await;
    Ok(data)
}

/// 内部函数：获取 Steam 精选游戏列表
async fn fetch_steam_featured_internal(client: &Client) -> Result<Vec<Value>, AppError> {
    let resp = match client
        .get("https://store.steampowered.com/api/featured/")
        .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Steam API 请求失败 (网络/超时): {}", e);
            return Ok(Vec::new());
        }
    };

    if !resp.status().is_success() {
        warn!("Steam API 返回非 200: {}", resp.status());
        return Ok(Vec::new());
    }

    let json: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("Steam JSON 解析失败: {}", e);
            return Ok(Vec::new());
        }
    };

    let mut games = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for section_key in &[
        "featured_win",
        "featured_mac",
        "featured_linux",
        "large_capsules",
    ] {
        if let Some(items) = json.get(section_key).and_then(|v| v.as_array()) {
            for item in items {
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let app_id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                if name.is_empty() || app_id == 0 || !seen_ids.insert(app_id) {
                    continue;
                }

                let header_image = item
                    .get("header_image")
                    .or_else(|| item.get("large_capsule_image"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let is_free = item
                    .get("discount_percent")
                    .and_then(|v| v.as_u64())
                    .map(|d| d == 100)
                    .unwrap_or(false)
                    || item
                        .get("final_price")
                        .and_then(|v| v.as_u64())
                        .map(|p| p == 0)
                        .unwrap_or(false);

                let original_price = item
                    .get("original_price")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let final_price = item
                    .get("final_price")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                let formatted_price = if is_free {
                    "免费".to_string()
                } else if final_price > 0 {
                    format!("¥{:.2}", final_price as f64 / 100.0)
                } else {
                    String::new()
                };

                games.push(serde_json::json!({
                    "name": name,
                    "app_id": app_id,
                    "header_image": header_image,
                    "is_free": is_free,
                    "platform": "steam",
                    "store_url": format!("https://store.steampowered.com/app/{}", app_id),
                    "price": {
                        "original": original_price,
                        "final": final_price,
                        "formatted": formatted_price,
                    },
                    "short_description": "",
                    "genres": [],
                }));
            }
        }
    }

    info!("Steam 精选: 获取到 {} 款游戏", games.len());
    Ok(games)
}

/// 内部函数：获取 Epic 免费游戏列表
async fn fetch_epic_free_internal(client: &Client) -> Result<Vec<Value>, AppError> {
    // ---- 策略 1: 使用 Epic 官方 GraphQL API ----
    if let Some(games) = fetch_epic_graphql(client).await {
        if !games.is_empty() {
            info!("Epic 免费游戏 (GraphQL): 获取到 {} 款", games.len());
            return Ok(games);
        }
    }

    // ---- 策略 2: 使用 Epic Store 促销 API (不同域名/路径) ----
    if let Some(games) = fetch_epic_store_promo(client).await {
        if !games.is_empty() {
            info!("Epic 免费游戏 (Promo API): 获取到 {} 款", games.len());
            return Ok(games);
        }
    }

    warn!("Epic 所有获取策略均失败，返回空列表");
    Ok(Vec::new())
}

/// 策略 1: Epic 官方 GraphQL — 可能被某些地区 DNS/防火墙阻断
async fn fetch_epic_graphql(client: &Client) -> Option<Vec<Value>> {
    let query_body = serde_json::json!({
        "query": r#"query searchStoreQuery($allowCountries: String, $category: String, $count: Int, $country: String!, $keywords: String, $locale: String, $namespace: String, $sortBy: String, $sortDir: String, $start: Int, $tag: String, $withPrice: Boolean = true, $freeGame: Boolean, $onSale: Boolean) {
            Catalog {
                searchStore(allowCountries: $allowCountries, category: $category, count: $count, country: $country, keywords: $keywords, locale: $locale, namespace: $namespace, sortBy: $sortBy, sortDir: $sortDir, start: $start, tag: $tag, freeGame: $freeGame, onSale: $onSale) {
                    elements {
                        title
                        id
                        namespace
                        description
                        keyImages {
                            type
                            url
                        }
                        seller {
                            name
                        }
                        price(country: $country) @include(if: $withPrice) {
                            totalPrice {
                                discountPrice
                                originalPrice
                                currencyCode
                                fmtPrice(locale: "zh-CN") {
                                    originalPrice
                                    discountPrice
                                    intermediatePrice
                                }
                            }
                            lineOffers {
                                appliedRules {
                                    endDate
                                }
                            }
                        }
                        promotions(category: $category) @include(if: $withPrice) {
                            promotionalOffers {
                                promotionalOffers {
                                    startDate
                                    endDate
                                    discountSetting {
                                        discountType
                                        discountPercentage
                                    }
                                }
                            }
                            upcomingPromotionalOffers {
                                promotionalOffers {
                                    startDate
                                    endDate
                                    discountSetting {
                                        discountType
                                        discountPercentage
                                    }
                                }
                            }
                        }
                    }
                    paging {
                        count
                        total
                    }
                }
            }
        }"#,
        "variables": {
            "category": "games/edition/base|bundles/games|editors|software/edition/base",
            "count": 30,
            "country": "CN",
            "freeGame": true,
            "locale": "zh-CN",
            "sortBy": "releaseDate",
            "sortDir": "DESC",
            "start": 0,
            "withPrice": true,
        }
    });

    let resp = match client
        .post("https://graphql.epicgames.com/graphql")
        .header("Content-Type", "application/json")
        .json(&query_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Epic GraphQL 请求失败 (网络/超时): {}", e);
            return None;
        }
    };

    if !resp.status().is_success() {
        warn!("Epic GraphQL 返回非 200: {}", resp.status());
        return None;
    }

    let json: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("Epic GraphQL JSON 解析失败: {}", e);
            return None;
        }
    };

    Some(parse_epic_elements(&json))
}

/// 策略 2: Epic Store Free Games 促销 API（备用端点）
async fn fetch_epic_store_promo(client: &Client) -> Option<Vec<Value>> {
    // 使用 Epic 的 catalog search REST 端点作为备选
    let url = "https://store-site-backend-official.ak.epicgames.com/freeGamesPromotions?locale=zh-CN&country=CN&allowCountries=CN";

    let resp = match client
        .get(url)
        .header("User-Agent", "RockZeroOS/1.0")
        .header("Accept", "application/json")
        .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Epic Promo API 请求失败: {}", e);
            return None;
        }
    };

    if !resp.status().is_success() {
        warn!("Epic Promo API 返回非 200: {}", resp.status());
        return None;
    }

    let json: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("Epic Promo API JSON 解析失败: {}", e);
            return None;
        }
    };

    // Promo API 的数据结构路径不同
    let elements = json
        .pointer("/data/Catalog/searchStore/elements")
        .and_then(|v| v.as_array());

    if let Some(elems) = elements {
        let games = parse_epic_elements_from_array(elems);
        if !games.is_empty() {
            return Some(games);
        }
    }

    None
}

/// 从 Epic GraphQL 响应解析游戏列表
fn parse_epic_elements(json: &Value) -> Vec<Value> {
    if let Some(elements) = json
        .pointer("/data/Catalog/searchStore/elements")
        .and_then(|v| v.as_array())
    {
        parse_epic_elements_from_array(elements)
    } else {
        Vec::new()
    }
}

/// 从 Epic elements 数组解析游戏条目
fn parse_epic_elements_from_array(elements: &[Value]) -> Vec<Value> {
    let mut games = Vec::new();

    for elem in elements {
            let title = elem.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let id = elem.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let description = elem
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if title.is_empty() {
                continue;
            }

            let header_image = elem
                .get("keyImages")
                .and_then(|v| v.as_array())
                .and_then(|images| {
                    images
                        .iter()
                        .find(|img| {
                            img.get("type")
                                .and_then(|t| t.as_str())
                                .map(|t| {
                                    t == "OfferImageWide"
                                        || t == "DieselStoreFrontWide"
                                        || t == "Thumbnail"
                                })
                                .unwrap_or(false)
                        })
                        .or_else(|| images.first())
                        .and_then(|img| img.get("url").and_then(|u| u.as_str()))
                })
                .unwrap_or("");

            let seller = elem
                .pointer("/seller/name")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let has_active_promo = elem
                .pointer("/promotions/promotionalOffers")
                .and_then(|v| v.as_array())
                .map(|offers| !offers.is_empty())
                .unwrap_or(false);

            let original_price_str = elem
                .pointer("/price/totalPrice/fmtPrice/originalPrice")
                .and_then(|v| v.as_str())
                .unwrap_or("0");

            let discount_price = elem
                .pointer("/price/totalPrice/discountPrice")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let is_free = discount_price == 0;
            let formatted_price = if is_free {
                "免费".to_string()
            } else {
                format!("¥{:.2}", discount_price as f64 / 100.0)
            };

            let namespace = elem
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let store_url = if !namespace.is_empty() {
                format!("https://store.epicgames.com/zh-CN/p/{}", namespace)
            } else {
                "https://store.epicgames.com/zh-CN/free-games".to_string()
            };

            games.push(serde_json::json!({
                "name": title,
                "id": id,
                "header_image": header_image,
                "is_free": is_free,
                "has_active_promo": has_active_promo,
                "platform": "epic",
                "store_url": store_url,
                "short_description": description,
                "seller": seller,
                "price": {
                    "original": original_price_str,
                    "formatted": formatted_price,
                },
                "genres": [],
            }));
        }

    games
}

/// GET /api/v1/wasm-store/steam/featured - Steam 精选游戏
pub async fn get_steam_featured() -> Result<HttpResponse, AppError> {
    info!("获取 Steam 精选游戏");
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let games = fetch_steam_featured_cached(&client)
        .await
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": games,
        "total": games.len(),
    })))
}

/// GET /api/v1/wasm-store/steam/app/{app_id} - Steam 游戏详情
pub async fn get_steam_app_details(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("获取 Steam 游戏详情: {}", app_id);

    // 缓存单个游戏详情
    let cache_key = format!("steam_app_{}", app_id);
    if let Some(cached) = cache_get(&cache_key).await {
        if let Some(first) = cached.into_iter().next() {
            return Ok(HttpResponse::Ok().json(first));
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let url = format!(
        "https://store.steampowered.com/api/appdetails?appids={}&l=schinese&cc=CN",
        app_id
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Steam API error: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::InternalServerError(
            "Steam API 请求失败".to_string(),
        ));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| AppError::InternalServerError(format!("JSON parse error: {}", e)))?;

    let data = json
        .get(&app_id)
        .and_then(|v| v.get("data"))
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // 缓存 10 分钟
    cache_set(&cache_key, vec![data.clone()], 600).await;

    Ok(HttpResponse::Ok().json(data))
}

// ============================================================================
// Steam 用户游戏库 — 获取玩家拥有的游戏及游玩时间
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SteamLibraryQuery {
    pub steam_id: String,
    /// Steam Web API Key (optional, reads from env STEAM_API_KEY if unset)
    pub api_key: Option<String>,
}

/// GET /api/v1/wasm-store/steam/library - 获取 Steam 用户的游戏库（含游玩时间）
pub async fn get_steam_user_library(
    query: web::Query<SteamLibraryQuery>,
) -> Result<HttpResponse, AppError> {
    let steam_id = &query.steam_id;
    info!("获取 Steam 用户游戏库: {}", steam_id);

    let api_key = query
        .api_key
        .clone()
        .or_else(|| std::env::var("STEAM_API_KEY").ok())
        .ok_or_else(|| {
            AppError::BadRequest(
                "Steam API Key 未提供。请在请求中提供 api_key 参数或设置 STEAM_API_KEY 环境变量"
                    .to_string(),
            )
        })?;

    // Try cache first
    let cache_key = format!("steam_library_{}", steam_id);
    if let Some(cached) = cache_get(&cache_key).await {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "steam_id": steam_id,
            "games": cached,
            "total": cached.len(),
            "cached": true,
        })));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // Call Steam IPlayerService/GetOwnedGames
    let url = format!(
        "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/?key={}&steamid={}&format=json&include_appinfo=1&include_played_free_games=1",
        api_key, steam_id
    );

    let resp = client.get(&url).send().await.map_err(|e| {
        AppError::InternalServerError(format!("Steam API 请求失败: {}", e))
    })?;

    if !resp.status().is_success() {
        return Err(AppError::InternalServerError(format!(
            "Steam API 返回错误: {}",
            resp.status()
        )));
    }

    let json: Value = resp.json().await.map_err(|e| {
        AppError::InternalServerError(format!("Steam JSON 解析失败: {}", e))
    })?;

    let mut games = Vec::new();

    if let Some(game_list) = json
        .pointer("/response/games")
        .and_then(|v| v.as_array())
    {
        for game in game_list {
            let appid = game.get("appid").and_then(|v| v.as_u64()).unwrap_or(0);
            let name = game
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let playtime_forever = game
                .get("playtime_forever")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let playtime_2weeks = game
                .get("playtime_2weeks")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let img_icon_url = game
                .get("img_icon_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let playtime_linux = game
                .get("playtime_linux_forever")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let playtime_mac = game
                .get("playtime_mac_forever")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let playtime_windows = game
                .get("playtime_windows_forever")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let rtime_last_played = game
                .get("rtime_last_played")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let header_image = if appid > 0 {
                format!(
                    "https://cdn.akamai.steamstatic.com/steam/apps/{}/header.jpg",
                    appid
                )
            } else {
                String::new()
            };

            let icon_url = if !img_icon_url.is_empty() && appid > 0 {
                format!(
                    "https://media.steampowered.com/steamcommunity/public/images/apps/{}/{}",
                    appid, img_icon_url
                )
            } else {
                String::new()
            };

            // Format playtime
            let hours = playtime_forever / 60;
            let minutes = playtime_forever % 60;
            let playtime_formatted = if hours > 0 {
                format!("{}h {}m", hours, minutes)
            } else {
                format!("{}m", minutes)
            };

            games.push(serde_json::json!({
                "appid": appid,
                "name": name,
                "playtime_forever": playtime_forever,
                "playtime_2weeks": playtime_2weeks,
                "playtime_formatted": playtime_formatted,
                "playtime_hours": playtime_forever as f64 / 60.0,
                "playtime_linux": playtime_linux,
                "playtime_mac": playtime_mac,
                "playtime_windows": playtime_windows,
                "rtime_last_played": rtime_last_played,
                "header_image": header_image,
                "icon_url": icon_url,
                "store_url": format!("https://store.steampowered.com/app/{}", appid),
                "platform": "steam",
            }));
        }
    }

    // Sort by playtime descending
    games.sort_by(|a, b| {
        let a_time = a
            .get("playtime_forever")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let b_time = b
            .get("playtime_forever")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        b_time.cmp(&a_time)
    });

    let total = games.len();

    // Cache for 10 minutes
    cache_set(&cache_key, games.clone(), 600).await;

    info!("Steam 用户游戏库: {} 款游戏", total);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "steam_id": steam_id,
        "games": games,
        "total": total,
        "cached": false,
    })))
}

/// GET /api/v1/wasm-store/steam/player - 获取 Steam 用户资料
pub async fn get_steam_player_summary(
    query: web::Query<SteamLibraryQuery>,
) -> Result<HttpResponse, AppError> {
    let steam_id = &query.steam_id;
    info!("获取 Steam 用户资料: {}", steam_id);

    let api_key = query
        .api_key
        .clone()
        .or_else(|| std::env::var("STEAM_API_KEY").ok())
        .ok_or_else(|| {
            AppError::BadRequest("Steam API Key 未提供".to_string())
        })?;

    let cache_key = format!("steam_player_{}", steam_id);
    if let Some(cached) = cache_get(&cache_key).await {
        if let Some(first) = cached.into_iter().next() {
            return Ok(HttpResponse::Ok().json(first));
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let url = format!(
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={}&steamids={}",
        api_key, steam_id
    );

    let resp = client.get(&url).send().await.map_err(|e| {
        AppError::InternalServerError(format!("Steam API 请求失败: {}", e))
    })?;

    let json: Value = resp.json().await.map_err(|e| {
        AppError::InternalServerError(format!("JSON 解析失败: {}", e))
    })?;

    let player = json
        .pointer("/response/players/0")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    cache_set(&cache_key, vec![player.clone()], 300).await;

    Ok(HttpResponse::Ok().json(player))
}

/// GET /api/v1/wasm-store/epic/free - Epic 免费游戏
pub async fn get_epic_free_games() -> Result<HttpResponse, AppError> {
    info!("获取 Epic 免费游戏");
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let games = fetch_epic_free_cached(&client).await.unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": games,
        "total": games.len(),
    })))
}

/// GET /api/v1/wasm-store/search - 跨平台搜索游戏和应用
///
/// 支持实时搜索 Steam Store、Epic Games、本地 WASM 应用。
/// 支持 `platform` 过滤器（steam / epic / wasm / 不传 = 搜索全部）。
/// 返回结果包含 `owned` 字段表示用户是否拥有该游戏。
pub async fn search_wasm_apps(
    query: web::Query<SearchQuery>,
    _req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let search_term = query.q.clone().unwrap_or_default().to_lowercase();
    let category_filter = query.category.clone();
    let platform_filter = query.platform.clone().map(|p| p.to_lowercase());
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).min(100);

    info!(
        "跨平台搜索: q='{}', platform={:?}, category={:?}",
        search_term, platform_filter, category_filter
    );

    if search_term.is_empty() && platform_filter.is_none() {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "total_pages": 0,
        })));
    }

    // 获取用户拥有的 Steam 游戏 ID 集合（用于标记 owned）
    let owned_appids = get_owned_steam_appids_from_cache().await;

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let mut results: Vec<Value> = Vec::new();

    // ── WASM 应用搜索 ──────────────────────────────────────────────
    let search_wasm = platform_filter.is_none()
        || platform_filter.as_deref() == Some("wasm");

    if search_wasm && !search_term.is_empty() {
        let apps = load_wasm_registry_async().await.unwrap_or_default();
        for app in &apps {
            let matches_category = category_filter.as_ref().is_none_or(|cat| {
                let app_cat = serde_json::to_string(&app.category)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_lowercase();
                app_cat == cat.to_lowercase()
            });

            let matches_search = app.name.to_lowercase().contains(&search_term)
                || app.description.to_lowercase().contains(&search_term)
                || app.author.to_lowercase().contains(&search_term);

            if matches_category && matches_search {
                results.push(serde_json::json!({
                    "name": app.name,
                    "id": app.id,
                    "header_image": app.icon_url,
                    "is_free": true,
                    "platform": "wasm",
                    "owned": app.installed,
                    "short_description": app.description,
                    "store_url": "",
                    "price": { "formatted": "免费" },
                    "genres": [],
                }));
            }
        }
    }

    // ── Steam Store 实时搜索 ──────────────────────────────────────
    let search_steam = platform_filter.is_none()
        || platform_filter.as_deref() == Some("steam");

    if search_steam && !search_term.is_empty() {
        let cache_key = format!("steam_search_{}", search_term);

        let steam_results = if let Some(cached) = cache_get(&cache_key).await {
            cached
        } else {
            let search_url = format!(
                "https://store.steampowered.com/api/storesearch/?term={}&l=schinese&cc=CN",
                urlencoding::encode(&search_term)
            );

            match client.get(&search_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<Value>().await {
                        Ok(json) => {
                            let mut games = Vec::new();
                            if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
                                for item in items.iter().take(20) {
                                    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                    let app_id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                                    if name.is_empty() || app_id == 0 {
                                        continue;
                                    }

                                    let tiny_image = item
                                        .get("tiny_image")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");

                                    // 从 price 字段解析价格
                                    let price_info = item.get("price");
                                    let final_price = price_info
                                        .and_then(|p| p.get("final"))
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let is_free = final_price == 0;
                                    let formatted_price = if is_free {
                                        "免费".to_string()
                                    } else {
                                        format!("¥{:.2}", final_price as f64 / 100.0)
                                    };

                                    // 平台支持
                                    let platforms = item.get("platforms");
                                    let supports_windows = platforms
                                        .and_then(|p| p.get("windows"))
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    let supports_linux = platforms
                                        .and_then(|p| p.get("linux"))
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    let supports_mac = platforms
                                        .and_then(|p| p.get("mac"))
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    let is_owned = owned_appids.contains(&app_id);

                                    let header_image = format!(
                                        "https://cdn.akamai.steamstatic.com/steam/apps/{}/header.jpg",
                                        app_id
                                    );

                                    games.push(serde_json::json!({
                                        "name": name,
                                        "app_id": app_id,
                                        "header_image": header_image,
                                        "tiny_image": tiny_image,
                                        "is_free": is_free,
                                        "platform": "steam",
                                        "owned": is_owned,
                                        "store_url": format!("https://store.steampowered.com/app/{}", app_id),
                                        "price": {
                                            "final": final_price,
                                            "formatted": formatted_price,
                                        },
                                        "platforms": {
                                            "windows": supports_windows,
                                            "linux": supports_linux,
                                            "mac": supports_mac,
                                        },
                                        "short_description": "",
                                        "genres": [],
                                    }));
                                }
                            }

                            // 缓存搜索结果 3 分钟
                            cache_set(&cache_key, games.clone(), 180).await;
                            games
                        }
                        Err(e) => {
                            warn!("Steam 搜索 JSON 解析失败: {}", e);
                            Vec::new()
                        }
                    }
                }
                _ => Vec::new(),
            }
        };

        results.extend(steam_results);
    }

    // ── Epic Games 实时搜索 ──────────────────────────────────────
    let search_epic = platform_filter.is_none()
        || platform_filter.as_deref() == Some("epic");

    if search_epic && !search_term.is_empty() {
        let cache_key = format!("epic_search_{}", search_term);

        let epic_results = if let Some(cached) = cache_get(&cache_key).await {
            cached
        } else {
            let query_body = serde_json::json!({
                "query": r#"query searchStoreQuery($count: Int, $country: String!, $keywords: String, $locale: String, $sortBy: String, $sortDir: String, $start: Int, $withPrice: Boolean = true) {
                    Catalog {
                        searchStore(count: $count, country: $country, keywords: $keywords, locale: $locale, sortBy: $sortBy, sortDir: $sortDir, start: $start) {
                            elements {
                                title
                                id
                                namespace
                                description
                                keyImages {
                                    type
                                    url
                                }
                                seller {
                                    name
                                }
                                price(country: $country) @include(if: $withPrice) {
                                    totalPrice {
                                        discountPrice
                                        originalPrice
                                        currencyCode
                                        fmtPrice(locale: "zh-CN") {
                                            originalPrice
                                            discountPrice
                                        }
                                    }
                                }
                            }
                            paging {
                                count
                                total
                            }
                        }
                    }
                }"#,
                "variables": {
                    "count": 20,
                    "country": "CN",
                    "keywords": search_term,
                    "locale": "zh-CN",
                    "sortBy": "relevancy",
                    "sortDir": "DESC",
                    "start": 0,
                    "withPrice": true,
                }
            });

            match client
                .post("https://graphql.epicgames.com/graphql")
                .header("Content-Type", "application/json")
                .json(&query_body)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<Value>().await {
                        Ok(json) => {
                            let mut games = Vec::new();
                            if let Some(elements) = json
                                .pointer("/data/Catalog/searchStore/elements")
                                .and_then(|v| v.as_array())
                            {
                                for elem in elements.iter().take(20) {
                                    let title = elem
                                        .get("title")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    let id = elem
                                        .get("id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    let description = elem
                                        .get("description")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");

                                    if title.is_empty() {
                                        continue;
                                    }

                                    let header_image = elem
                                        .get("keyImages")
                                        .and_then(|v| v.as_array())
                                        .and_then(|images| {
                                            images
                                                .iter()
                                                .find(|img| {
                                                    img.get("type")
                                                        .and_then(|t| t.as_str())
                                                        .map(|t| {
                                                            t == "OfferImageWide"
                                                                || t == "DieselStoreFrontWide"
                                                                || t == "Thumbnail"
                                                        })
                                                        .unwrap_or(false)
                                                })
                                                .or_else(|| images.first())
                                                .and_then(|img| {
                                                    img.get("url").and_then(|u| u.as_str())
                                                })
                                        })
                                        .unwrap_or("");

                                    let seller = elem
                                        .pointer("/seller/name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");

                                    let discount_price = elem
                                        .pointer("/price/totalPrice/discountPrice")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let is_free = discount_price == 0;
                                    let formatted_price = if is_free {
                                        "免费".to_string()
                                    } else {
                                        format!("¥{:.2}", discount_price as f64 / 100.0)
                                    };

                                    let namespace = elem
                                        .get("namespace")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    let store_url = if !namespace.is_empty() {
                                        format!(
                                            "https://store.epicgames.com/zh-CN/p/{}",
                                            namespace
                                        )
                                    } else {
                                        "https://store.epicgames.com/zh-CN".to_string()
                                    };

                                    games.push(serde_json::json!({
                                        "name": title,
                                        "id": id,
                                        "header_image": header_image,
                                        "is_free": is_free,
                                        "platform": "epic",
                                        "owned": false,
                                        "store_url": store_url,
                                        "short_description": description,
                                        "seller": seller,
                                        "price": {
                                            "formatted": formatted_price,
                                        },
                                        "genres": [],
                                    }));
                                }
                            }

                            cache_set(&cache_key, games.clone(), 180).await;
                            games
                        }
                        Err(e) => {
                            warn!("Epic 搜索 JSON 解析失败: {}", e);
                            Vec::new()
                        }
                    }
                }
                _ => Vec::new(),
            }
        };

        results.extend(epic_results);
    }

    let total = results.len() as i64;
    let start = ((page - 1) * page_size) as usize;
    let items: Vec<Value> = results
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": ((total as f64) / (page_size as f64)).ceil() as u32,
    })))
}

/// 从缓存获取用户拥有的 Steam 游戏 AppID 集合
async fn get_owned_steam_appids_from_cache() -> std::collections::HashSet<u64> {
    let cache = get_cache().read().await;
    let mut owned = std::collections::HashSet::new();

    // 扫描所有 steam_library_* 缓存条目
    for (key, entry) in cache.iter() {
        if key.starts_with("steam_library_") && !entry.is_expired() {
            for game in &entry.data {
                if let Some(appid) = game.get("appid").and_then(|v| v.as_u64()) {
                    owned.insert(appid);
                }
            }
        }
    }

    owned
}

/// GET /api/v1/wasm-store/wasm/apps - WASM 应用列表
pub async fn list_wasm_apps() -> Result<HttpResponse, AppError> {
    info!("获取 WASM 应用列表");
    let apps = load_wasm_registry_async().await?;
    Ok(HttpResponse::Ok().json(apps))
}

/// GET /api/v1/wasm-store/wasm/apps/{app_id} - 获取单个 WASM 应用详情
pub async fn get_wasm_app_details(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("获取 WASM 应用详情: {}", app_id);

    let apps = load_wasm_registry_async().await?;
    let app = apps
        .iter()
        .find(|a| a.id == app_id)
        .ok_or_else(|| AppError::NotFound(format!("WASM 应用 {} 未找到", app_id)))?;

    Ok(HttpResponse::Ok().json(app))
}

/// POST /api/v1/wasm-store/wasm/install - 安装 WASM 应用
pub async fn install_wasm_app(
    body: web::Json<InstallWasmAppRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("安装 WASM 应用: {}", body.name);

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let response = client
        .get(&body.wasm_url)
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("下载 WASM 模块失败: {}", e)))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest("下载 WASM 模块失败".to_string()));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("读取 WASM 数据失败: {}", e)))?;

    // 验证 BLAKE3 哈希
    let hash = blake3::hash(&bytes);
    let hash_hex = hash.to_hex().to_string();

    if let Some(expected) = &body.expected_hash {
        if expected != &hash_hex {
            return Err(AppError::PreconditionFailed(format!(
                "BLAKE3 哈希不匹配: 期望 {}, 实际 {}",
                expected, hash_hex
            )));
        }
    }

    // 验证是有效的 WASM 模块（在 blocking 线程池中运行）
    let wasm_bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || {
        let engine = wasmtime::Engine::default();
        wasmtime::Module::new(&engine, &wasm_bytes)
            .map_err(|e| AppError::BadRequest(format!("无效的 WASM 模块: {}", e)))
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("Validation task failed: {}", e)))??;

    // 保存到磁盘
    let store_dir = wasm_store_root().join("modules");
    let app_id = body.app_id.clone();
    let app_name = body.name.clone();
    let _wasm_url = body.wasm_url.clone();
    let file_bytes = bytes.to_vec();
    let hash_hex_clone = hash_hex.clone();
    let size = bytes.len() as u64;

    let file_path = tokio::task::spawn_blocking(move || -> Result<PathBuf, AppError> {
        std::fs::create_dir_all(&store_dir).map_err(|e| AppError::IoError(e.to_string()))?;
        let filename = format!("{}_{}.wasm", app_id, &hash_hex_clone[..8]);
        let file_path = store_dir.join(&filename);
        std::fs::write(&file_path, &file_bytes).map_err(|e| AppError::IoError(e.to_string()))?;
        Ok(file_path)
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("I/O task failed: {}", e)))??;

    // 更新注册表
    let app_id = body.app_id.clone();
    let app_name_for_registry = body.name.clone();
    let wasm_url_for_registry = body.wasm_url.clone();
    let file_path_str = file_path.to_string_lossy().to_string();

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut apps = load_wasm_registry()?;

        if let Some(existing) = apps.iter_mut().find(|a| a.id == app_id) {
            existing.installed = true;
            existing.installed_path = Some(file_path_str);
            existing.updated_at = now_epoch();
        } else {
            apps.push(WasmApp {
                id: app_id,
                name: app_name_for_registry,
                description: String::new(),
                version: "1.0.0".to_string(),
                author: String::new(),
                icon_url: String::new(),
                wasm_url: wasm_url_for_registry,
                category: WasmAppCategory::Other,
                size_bytes: size,
                installed: true,
                installed_path: Some(file_path_str),
                permissions: Vec::new(),
                created_at: now_epoch(),
                updated_at: now_epoch(),
            });
        }

        save_wasm_registry(&apps)
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("Registry task failed: {}", e)))??;

    info!("WASM 应用安装完成: {} (hash: {})", app_name, hash_hex);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "installed",
        "app_id": body.app_id,
        "hash": hash_hex,
        "size": size,
    })))
}

/// POST /api/v1/wasm-store/wasm/{app_id}/run - 运行 WASM 应用
///
/// WASM 执行通过 `spawn_blocking` 在独立线程运行，
/// 不会阻塞 tokio 的 async 运行时线程。同时加了 30 秒超时保护。
pub async fn run_wasm_app(
    path: web::Path<String>,
    body: web::Json<RunWasmAppRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("运行 WASM 应用: {}", app_id);

    let apps = load_wasm_registry_async().await?;
    let app = apps
        .iter()
        .find(|a| a.id == app_id && a.installed)
        .ok_or_else(|| AppError::NotFound(format!("WASM 应用 {} 未安装", app_id)))?;

    let wasm_path = app
        .installed_path
        .clone()
        .ok_or_else(|| AppError::NotFound("WASM 模块路径未找到".to_string()))?;

    if !Path::new(&wasm_path).exists() {
        return Err(AppError::NotFound("WASM 模块文件不存在".to_string()));
    }

    let func_name = body
        .function
        .clone()
        .unwrap_or_else(|| "_start".to_string());
    let args = body.args.clone().unwrap_or_default();
    let env = body.env.clone().unwrap_or_default();

    let func_name_clone = func_name.clone();
    let app_id_clone = app_id.clone();

    // WASM 执行放到 blocking 线程池，并设置 30 秒超时
    let exec_result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || -> Result<(), AppError> {
            let engine = wasmtime::Engine::default();
            let module = wasmtime::Module::from_file(&engine, &wasm_path)
                .map_err(|e| AppError::BadRequest(format!("加载 WASM 模块失败: {}", e)))?;

            let mut linker = wasmtime::Linker::new(&engine);
            #[allow(deprecated)]
            wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;

            #[allow(deprecated)]
            let mut builder = wasmtime_wasi::sync::WasiCtxBuilder::new();
            builder.inherit_stdio();

            for arg in &args {
                builder
                    .arg(arg)
                    .map_err(|e| AppError::ValidationError(format!("无效参数: {}", e)))?;
            }

            for (key, value) in &env {
                builder
                    .env(key, value)
                    .map_err(|e| AppError::ValidationError(format!("无效环境变量: {}", e)))?;
            }

            let mut store = wasmtime::Store::new(&engine, builder.build());
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| AppError::BadRequest(format!("实例化 WASM 失败: {}", e)))?;

            if let Ok(entry) = instance.get_typed_func::<(), ()>(&mut store, &func_name_clone) {
                entry
                    .call(&mut store, ())
                    .map_err(|e| AppError::BadRequest(format!("WASM 执行失败: {}", e)))?;
            } else if let Some(func) = instance.get_func(&mut store, &func_name_clone) {
                func.call(&mut store, &[], &mut [])
                    .map_err(|e| AppError::BadRequest(format!("WASM 执行失败: {}", e)))?;
            } else {
                return Err(AppError::NotFound(format!(
                    "函数 '{}' 在 WASM 模块中未找到",
                    func_name_clone
                )));
            }

            Ok(())
        }),
    )
    .await;

    match exec_result {
        Ok(Ok(Ok(()))) => {
            info!("WASM 应用执行成功: {}", app_id);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "completed",
                "app_id": app_id,
                "function": func_name,
            })))
        }
        Ok(Ok(Err(app_err))) => Err(app_err),
        Ok(Err(join_err)) => Err(AppError::InternalServerError(format!(
            "WASM execution task panicked: {}",
            join_err
        ))),
        Err(_timeout) => {
            warn!("WASM 应用执行超时 (30s): {}", app_id_clone);
            Err(AppError::InternalServerError(format!(
                "WASM 执行超时 (30s): {}",
                app_id_clone
            )))
        }
    }
}

/// DELETE /api/v1/wasm-store/wasm/{app_id} - 卸载 WASM 应用
pub async fn uninstall_wasm_app(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("卸载 WASM 应用: {}", app_id);

    let app_id_clone = app_id.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<String, AppError> {
        let mut apps = load_wasm_registry()?;

        if let Some(app) = apps.iter_mut().find(|a| a.id == app_id_clone) {
            if let Some(path) = &app.installed_path {
                if let Err(e) = std::fs::remove_file(path) {
                    warn!("删除 WASM 文件失败 {}: {}", path, e);
                }
            }
            app.installed = false;
            app.installed_path = None;
            save_wasm_registry(&apps)?;

            Ok(app_id_clone)
        } else {
            Err(AppError::NotFound(format!(
                "WASM 应用 {} 未找到",
                app_id_clone
            )))
        }
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("Uninstall task failed: {}", e)))??;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "uninstalled",
        "app_id": result,
    })))
}

// ============================================================================
// 内置 WASM 应用 — 原生处理器（不需要 .wasm 文件）
// ============================================================================

/// 内置应用查询参数
#[derive(Debug, Deserialize)]
pub struct BuiltinAppQuery {
    /// Steam App ID（SteamDB 需要）
    pub app_id: Option<u32>,
    /// 游戏名称搜索（SteamDB 名称搜索）
    pub name: Option<String>,
    /// M3U8 URL（下载器需要）
    pub url: Option<String>,
    /// Steam ID（P2P Info 需要）
    pub steam_id: Option<String>,
    /// M3U8 下载保存目录（可选，默认 wasm_store/downloads）
    pub save_dir: Option<String>,
}

/// GET /api/v1/wasm-store/builtin/{app_id}/run - 运行内置应用
pub async fn run_builtin_app(
    path: web::Path<String>,
    query: web::Query<BuiltinAppQuery>,
) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("运行内置应用: {}", app_id);

    match app_id.as_str() {
        "steamdb-viewer" => run_steamdb_viewer(&query).await,
        "m3u8-downloader" => run_m3u8_downloader(&query).await,
        "steam-p2p-info" => run_steam_p2p_info(&query).await,
        "wxy-edge-node" => run_wxy_edge_node().await,
        _ => Err(AppError::NotFound(format!("未知内置应用: {}", app_id))),
    }
}

async fn run_wxy_edge_node() -> Result<HttpResponse, AppError> {
    let snapshot = crate::handlers::edge_compute::builtin_wxy_edge_node_status().await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "source": "wxy-edge-node",
        "snapshot": snapshot,
    })))
}

/// SteamDB 数据查看器 — 查询 Steam API 获取游戏详情
///
/// 支持两种查询方式:
/// 1. 通过 `app_id` 直接查询（精确）
/// 2. 通过 `name` 搜索游戏名称（模糊匹配，返回搜索结果列表后选择）
async fn run_steamdb_viewer(query: &BuiltinAppQuery) -> Result<HttpResponse, AppError> {
    // 如果提供了游戏名称，先搜索获取 App ID
    if let Some(ref search_name) = query.name {
        if query.app_id.is_none() {
            return run_steamdb_name_search(search_name).await;
        }
    }

    let steam_app_id = query
        .app_id
        .ok_or_else(|| AppError::BadRequest("缺少参数 app_id 或 name".to_string()))?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // 并行获取多个 Steam API 数据源
    let details_url = format!(
        "https://store.steampowered.com/api/appdetails?appids={}&cc=cn&l=schinese",
        steam_app_id
    );
    let charts_url = format!(
        "https://api.steampowered.com/ISteamUserStats/GetNumberOfCurrentPlayers/v1/?appid={}",
        steam_app_id
    );
    let reviews_url = format!(
        "https://store.steampowered.com/appreviews/{}?json=1&language=all&purchase_type=all&num_per_page=0",
        steam_app_id
    );

    let (details_resp, players_resp, reviews_resp) = tokio::join!(
        client.get(&details_url).send(),
        client.get(&charts_url).send(),
        client.get(&reviews_url).send(),
    );

    // 解析游戏详情
    let mut result = serde_json::json!({
        "app_id": steam_app_id,
        "source": "steamdb-viewer",
    });

    if let Ok(resp) = details_resp {
        if let Ok(json) = resp.json::<Value>().await {
            let key = steam_app_id.to_string();
            if let Some(app_data) = json.get(&key).and_then(|v| v.get("data")) {
                result["name"] = app_data.get("name").cloned().unwrap_or(Value::Null);
                result["type"] = app_data.get("type").cloned().unwrap_or(Value::Null);
                result["is_free"] = app_data.get("is_free").cloned().unwrap_or(Value::Null);
                result["short_description"] = app_data
                    .get("short_description")
                    .cloned()
                    .unwrap_or(Value::Null);
                result["header_image"] =
                    app_data.get("header_image").cloned().unwrap_or(Value::Null);
                result["developers"] =
                    app_data.get("developers").cloned().unwrap_or(Value::Null);
                result["publishers"] =
                    app_data.get("publishers").cloned().unwrap_or(Value::Null);
                result["release_date"] =
                    app_data.get("release_date").cloned().unwrap_or(Value::Null);
                result["metacritic"] =
                    app_data.get("metacritic").cloned().unwrap_or(Value::Null);
                result["categories"] =
                    app_data.get("categories").cloned().unwrap_or(Value::Null);
                result["genres"] = app_data.get("genres").cloned().unwrap_or(Value::Null);
                result["platforms"] = app_data.get("platforms").cloned().unwrap_or(Value::Null);
                result["recommendations"] = app_data
                    .get("recommendations")
                    .cloned()
                    .unwrap_or(Value::Null);

                // 价格信息
                if let Some(price) = app_data.get("price_overview") {
                    result["price"] = price.clone();
                }

                // DLC 列表
                if let Some(dlc) = app_data.get("dlc") {
                    result["dlc_count"] = Value::from(dlc.as_array().map(|a| a.len()).unwrap_or(0));
                    result["dlc_ids"] = dlc.clone();
                }

                // 系统需求
                if let Some(req) = app_data.get("pc_requirements") {
                    result["pc_requirements"] = req.clone();
                }
            }
        }
    }

    // 当前在线人数
    if let Ok(resp) = players_resp {
        if let Ok(json) = resp.json::<Value>().await {
            if let Some(count) = json.pointer("/response/player_count") {
                result["current_players"] = count.clone();
            }
        }
    }

    // 评价统计
    if let Ok(resp) = reviews_resp {
        if let Ok(json) = resp.json::<Value>().await {
            if let Some(summary) = json.get("query_summary") {
                result["review_score"] = summary
                    .get("review_score")
                    .cloned()
                    .unwrap_or(Value::Null);
                result["review_score_desc"] = summary
                    .get("review_score_desc")
                    .cloned()
                    .unwrap_or(Value::Null);
                result["total_positive"] = summary
                    .get("total_positive")
                    .cloned()
                    .unwrap_or(Value::Null);
                result["total_negative"] = summary
                    .get("total_negative")
                    .cloned()
                    .unwrap_or(Value::Null);
                result["total_reviews"] = summary
                    .get("total_reviews")
                    .cloned()
                    .unwrap_or(Value::Null);
            }
        }
    }

    Ok(HttpResponse::Ok().json(result))
}

/// Steam 游戏名称搜索 — 使用 Steam Store 搜索 API
///
/// 返回匹配的游戏列表（包含 app_id、名称、头像等），
/// 前端可让用户选择后再以 app_id 查询完整详情。
async fn run_steamdb_name_search(search_name: &str) -> Result<HttpResponse, AppError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // Steam Store 搜索建议 API（官方非文档化但稳定的接口）
    let suggest_url = format!(
        "https://store.steampowered.com/search/suggest?term={}&f=games&cc=cn&l=schinese&excluded_content_descriptors%5B%5D=3&excluded_content_descriptors%5B%5D=4&use_b64_image=1&category1=998",
        urlencoding::encode(search_name)
    );

    // 同时也使用 storesearch API 作为备选（返回 JSON 结构化数据）
    let storesearch_url = format!(
        "https://store.steampowered.com/api/storesearch/?term={}&l=schinese&cc=cn",
        urlencoding::encode(search_name)
    );

    let storesearch_resp = client
        .get(&storesearch_url)
        .header("User-Agent", "RockZeroOS/1.0")
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Steam 搜索失败: {}", e)))?;

    if storesearch_resp.status().is_success() {
        if let Ok(json) = storesearch_resp.json::<Value>().await {
            let items = json.get("items").and_then(|v| v.as_array());
            if let Some(items) = items {
                let results: Vec<Value> = items
                    .iter()
                    .take(20)
                    .map(|item| {
                        serde_json::json!({
                            "app_id": item.get("id").and_then(|v| v.as_u64()).unwrap_or(0),
                            "name": item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                            "tiny_image": item.get("tiny_image").and_then(|v| v.as_str()).unwrap_or(""),
                            "price": item.get("price").cloned().unwrap_or(Value::Null),
                            "platforms": item.get("platforms").cloned().unwrap_or(Value::Null),
                            "metascore": item.get("metascore").and_then(|v| v.as_str()).unwrap_or(""),
                        })
                    })
                    .collect();

                return Ok(HttpResponse::Ok().json(serde_json::json!({
                    "source": "steamdb-viewer",
                    "search_query": search_name,
                    "search_results": results,
                    "total": results.len(),
                })));
            }
        }
    }

    // 搜索 API 也失败时 — 尝试 suggest HTML 解析的回退
    // 但生产环境中 storesearch API 基本不会失败，这里仅做兜底
    info!("Steam storesearch API failed for '{}', trying suggest API", search_name);

    let suggest_resp = client
        .get(&suggest_url)
        .header("User-Agent", "RockZeroOS/1.0")
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Steam 搜索回退失败: {}", e)))?;

    if suggest_resp.status().is_success() {
        let html = suggest_resp.text().await.unwrap_or_default();
        // suggest API 返回 HTML 片段，解析 <a> 标签中的 data-ds-appid 和游戏名
        let mut results = Vec::new();
        for line in html.lines() {
            let trimmed = line.trim();
            if let Some(appid_start) = trimmed.find("data-ds-appid=\"") {
                let after = &trimmed[appid_start + 15..];
                if let Some(appid_end) = after.find('"') {
                    let appid_str = &after[..appid_end];
                    if let Ok(appid) = appid_str.parse::<u64>() {
                        // 提取游戏名称
                        let name = trimmed
                            .find("match_name\">")
                            .map(|start| {
                                let after_name = &trimmed[start + 12..];
                                after_name
                                    .find('<')
                                    .map(|end| after_name[..end].to_string())
                                    .unwrap_or_default()
                            })
                            .unwrap_or_default();

                        if !name.is_empty() {
                            results.push(serde_json::json!({
                                "app_id": appid,
                                "name": name,
                                "tiny_image": "",
                            }));
                        }
                    }
                }
            }
            if results.len() >= 20 {
                break;
            }
        }

        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "source": "steamdb-viewer",
            "search_query": search_name,
            "search_results": results,
            "total": results.len(),
        })));
    }

    Err(AppError::InternalServerError(
        "无法搜索 Steam 游戏，请检查网络连接".to_string(),
    ))
}

/// M3U8 下载器 — 解析 M3U8 播放列表并下载所有分片
async fn run_m3u8_downloader(query: &BuiltinAppQuery) -> Result<HttpResponse, AppError> {
    let m3u8_url = query
        .url
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("缺少参数 url".to_string()))?;

    info!("M3U8 下载器: 解析 {}", m3u8_url);

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    // 获取 M3U8 播放列表
    let resp = client
        .get(m3u8_url)
        .header("User-Agent", "RockZeroOS/1.0")
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("获取 M3U8 失败: {}", e)))?;

    if !resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "M3U8 返回错误状态: {}",
            resp.status()
        )));
    }

    let m3u8_content = resp
        .text()
        .await
        .map_err(|e| AppError::BadRequest(format!("读取 M3U8 内容失败: {}", e)))?;

    // 解析 M3U8 内容
    let base_url = {
        let mut url = m3u8_url.to_string();
        if let Some(pos) = url.rfind('/') {
            url.truncate(pos + 1);
        }
        url
    };

    let mut segments: Vec<Value> = Vec::new();
    let mut total_duration: f64 = 0.0;
    let mut current_duration: f64 = 0.0;
    let mut encryption_method = String::new();
    let mut encryption_uri = String::new();
    let mut is_master_playlist = false;
    let mut variant_streams: Vec<Value> = Vec::new();

    for line in m3u8_content.lines() {
        let line = line.trim();

        if line.starts_with("#EXT-X-STREAM-INF:") {
            is_master_playlist = true;
            // 解析变体流参数
            let mut bandwidth: u64 = 0;
            let mut resolution = String::new();
            for param in line
                .strip_prefix("#EXT-X-STREAM-INF:")
                .unwrap_or("")
                .split(',')
            {
                let param = param.trim();
                if let Some(val) = param.strip_prefix("BANDWIDTH=") {
                    bandwidth = val.parse().unwrap_or(0);
                } else if let Some(val) = param.strip_prefix("RESOLUTION=") {
                    resolution = val.to_string();
                }
            }
            // 下一行是 URL
            variant_streams.push(serde_json::json!({
                "bandwidth": bandwidth,
                "resolution": resolution,
            }));
        } else if line.starts_with("#EXT-X-KEY:") {
            // 加密信息
            let key_info = line.strip_prefix("#EXT-X-KEY:").unwrap_or("");
            for param in key_info.split(',') {
                let param = param.trim();
                if let Some(val) = param.strip_prefix("METHOD=") {
                    encryption_method = val.to_string();
                } else if let Some(val) = param.strip_prefix("URI=\"") {
                    encryption_uri = val.trim_end_matches('"').to_string();
                }
            }
        } else if line.starts_with("#EXTINF:") {
            // 分片时长
            if let Some(dur_str) = line
                .strip_prefix("#EXTINF:")
                .and_then(|s| s.split(',').next())
            {
                current_duration = dur_str.parse().unwrap_or(0.0);
                total_duration += current_duration;
            }
        } else if !line.is_empty() && !line.starts_with('#') {
            // 分片 URL
            let segment_url = if line.starts_with("http://") || line.starts_with("https://") {
                line.to_string()
            } else {
                format!("{}{}", base_url, line)
            };

            if is_master_playlist {
                // 为变体流添加 URL
                if let Some(last) = variant_streams.last_mut() {
                    last["url"] = Value::String(segment_url);
                }
            } else {
                segments.push(serde_json::json!({
                    "index": segments.len(),
                    "url": segment_url,
                    "duration": current_duration,
                }));
            }
        }
    }

    let result = serde_json::json!({
        "source": "m3u8-downloader",
        "url": m3u8_url,
        "is_master_playlist": is_master_playlist,
        "variant_streams": variant_streams,
        "segments": segments,
        "total_segments": segments.len(),
        "total_duration": total_duration,
        "encryption": {
            "method": encryption_method,
            "key_uri": encryption_uri,
            "encrypted": !encryption_method.is_empty() && encryption_method != "NONE",
        },
        "raw_content": m3u8_content,
    });

    Ok(HttpResponse::Ok().json(result))
}

/// POST /api/v1/wasm-store/builtin/m3u8-downloader/download - 下载 M3U8 视频
#[derive(Debug, Deserialize)]
pub struct M3u8DownloadRequest {
    pub url: String,
    pub output_name: Option<String>,
    pub variant_index: Option<usize>,
    /// 自定义保存目录（相对于外部存储根目录）
    /// 例如: "Downloads/Videos" 会保存到 /mnt/external/Downloads/Videos/
    /// 默认保存到 wasm_store/downloads/
    pub save_dir: Option<String>,
}

pub async fn download_m3u8_video(
    body: web::Json<M3u8DownloadRequest>,
) -> Result<HttpResponse, AppError> {
    info!("M3U8 下载: {}", body.url);

    let output_name = body
        .output_name
        .clone()
        .unwrap_or_else(|| format!("m3u8_video_{}.ts", now_epoch()));

    // 支持自定义保存目录：优先使用 save_dir，否则默认 wasm_store/downloads
    let download_dir = if let Some(ref custom_dir) = body.save_dir {
        let custom_dir = custom_dir.trim();
        if custom_dir.is_empty() {
            wasm_store_root().join("downloads")
        } else {
            // 安全性检查：防止路径遍历
            let sanitized = custom_dir
                .replace("..", "")
                .trim_start_matches('/')
                .trim_start_matches('\\')
                .to_string();
            if sanitized.is_empty() {
                wasm_store_root().join("downloads")
            } else {
                // 允许绝对路径（在 allowed directories 内）或相对路径
                let path = std::path::PathBuf::from(&sanitized);
                if path.is_absolute() {
                    // 验证绝对路径是否在允许目录内
                    let path_str = path.to_string_lossy();
                    const ALLOWED_DIRS: &[&str] =
                        &["/mnt", "/media", "/home", "/data", "/storage"];
                    let is_allowed = ALLOWED_DIRS.iter().any(|d| path_str.starts_with(d));
                    #[cfg(target_os = "windows")]
                    let is_allowed =
                        is_allowed || (path_str.len() >= 2 && path_str.chars().nth(1) == Some(':'));
                    if is_allowed {
                        path
                    } else {
                        return Err(AppError::Forbidden(
                            "保存路径不在允许的目录范围内".to_string(),
                        ));
                    }
                } else {
                    // 相对路径：基于外部存储根目录
                    let base = std::env::var("EXTERNAL_STORAGE_PATH")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|_| std::path::PathBuf::from("/mnt/external"));
                    base.join(sanitized)
                }
            }
        }
    } else {
        wasm_store_root().join("downloads")
    };

    tokio::fs::create_dir_all(&download_dir)
        .await
        .map_err(|e| AppError::IoError(e.to_string()))?;

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    // 获取并解析 M3U8
    let resp = client
        .get(&body.url)
        .header("User-Agent", "RockZeroOS/1.0")
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("获取 M3U8 失败: {}", e)))?;

    let m3u8_content = resp
        .text()
        .await
        .map_err(|e| AppError::BadRequest(format!("读取失败: {}", e)))?;

    let base_url = {
        let mut url = body.url.clone();
        if let Some(pos) = url.rfind('/') {
            url.truncate(pos + 1);
        }
        url
    };

    // 收集分片 URL
    let mut segment_urls: Vec<String> = Vec::new();
    for line in m3u8_content.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            let url = if line.starts_with("http://") || line.starts_with("https://") {
                line.to_string()
            } else {
                format!("{}{}", base_url, line)
            };
            segment_urls.push(url);
        }
    }

    if segment_urls.is_empty() {
        return Err(AppError::BadRequest("M3U8 中没有找到分片".to_string()));
    }

    // 下载所有分片并合并
    let output_path = download_dir.join(&output_name);
    let mut output_file = tokio::fs::File::create(&output_path)
        .await
        .map_err(|e| AppError::IoError(e.to_string()))?;

    let total = segment_urls.len();
    let mut downloaded = 0usize;

    for url in &segment_urls {
        let seg_resp = client
            .get(url)
            .header("User-Agent", "RockZeroOS/1.0")
            .send()
            .await
            .map_err(|e| {
                AppError::BadRequest(format!("下载分片失败 ({}/{}): {}", downloaded + 1, total, e))
            })?;

        let bytes = seg_resp
            .bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("读取分片数据失败: {}", e)))?;

        output_file
            .write_all(&bytes)
            .await
            .map_err(|e| AppError::IoError(e.to_string()))?;

        downloaded += 1;
    }

    let file_size = tokio::fs::metadata(&output_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);

    info!(
        "M3U8 下载完成: {} ({} 分片, {} bytes)",
        output_name, total, file_size
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "completed",
        "output_path": output_path.to_string_lossy(),
        "output_name": output_name,
        "total_segments": total,
        "downloaded_segments": downloaded,
        "file_size": file_size,
    })))
}

/// GET /api/v1/wasm-store/builtin/downloads - 列出已下载的文件
pub async fn list_downloads() -> Result<HttpResponse, AppError> {
    let download_dir = wasm_store_root().join("downloads");
    if !download_dir.exists() {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "files": [],
            "total": 0,
        })));
    }

    let mut files = Vec::new();
    let mut entries = tokio::fs::read_dir(&download_dir)
        .await
        .map_err(|e| AppError::IoError(e.to_string()))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| AppError::IoError(e.to_string()))?
    {
        let meta = entry.metadata().await.ok();
        let name = entry.file_name().to_string_lossy().to_string();
        files.push(serde_json::json!({
            "name": name,
            "size": meta.as_ref().map(|m| m.len()).unwrap_or(0),
            "is_file": meta.as_ref().map(|m| m.is_file()).unwrap_or(false),
        }));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "files": files,
        "total": files.len(),
    })))
}

/// GET /api/v1/wasm-store/builtin/downloads/{filename} - 下载指定文件
pub async fn serve_download_file(
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let filename = path.into_inner();

    // 安全检查：防止路径遍历
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(AppError::BadRequest("非法文件名".to_string()));
    }

    let file_path = wasm_store_root().join("downloads").join(&filename);
    if !file_path.exists() || !file_path.is_file() {
        return Err(AppError::NotFound(format!("文件不存在: {}", filename)));
    }

    let data = tokio::fs::read(&file_path)
        .await
        .map_err(|e| AppError::IoError(e.to_string()))?;

    let content_type = if filename.ends_with(".ts") {
        "video/mp2t"
    } else if filename.ends_with(".mp4") {
        "video/mp4"
    } else if filename.ends_with(".mkv") {
        "video/x-matroska"
    } else {
        "application/octet-stream"
    };

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", content_type))
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        ))
        .body(data))
}

/// Steam P2P 连接信息查看器
async fn run_steam_p2p_info(query: &BuiltinAppQuery) -> Result<HttpResponse, AppError> {
    let steam_id = query
        .steam_id
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("缺少参数 steam_id".to_string()))?;

    info!("Steam P2P Info: 查询 {}", steam_id);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // 获取用户信息
    let summary_url = format!(
        "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?steamids={}",
        steam_id
    );
    let friends_url = format!(
        "https://api.steampowered.com/ISteamUser/GetFriendList/v1/?steamid={}&relationship=friend",
        steam_id
    );
    let games_url = format!(
        "https://api.steampowered.com/IPlayerService/GetRecentlyPlayedGames/v1/?steamid={}",
        steam_id
    );

    let (summary_resp, friends_resp, games_resp) =
        tokio::join!(client.get(&summary_url).send(), client.get(&friends_url).send(), client.get(&games_url).send(),);

    let mut result = serde_json::json!({
        "source": "steam-p2p-info",
        "steam_id": steam_id,
    });

    // 用户概况
    if let Ok(resp) = summary_resp {
        if let Ok(json) = resp.json::<Value>().await {
            if let Some(players) = json
                .pointer("/response/players")
                .and_then(|v| v.as_array())
            {
                if let Some(player) = players.first() {
                    result["player"] = serde_json::json!({
                        "name": player.get("personaname"),
                        "avatar": player.get("avatarfull"),
                        "profile_url": player.get("profileurl"),
                        "status": player.get("personastate"),
                        "game_id": player.get("gameid"),
                        "game_name": player.get("gameextrainfo"),
                        "country": player.get("loccountrycode"),
                        "state": player.get("locstatecode"),
                        "city": player.get("loccityid"),
                        "last_logoff": player.get("lastlogoff"),
                        "time_created": player.get("timecreated"),
                    });
                }
            }
        }
    }

    // 好友列表（可能受隐私设置限制）
    if let Ok(resp) = friends_resp {
        if let Ok(json) = resp.json::<Value>().await {
            if let Some(friends) = json
                .pointer("/friendslist/friends")
                .and_then(|v| v.as_array())
            {
                result["friends_count"] = Value::from(friends.len());
                // 仅返回前 20 个好友
                let preview: Vec<&Value> = friends.iter().take(20).collect();
                result["friends_preview"] = serde_json::json!(preview);
            }
        }
    }

    // 最近游玩的游戏
    if let Ok(resp) = games_resp {
        if let Ok(json) = resp.json::<Value>().await {
            if let Some(games) = json
                .pointer("/response/games")
                .and_then(|v| v.as_array())
            {
                let game_info: Vec<Value> = games
                    .iter()
                    .map(|g| {
                        let appid = g.get("appid").and_then(|v| v.as_u64()).unwrap_or(0);
                        serde_json::json!({
                            "appid": appid,
                            "name": g.get("name"),
                            "playtime_2weeks": g.get("playtime_2weeks"),
                            "playtime_forever": g.get("playtime_forever"),
                            "img_icon_url": g.get("img_icon_url"),
                            "has_p2p": true, // Placeholder — actual detection needs Steam networking API
                        })
                    })
                    .collect();

                result["recent_games"] = Value::Array(game_info);
            }
        }
    }

    // P2P 连接模拟信息
    result["p2p_info"] = serde_json::json!({
        "note": "P2P 连接详情需要本机 Steam 客户端运行时获取",
        "supported_apis": [
            "ISteamNetworking",
            "ISteamNetworkingSockets",
            "ISteamNetworkingMessages",
        ],
        "connection_types": [
            {"type": "relay", "description": "通过 Steam 中继服务器转发"},
            {"type": "direct", "description": "NAT 穿透后的直连"},
            {"type": "lan", "description": "局域网内直接连接"},
        ],
    });

    Ok(HttpResponse::Ok().json(result))
}

// ============================================================================
// 插件系统
// ============================================================================

/// GET /api/v1/wasm-store/plugins - 获取已注册插件列表
pub async fn list_plugins() -> Result<HttpResponse, AppError> {
    info!("获取插件列表");
    let plugins = tokio::task::spawn_blocking(load_plugin_registry)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Task failed: {}", e)))??;
    Ok(HttpResponse::Ok().json(plugins))
}

/// POST /api/v1/wasm-store/plugins/register - 注册新插件
pub async fn register_plugin(
    body: web::Json<RegisterPluginRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let plugin_id = body.manifest.id.clone();
    let manifest = body.manifest.clone();
    info!("注册插件: {}", manifest.name);

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut plugins = load_plugin_registry()?;

        if let Some(existing) = plugins.iter_mut().find(|p| p.id == manifest.id) {
            *existing = manifest;
        } else {
            plugins.push(manifest);
        }

        save_plugin_registry(&plugins)
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("Task failed: {}", e)))??;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "registered",
        "plugin_id": plugin_id,
    })))
}

/// DELETE /api/v1/wasm-store/plugins/{plugin_id} - 注销插件
pub async fn unregister_plugin(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let plugin_id = path.into_inner();
    info!("注销插件: {}", plugin_id);

    let pid = plugin_id.clone();
    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut plugins = load_plugin_registry()?;
        let original_len = plugins.len();
        plugins.retain(|p| p.id != pid);

        if plugins.len() == original_len {
            return Err(AppError::NotFound(format!("插件 {} 未找到", pid)));
        }

        save_plugin_registry(&plugins)
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("Task failed: {}", e)))??;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "unregistered",
        "plugin_id": plugin_id,
    })))
}

// ============================================================================
// GitHub WASM 仓库导入
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GitHubImportRequest {
    /// GitHub 仓库 URL，如 https://github.com/user/repo
    pub repo_url: String,
    /// 要下载的 release tag（默认 latest）
    pub tag: Option<String>,
    /// 指定 WASM 文件名（从 release assets 中匹配）
    pub asset_name: Option<String>,
    /// 应用名称（默认使用仓库名）
    pub name: Option<String>,
}

/// POST /api/v1/wasm-store/github/import - 从 GitHub 仓库导入 WASM 模块
///
/// 支持从 GitHub Releases 下载 .wasm 文件并注册到 WASM 应用商店。
/// 1. 解析仓库 URL → owner/repo
/// 2. 调用 GitHub API 获取 release 信息
/// 3. 找到 .wasm 资源文件并下载
/// 4. BLAKE3 哈希校验 + wasmtime 模块验证
/// 5. 注册到本地 WASM 商店
pub async fn import_from_github(
    body: web::Json<GitHubImportRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let repo_url = body.repo_url.trim().trim_end_matches('/');
    info!("从 GitHub 导入 WASM: {}", repo_url);

    // 解析 owner/repo
    let (owner, repo) = parse_github_url(repo_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("RockZeroOS/1.0")
        .build()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    // 获取 release 信息
    let release_url = if let Some(tag) = &body.tag {
        format!(
            "https://api.github.com/repos/{}/{}/releases/tags/{}",
            owner, repo, tag
        )
    } else {
        format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            owner, repo
        )
    };

    let release_resp = client
        .get(&release_url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("GitHub API 请求失败: {}", e)))?;

    if release_resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(AppError::NotFound(format!(
            "仓库 {}/{} 没有找到 release",
            owner, repo
        )));
    }

    if !release_resp.status().is_success() {
        return Err(AppError::InternalServerError(format!(
            "GitHub API 返回错误: {}",
            release_resp.status()
        )));
    }

    let release: Value = release_resp.json().await.map_err(|e| {
        AppError::InternalServerError(format!("解析 release JSON 失败: {}", e))
    })?;

    let tag_name = release
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let release_body = release
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // 查找 .wasm 资源
    let assets = release
        .get("assets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::NotFound("Release 中没有资源文件".to_string()))?;

    let wasm_asset = if let Some(asset_name) = &body.asset_name {
        // 指定了文件名则精确匹配
        assets
            .iter()
            .find(|a| {
                a.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n == asset_name.as_str())
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Release 中未找到文件: {}",
                    asset_name
                ))
            })?
    } else {
        // 自动寻找第一个 .wasm 文件
        assets
            .iter()
            .find(|a| {
                a.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| n.ends_with(".wasm"))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                AppError::NotFound("Release 中未找到 .wasm 文件".to_string())
            })?
    };

    let asset_name = wasm_asset
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("module.wasm");
    let download_url = wasm_asset
        .get("browser_download_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::NotFound("无法获取下载地址".to_string()))?;
    let asset_size = wasm_asset
        .get("size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    info!(
        "下载 WASM 资源: {} ({} bytes) from {}",
        asset_name, asset_size, download_url
    );

    // 下载 WASM 文件
    let wasm_resp = client
        .get(download_url)
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .map_err(|e| AppError::BadRequest(format!("下载 WASM 失败: {}", e)))?;

    if !wasm_resp.status().is_success() {
        return Err(AppError::BadRequest(format!(
            "下载失败: HTTP {}",
            wasm_resp.status()
        )));
    }

    let bytes = wasm_resp
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("读取 WASM 数据失败: {}", e)))?;

    // BLAKE3 哈希
    let hash = blake3::hash(&bytes);
    let hash_hex = hash.to_hex().to_string();

    // 验证 WASM 模块
    let wasm_bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || {
        let engine = wasmtime::Engine::default();
        wasmtime::Module::new(&engine, &wasm_bytes)
            .map_err(|e| AppError::BadRequest(format!("无效的 WASM 模块: {}", e)))
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("验证任务失败: {}", e)))??;

    // 保存到磁盘
    let app_id = format!("github-{}-{}", owner, repo);
    let app_name = body
        .name
        .clone()
        .unwrap_or_else(|| repo.to_string());
    let store_dir = wasm_store_root().join("modules");
    let file_bytes = bytes.to_vec();
    let hash_hex_clone = hash_hex.clone();
    let app_id_clone = app_id.clone();
    let size = bytes.len() as u64;

    let file_path = tokio::task::spawn_blocking(move || -> Result<PathBuf, AppError> {
        std::fs::create_dir_all(&store_dir).map_err(|e| AppError::IoError(e.to_string()))?;
        let filename = format!("{}_{}.wasm", app_id_clone, &hash_hex_clone[..8]);
        let file_path = store_dir.join(&filename);
        std::fs::write(&file_path, &file_bytes).map_err(|e| AppError::IoError(e.to_string()))?;
        Ok(file_path)
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("I/O 任务失败: {}", e)))??;

    // 更新注册表
    let file_path_str = file_path.to_string_lossy().to_string();
    let app_name_clone = app_name.clone();
    let description = format!(
        "从 GitHub 导入: {}/{}@{}\n\n{}",
        owner, repo, tag_name, release_body
    );
    let app_id_for_reg = app_id.clone();
    let repo_url_clone = repo_url.to_string();
    let owner_for_closure = owner.clone();
    let repo_for_closure = repo.clone();
    let tag_name_for_closure = tag_name.clone();

    tokio::task::spawn_blocking(move || -> Result<(), AppError> {
        let mut apps = load_wasm_registry()?;

        if let Some(existing) = apps.iter_mut().find(|a| a.id == app_id_for_reg) {
            existing.installed = true;
            existing.installed_path = Some(file_path_str);
            existing.version = tag_name_for_closure.clone();
            existing.description = description;
            existing.updated_at = now_epoch();
        } else {
            apps.push(WasmApp {
                id: app_id_for_reg,
                name: app_name_clone,
                description,
                version: tag_name_for_closure.clone(),
                author: owner_for_closure.to_string(),
                icon_url: format!(
                    "https://github.com/{}/{}/raw/main/icon.png",
                    owner_for_closure, repo_for_closure
                ),
                wasm_url: repo_url_clone,
                category: WasmAppCategory::Other,
                size_bytes: size,
                installed: true,
                installed_path: Some(file_path_str),
                permissions: Vec::new(),
                created_at: now_epoch(),
                updated_at: now_epoch(),
            });
        }

        save_wasm_registry(&apps)
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("注册失败: {}", e)))??;

    info!(
        "GitHub WASM 导入完成: {}/{} → {} (hash: {})",
        owner, repo, app_name, hash_hex
    );

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "imported",
        "app_id": app_id,
        "name": app_name,
        "version": tag_name,
        "hash": hash_hex,
        "size": size,
        "source": format!("github:{}/{}", owner, repo),
    })))
}

/// 解析 GitHub URL → (owner, repo)
fn parse_github_url(url: &str) -> Result<(String, String), AppError> {
    // 支持格式：
    //   https://github.com/owner/repo
    //   https://github.com/owner/repo.git
    //   github.com/owner/repo
    //   owner/repo
    let path = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("github.com/")
        .trim_end_matches(".git");

    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 {
        return Err(AppError::BadRequest(format!(
            "无效的 GitHub URL: {}（格式应为 owner/repo）",
            url
        )));
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

// ============================================================================
// WASM 脚本执行（支持多语言、输出捕获）
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RunScriptRequest {
    /// WASM 模块 URL 或已安装的 app_id
    pub source: String,
    /// 入口函数名（默认 _start）
    pub function: Option<String>,
    /// 命令行参数
    pub args: Option<Vec<String>>,
    /// 环境变量
    pub env: Option<HashMap<String, String>>,
    /// 执行超时秒数（默认 30，最大 300）
    pub timeout_secs: Option<u64>,
    /// 将 stdin 数据传入 WASM
    pub stdin_data: Option<String>,
}

/// POST /api/v1/wasm-store/wasm/run-script - 执行 WASM 脚本并捕获输出
///
/// 与 `run_wasm_app` 不同，此端点：
/// - 捕获 stdout 和 stderr 输出并返回给调用者
/// - 支持可配置超时（最长 5 分钟）
/// - 支持 stdin 数据传入
/// - 支持直接通过 URL 执行（无需先安装）
pub async fn run_wasm_script(
    body: web::Json<RunScriptRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let source = body.source.clone();
    let func_name = body
        .function
        .clone()
        .unwrap_or_else(|| "_start".to_string());
    let args = body.args.clone().unwrap_or_default();
    let env = body.env.clone().unwrap_or_default();
    let timeout_secs = body.timeout_secs.unwrap_or(30).min(300);
    let stdin_data = body.stdin_data.clone();

    info!(
        "执行 WASM 脚本: source={}, func={}, timeout={}s",
        source, func_name, timeout_secs
    );

    // 获取 WASM 字节码
    let wasm_bytes = if source.starts_with("http://") || source.starts_with("https://") {
        // 从 URL 下载
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;

        let resp = client
            .get(&source)
            .send()
            .await
            .map_err(|e| AppError::BadRequest(format!("下载 WASM 失败: {}", e)))?;

        if !resp.status().is_success() {
            return Err(AppError::BadRequest("下载 WASM 失败".to_string()));
        }

        resp.bytes()
            .await
            .map_err(|e| AppError::BadRequest(format!("读取失败: {}", e)))?
            .to_vec()
    } else {
        // 从已安装的应用加载
        let apps = load_wasm_registry_async().await?;
        let app = apps
            .iter()
            .find(|a| a.id == source && a.installed)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "WASM 应用 '{}' 未找到或未安装",
                    source
                ))
            })?;

        let path = app
            .installed_path
            .as_ref()
            .ok_or_else(|| AppError::NotFound("WASM 路径不存在".to_string()))?;

        tokio::fs::read(path)
            .await
            .map_err(|e| AppError::IoError(format!("读取 WASM 文件失败: {}", e)))?
    };

    let func_name_clone = func_name.clone();
    let source_clone = source.clone();
    let start_time = Instant::now();

    // 在 blocking 线程中执行 WASM，捕获 stdout/stderr
    let exec_result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::task::spawn_blocking(move || -> Result<(String, String), AppError> {
            let engine = wasmtime::Engine::default();
            let module = wasmtime::Module::new(&engine, &wasm_bytes)
                .map_err(|e| AppError::BadRequest(format!("无效 WASM: {}", e)))?;

            let mut linker = wasmtime::Linker::new(&engine);
            #[allow(deprecated)]
            wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;

            #[allow(deprecated)]
            let mut builder = wasmtime_wasi::sync::WasiCtxBuilder::new();

            // 使用 wasi_common::pipe 捕获 stdout/stderr
            let stdout_pipe = wasi_common::pipe::WritePipe::new_in_memory();
            let stderr_pipe = wasi_common::pipe::WritePipe::new_in_memory();

            builder.stdout(Box::new(stdout_pipe.clone()));
            builder.stderr(Box::new(stderr_pipe.clone()));

            // 设置 stdin
            if let Some(ref data) = stdin_data {
                let bytes = data.as_bytes().to_vec();
                builder.stdin(Box::new(wasi_common::pipe::ReadPipe::from(bytes)));
            }

            for arg in &args {
                builder.arg(arg)
                    .map_err(|e| AppError::ValidationError(format!("无效参数: {}", e)))?;
            }

            for (key, value) in &env {
                builder.env(key, value)
                    .map_err(|e| AppError::ValidationError(format!("无效环境变量: {}", e)))?;
            }

            let mut store = wasmtime::Store::new(&engine, builder.build());
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| AppError::BadRequest(format!("实例化失败: {}", e)))?;

            // 尝试调用
            let call_result = if let Ok(entry) =
                instance.get_typed_func::<(), ()>(&mut store, &func_name_clone)
            {
                entry.call(&mut store, ()).map_err(|e| {
                    AppError::BadRequest(format!("WASM 执行失败: {}", e))
                })
            } else if let Some(func) = instance.get_func(&mut store, &func_name_clone) {
                func.call(&mut store, &[], &mut []).map_err(|e| {
                    AppError::BadRequest(format!("WASM 执行失败: {}", e))
                })
            } else {
                return Err(AppError::NotFound(format!(
                    "函数 '{}' 不存在",
                    func_name_clone
                )));
            };

            // 释放 store 以 flush 管道
            drop(store);

            // 提取管道输出
            let stdout = stdout_pipe
                .try_into_inner()
                .map(|cursor| String::from_utf8_lossy(&cursor.into_inner()).to_string())
                .unwrap_or_default();

            let stderr = stderr_pipe
                .try_into_inner()
                .map(|cursor| String::from_utf8_lossy(&cursor.into_inner()).to_string())
                .unwrap_or_default();

            call_result?;
            Ok((stdout, stderr))
        }),
    )
    .await;

    let elapsed_ms = start_time.elapsed().as_millis();

    match exec_result {
        Ok(Ok(Ok((stdout, stderr)))) => {
            info!(
                "WASM 脚本执行成功: {} ({}ms)",
                source_clone, elapsed_ms
            );
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "completed",
                "source": source,
                "function": func_name,
                "stdout": stdout,
                "stderr": stderr,
                "elapsed_ms": elapsed_ms,
            })))
        }
        Ok(Ok(Err(app_err))) => Err(app_err),
        Ok(Err(join_err)) => Err(AppError::InternalServerError(format!(
            "执行线程异常: {}",
            join_err
        ))),
        Err(_timeout) => {
            warn!(
                "WASM 脚本超时 ({}s): {}",
                timeout_secs, source_clone
            );
            Err(AppError::InternalServerError(format!(
                "WASM 执行超时 ({}s)",
                timeout_secs
            )))
        }
    }
}

// ============================================================================
// 平台游戏数据 — 从官方 API 获取 (Epic / WeGame / Ubisoft / Xbox)
// ============================================================================

/// 平台游戏查询参数
#[derive(Debug, Deserialize)]
pub struct PlatformGamesQuery {
    pub platform: String,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub market: Option<String>,
    pub locale: Option<String>,
}

/// GET /api/v1/wasm-store/platform/games - 获取指定平台的游戏列表
///
/// 支持平台: epic, wegame, ubisoft, xbox
/// 优先从官方 API 获取实时数据，缓存 30 分钟；API 不可用时返回空
pub async fn get_platform_games(
    query: web::Query<PlatformGamesQuery>,
) -> Result<HttpResponse, AppError> {
    let platform = query.platform.to_lowercase();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(30).min(100);
    let market = query.market.clone().unwrap_or_else(|| "CN".to_string());
    let locale = query
        .locale
        .clone()
        .unwrap_or_else(|| "zh-cn".to_string());

    info!(
        "获取平台游戏数据: platform={}, page={}, page_size={}, market={}, locale={}",
        platform, page, page_size, market, locale
    );

    let cache_key = format!("platform_games_{}_{}_{}", platform, market.to_uppercase(), locale.to_lowercase());
    if let Some(cached) = cache_get(&cache_key).await {
        let total = cached.len();
        let start = ((page - 1) * page_size) as usize;
        let items: Vec<Value> = cached.into_iter().skip(start).take(page_size as usize).collect();
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "platform": platform,
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": ((total as f64) / (page_size as f64)).ceil() as u32,
            "cached": true,
            "source": "cache",
        })));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let fetch_count = (page * page_size).min(300);
    let games = match platform.as_str() {
        "epic" => fetch_epic_platform_games(&client, fetch_count, &market, &locale).await,
        "wegame" => fetch_wegame_platform_games(&client, page_size).await,
        "ubisoft" => fetch_ubisoft_platform_games(&client, page_size).await,
        "xbox" => fetch_xbox_platform_games(&client, fetch_count, &market, &locale).await,
        _ => {
            return Err(AppError::BadRequest(format!(
                "不支持的平台: {}。支持: epic, wegame, ubisoft, xbox",
                platform
            )));
        }
    };

    let fetch_failed = games.is_err();
    let mut items = games.unwrap_or_default();

    if fetch_failed {
        if let Some(stale) = cache_get_stale(&cache_key).await {
            let total = stale.len();
            let start = ((page - 1) * page_size) as usize;
            let paged: Vec<Value> = stale.into_iter().skip(start).take(page_size as usize).collect();
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "platform": platform,
                "items": paged,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": ((total as f64) / (page_size as f64)).ceil() as u32,
                "cached": true,
                "stale": true,
                "source": "stale-cache",
            })));
        }
    }

    items.sort_by(|a, b| {
        let an = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let bn = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        an.cmp(bn)
    });

    let total = items.len();
    let start = ((page - 1) * page_size) as usize;
    let paged: Vec<Value> = items.clone().into_iter().skip(start).take(page_size as usize).collect();

    if !items.is_empty() {
        cache_set(&cache_key, items.clone(), 1800).await; // 缓存 30 分钟
    }

    info!("平台 {} 游戏数据: {} 款 (live)", platform, total);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "platform": platform,
        "items": paged,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": ((total as f64) / (page_size as f64)).ceil() as u32,
        "cached": false,
        "source": "api",
    })))
}

/// Epic Games — 使用 GraphQL API 获取全品类游戏
async fn fetch_epic_platform_games(
    client: &Client,
    count: u32,
    market: &str,
    locale: &str,
) -> Result<Vec<Value>, AppError> {
    let query_body = serde_json::json!({
        "query": r#"query searchStoreQuery($count: Int, $country: String!, $locale: String, $sortBy: String, $sortDir: String, $start: Int, $withPrice: Boolean = true) {
            Catalog {
                searchStore(count: $count, country: $country, locale: $locale, sortBy: $sortBy, sortDir: $sortDir, start: $start) {
                    elements {
                        title
                        id
                        namespace
                        description
                        keyImages { type url }
                        seller { name }
                        categories { path }
                        tags { id name }
                        price(country: $country) @include(if: $withPrice) {
                            totalPrice {
                                discountPrice
                                originalPrice
                                currencyCode
                                fmtPrice(locale: "zh-CN") { originalPrice discountPrice }
                            }
                        }
                    }
                    paging { count total }
                }
            }
        }"#,
        "variables": {
            "count": count,
            "country": market.to_uppercase(),
            "locale": locale,
            "sortBy": "releaseDate",
            "sortDir": "DESC",
            "start": 0,
            "withPrice": true,
        }
    });

    let resp = client
        .post("https://graphql.epicgames.com/graphql")
        .header("Content-Type", "application/json")
        .json(&query_body)
        .send()
        .await
        .map_err(|e| AppError::InternalServerError(format!("Epic API 请求失败: {}", e)))?;

    if !resp.status().is_success() {
        warn!("Epic API 返回非 200: {}", resp.status());
        return Ok(Vec::new());
    }

    let json: Value = resp.json().await.unwrap_or(Value::Null);

    let elements = json
        .pointer("/data/Catalog/searchStore/elements")
        .and_then(|v| v.as_array());

    let mut games = Vec::new();
    if let Some(elems) = elements {
        for elem in elems {
            let title = elem.get("title").and_then(|v| v.as_str()).unwrap_or("");
            if title.is_empty() {
                continue;
            }

            let id = elem.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let desc = elem.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let seller = elem.pointer("/seller/name").and_then(|v| v.as_str()).unwrap_or("");

            let header_image = elem
                .get("keyImages")
                .and_then(|v| v.as_array())
                .and_then(|imgs| {
                    imgs.iter()
                        .find(|img| {
                            matches!(
                                img.get("type").and_then(|t| t.as_str()),
                                Some("OfferImageWide" | "DieselStoreFrontWide" | "Thumbnail")
                            )
                        })
                        .or_else(|| imgs.first())
                        .and_then(|img| img.get("url").and_then(|u| u.as_str()))
                })
                .unwrap_or("");

            let discount_price = elem
                .pointer("/price/totalPrice/discountPrice")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let original_price = elem
                .pointer("/price/totalPrice/originalPrice")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let is_free = discount_price == 0;
            let formatted_price = if is_free {
                "免费".to_string()
            } else {
                elem.pointer("/price/totalPrice/fmtPrice/discountPrice")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };

            let namespace = elem.get("namespace").and_then(|v| v.as_str()).unwrap_or("");

            let tags: Vec<String> = elem
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                        .take(5)
                        .collect()
                })
                .unwrap_or_default();

            let genre = elem
                .get("categories")
                .and_then(|v| v.as_array())
                .and_then(|cats| {
                    cats.first()
                        .and_then(|c| c.get("path").and_then(|p| p.as_str()))
                })
                .unwrap_or("games")
                .to_string();

            let store_url = if !namespace.is_empty() {
                format!("https://store.epicgames.com/zh-CN/p/{}", namespace)
            } else {
                "https://store.epicgames.com/zh-CN".to_string()
            };

            games.push(serde_json::json!({
                "id": id,
                "name": title,
                "developer": seller,
                "genre": genre,
                "description": desc,
                "header_image": header_image,
                "is_free": is_free,
                "platform": "epic",
                "store_url": store_url,
                "tags": tags,
                "price": {
                    "original": original_price,
                    "final": discount_price,
                    "formatted": formatted_price,
                },
            }));
        }
    }

    Ok(games)
}

/// WeGame — 使用腾讯 WeGame 内部 API 获取游戏列表
async fn fetch_wegame_platform_games(client: &Client, count: u32) -> Result<Vec<Value>, AppError> {
    // WeGame 商店推荐 API (公开可访问)
    let body = serde_json::json!({
        "search_text": "",
        "limit": count.min(50),
        "platform_id": 0,
        "sort_field": 1,
        "sort_type": 1,
        "scene": "wegame-store-pc"
    });

    let resp = match client
        .post("https://www.wegame.com.cn/api/v1/wegame.product.search/")
        .header("Content-Type", "application/json")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .header("Accept", "application/json")
        .header("Accept-Language", "zh-CN,zh;q=0.9")
        .header("Referer", "https://www.wegame.com.cn/store")
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("WeGame API 请求失败: {}", e);
            // 尝试备用 API: 热门游戏列表
            return fetch_wegame_hot_games(client, count).await;
        }
    };

    if !resp.status().is_success() {
        warn!("WeGame API 非 200: {}", resp.status());
        return fetch_wegame_hot_games(client, count).await;
    }

    let json: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("WeGame JSON 解析失败: {}", e);
            return fetch_wegame_hot_games(client, count).await;
        }
    };

    let mut games = Vec::new();

    if let Some(items) = json
        .pointer("/data/items")
        .or_else(|| json.pointer("/result/items"))
        .and_then(|v| v.as_array())
    {
        for item in items {
            let name = item
                .get("name")
                .or_else(|| item.get("product_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }

            let id = item
                .get("product_id")
                .or_else(|| item.get("id"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let desc = item
                .get("description")
                .or_else(|| item.get("short_desc"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let developer = item
                .get("developer")
                .or_else(|| item.get("developer_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let header_image = item
                .get("icon_url")
                .or_else(|| item.get("cover_url"))
                .or_else(|| item.get("image_url"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let is_free = item
                .get("is_free")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let price_val = item
                .get("price")
                .or_else(|| item.get("current_price"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let formatted_price = if is_free || price_val == 0.0 {
                "免费".to_string()
            } else {
                format!("¥{:.0}", price_val / 100.0)
            };

            let genre = item
                .get("category")
                .or_else(|| item.get("genre"))
                .and_then(|v| v.as_str())
                .unwrap_or("游戏")
                .to_string();

            let tags: Vec<String> = item
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            t.as_str()
                                .map(String::from)
                                .or_else(|| t.get("name").and_then(|n| n.as_str()).map(String::from))
                        })
                        .take(5)
                        .collect()
                })
                .unwrap_or_default();

            games.push(serde_json::json!({
                "id": format!("wg_{}", id),
                "name": name,
                "developer": developer,
                "genre": genre,
                "description": desc,
                "header_image": header_image,
                "is_free": is_free,
                "platform": "wegame",
                "store_url": format!("https://www.wegame.com.cn/store/detail?productid={}", id),
                "tags": tags,
                "price": {
                    "final": price_val as u64,
                    "formatted": formatted_price,
                },
            }));
        }
    }

    info!("WeGame 搜索 API: {} 款游戏", games.len());
    Ok(games)
}

/// WeGame 备用: 热门游戏排行列表
async fn fetch_wegame_hot_games(client: &Client, count: u32) -> Result<Vec<Value>, AppError> {
    // 使用 WeGame 热门排行 API
    let url = format!(
        "https://www.wegame.com.cn/api/v1/wegame.pcsale.recommend/GetRankList?limit={}&offset=0",
        count.min(50)
    );

    let resp = match client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .header("Referer", "https://www.wegame.com.cn/store")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("WeGame 热门排行 API 也失败: {}", e);
            return Ok(Vec::new());
        }
    };

    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let json: Value = resp.json().await.unwrap_or(Value::Null);
    let mut games = Vec::new();

    if let Some(items) = json
        .pointer("/data/rank_list")
        .or_else(|| json.pointer("/result/items"))
        .and_then(|v| v.as_array())
    {
        for item in items {
            let name = item
                .get("product_name")
                .or_else(|| item.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let id = item
                .get("product_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let icon = item
                .get("icon_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            games.push(serde_json::json!({
                "id": format!("wg_{}", id),
                "name": name,
                "developer": "",
                "genre": "游戏",
                "description": "",
                "header_image": icon,
                "is_free": false,
                "platform": "wegame",
                "store_url": format!("https://www.wegame.com.cn/store/detail?productid={}", id),
                "tags": [],
                "price": { "formatted": "" },
            }));
        }
    }

    info!("WeGame 热门排行: {} 款", games.len());
    Ok(games)
}

/// Ubisoft — 使用 Ubisoft Store API 获取游戏列表
async fn fetch_ubisoft_platform_games(client: &Client, count: u32) -> Result<Vec<Value>, AppError> {
    // Ubisoft Store REST API（公开可访问）
    let url = format!(
        "https://store.ubisoft.com/on/demandware.store/Sites-us-ubisoft-Site/zh_TW/Search-Show?cgid=games&format=ajax&start=0&sz={}",
        count.min(60)
    );

    let resp = match client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .header("Accept", "application/json, text/html")
        .header("Accept-Language", "zh-TW,zh;q=0.9,en;q=0.8")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Ubisoft Store API 请求失败: {}", e);
            return fetch_ubisoft_from_api_v2(client, count).await;
        }
    };

    if !resp.status().is_success() {
        warn!("Ubisoft Store API 非 200: {}", resp.status());
        return fetch_ubisoft_from_api_v2(client, count).await;
    }

    let body = resp.text().await.unwrap_or_default();

    // 尝试 JSON 解析
    if let Ok(json) = serde_json::from_str::<Value>(&body) {
        let mut games = Vec::new();

        if let Some(hits) = json
            .pointer("/hits")
            .or_else(|| json.pointer("/products"))
            .or_else(|| json.pointer("/data/products"))
            .and_then(|v| v.as_array())
        {
            for hit in hits.iter().take(count as usize) {
                let name = hit
                    .get("productName")
                    .or_else(|| hit.get("name"))
                    .or_else(|| hit.get("title"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if name.is_empty() {
                    continue;
                }

                let id = hit
                    .get("productID")
                    .or_else(|| hit.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let desc = hit
                    .get("shortDescription")
                    .or_else(|| hit.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let image = hit
                    .get("image")
                    .or_else(|| hit.pointer("/images/0/url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let brand = hit
                    .get("brand")
                    .or_else(|| hit.get("developer"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Ubisoft");
                let category = hit
                    .get("primaryCategory")
                    .or_else(|| hit.get("genre"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("游戏");

                let price_str = hit
                    .pointer("/price/sales/value")
                    .or_else(|| hit.get("price"))
                    .and_then(|v| v.as_f64())
                    .map(|p| format!("¥{:.0}", p))
                    .unwrap_or_default();

                let is_free = hit
                    .get("isFree")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let url = hit
                    .get("url")
                    .or_else(|| hit.get("pdpUrl"))
                    .and_then(|v| v.as_str())
                    .map(|u| {
                        if u.starts_with("http") {
                            u.to_string()
                        } else {
                            format!("https://store.ubisoft.com{}", u)
                        }
                    })
                    .unwrap_or_else(|| "https://store.ubisoft.com".to_string());

                games.push(serde_json::json!({
                    "id": format!("ubi_{}", id),
                    "name": name,
                    "developer": brand,
                    "genre": category,
                    "description": desc,
                    "header_image": image,
                    "is_free": is_free,
                    "platform": "ubisoft",
                    "store_url": url,
                    "tags": [],
                    "price": { "formatted": if is_free { "免费".to_string() } else { price_str } },
                }));
            }
        }

        if !games.is_empty() {
            info!("Ubisoft Store API: {} 款游戏", games.len());
            return Ok(games);
        }
    }

    // JSON 解析失败 → 尝试 v2 API
    fetch_ubisoft_from_api_v2(client, count).await
}

/// Ubisoft 备用 API — 使用不同端点
async fn fetch_ubisoft_from_api_v2(client: &Client, count: u32) -> Result<Vec<Value>, AppError> {
    // 尝试 Ubisoft Connect API
    let url = "https://public-ubiservices.ubi.com/v1/spaces/4ce775e2-fdd5-4a1a-b78a-a0d7846e498f/sandboxes/UPLAY_PC_NA/catalog/products?limit=30&offset=0";

    let resp = match client
        .get(url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .header("Ubi-AppId", "e3d5ea9e-50bd-43b7-88bf-39794f4e3d40")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => {
            warn!("Ubisoft 所有 API 均失败");
            return Ok(Vec::new());
        }
    };

    let json: Value = resp.json().await.unwrap_or(Value::Null);
    let mut games = Vec::new();

    if let Some(items) = json.get("products").and_then(|v| v.as_array()) {
        for item in items.iter().take(count as usize) {
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let id = item.get("productId").and_then(|v| v.as_str()).unwrap_or("");
            let desc = item
                .get("shortDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let image = item
                .pointer("/images/0")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            games.push(serde_json::json!({
                "id": format!("ubi_{}", id),
                "name": name,
                "developer": "Ubisoft",
                "genre": "游戏",
                "description": desc,
                "header_image": image,
                "is_free": false,
                "platform": "ubisoft",
                "store_url": format!("https://www.ubisoft.com/zh-tw/game/{}", id),
                "tags": [],
                "price": { "formatted": "" },
            }));
        }
    }

    info!("Ubisoft v2 API: {} 款", games.len());
    Ok(games)
}

/// Xbox / Microsoft — 使用 Xbox Game Pass 目录 API + Microsoft Display Catalog
async fn fetch_xbox_platform_games(
    client: &Client,
    count: u32,
    market: &str,
    locale: &str,
) -> Result<Vec<Value>, AppError> {
    // Xbox Game Pass PC 目录 (公开 API, 无需密钥)
    // sigls ID 对照: fdd9e2a7-... = Game Pass PC
    let gp_url = format!(
        "https://catalog.gamepass.com/sigls/v2?id=fdd9e2a7-0fee-49f6-ad69-4354098401ff&language={}&market={}",
        locale,
        market.to_uppercase()
    );

    let resp = match client
        .get(&gp_url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .header("Accept", "application/json")
        .header("ms-cv", "RockZeroOS")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Xbox Game Pass API 请求失败: {}", e);
            return fetch_xbox_from_catalog(client, count).await;
        }
    };

    if !resp.status().is_success() {
        warn!("Xbox Game Pass API 非 200: {}", resp.status());
        return fetch_xbox_from_catalog(client, count).await;
    }

    let json: Value = resp.json().await.unwrap_or(Value::Null);
    let items = json.as_array();

    if let Some(items) = items {
        // Game Pass API 返回产品 ID 列表,需要批量查询详情
        let mut product_ids: Vec<String> = Vec::new();
        for item in items.iter().take(count as usize) {
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                product_ids.push(id.to_string());
            }
        }

        if !product_ids.is_empty() {
            return fetch_xbox_product_details(client, &product_ids, market, locale).await;
        }
    }

    // 直接从 DisplayCatalog 获取
    fetch_xbox_from_catalog(client, count).await
}

/// 批量获取 Xbox 产品详情 (Microsoft DisplayCatalog API)
async fn fetch_xbox_product_details(
    client: &Client,
    product_ids: &[String],
    market: &str,
    locale: &str,
) -> Result<Vec<Value>, AppError> {
    // DisplayCatalog API 每次最多查 20 个
    let mut all_games = Vec::new();

    for chunk in product_ids.chunks(20) {
        let big_ids = chunk.join(",");
        let url = format!(
            "https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={}&market={}&languages={},en-us&MS-CV=RockZeroOS",
            big_ids,
            market.to_uppercase(),
            locale
        );

        let resp = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let json: Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(products) = json.get("Products").and_then(|v| v.as_array()) {
            for product in products {
                let props = match product.get("LocalizedProperties").and_then(|v| v.as_array()).and_then(|a| a.first()) {
                    Some(p) => p,
                    None => continue,
                };

                let name = props
                    .get("ProductTitle")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if name.is_empty() {
                    continue;
                }

                let id = product
                    .get("ProductId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let desc = props
                    .get("ShortDescription")
                    .or_else(|| props.get("ShortTitle"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let developer = props
                    .get("DeveloperName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let publisher = props
                    .get("PublisherName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // 获取封面图
                let header_image = props
                    .get("Images")
                    .and_then(|v| v.as_array())
                    .and_then(|imgs| {
                        imgs.iter()
                            .find(|img| {
                                img.get("ImagePurpose")
                                    .and_then(|v| v.as_str())
                                    .map(|p| p == "SuperHeroArt" || p == "Poster" || p == "BoxArt")
                                    .unwrap_or(false)
                            })
                            .or_else(|| imgs.first())
                            .and_then(|img| img.get("Uri").and_then(|u| u.as_str()))
                    })
                    .map(|u| {
                        if u.starts_with("//") {
                            format!("https:{}", u)
                        } else {
                            u.to_string()
                        }
                    })
                    .unwrap_or_default();

                // 解析价格
                let (is_free, formatted_price) = product
                    .get("DisplaySkuAvailabilities")
                    .and_then(|v| v.as_array())
                    .and_then(|skus| skus.first())
                    .and_then(|sku| {
                        sku.get("Availabilities")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                    })
                    .map(|avail| {
                        let list_price = avail
                            .pointer("/OrderManagementData/Price/ListPrice")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let ms_price = avail
                            .pointer("/OrderManagementData/Price/MSRP")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let price = if list_price > 0.0 { list_price } else { ms_price };
                        let free = price == 0.0;
                        let fmt = if free {
                            "免费".to_string()
                        } else {
                            format!("¥{:.0}", price)
                        };
                        (free, fmt)
                    })
                    .unwrap_or((false, String::new()));

                let store_url = format!(
                    "https://www.xbox.com/zh-CN/games/store/{}",
                    id.to_lowercase()
                );

                let category = product
                    .get("Properties")
                    .and_then(|v| v.get("Category"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("游戏");

                all_games.push(serde_json::json!({
                    "id": format!("xb_{}", id),
                    "name": name,
                    "developer": if !developer.is_empty() { developer } else { publisher },
                    "genre": category,
                    "description": desc,
                    "header_image": header_image,
                    "is_free": is_free,
                    "platform": "xbox",
                    "store_url": store_url,
                    "tags": ["Game Pass"],
                    "price": { "formatted": formatted_price },
                }));
            }
        }
    }

    info!("Xbox DisplayCatalog: {} 款游戏", all_games.len());
    Ok(all_games)
}

/// Xbox 备用: 使用 Microsoft Store 搜索 API
async fn fetch_xbox_from_catalog(client: &Client, count: u32) -> Result<Vec<Value>, AppError> {
    // Microsoft Store 搜索接口
    let url = format!(
        "https://storeedgefd.dsx.mp.microsoft.com/v9.0/pages/pdp?market=CN&locale=zh-cn&deviceFamily=Windows.Xbox&appVersion=0&catalogIds=&productIds=&mediaGroup=Games&top={}",
        count.min(50)
    );

    let resp = match client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => {
            warn!("Xbox 所有 API 均失败");
            return Ok(Vec::new());
        }
    };

    let json: Value = resp.json().await.unwrap_or(Value::Null);
    let mut games = Vec::new();

    // storeedge API 结构
    if let Some(cards) = json
        .pointer("/Payload/Cards")
        .and_then(|v| v.as_array())
    {
        for card in cards {
            if let Some(items) = card.get("Items").and_then(|v| v.as_array()) {
                for item in items.iter().take(count as usize) {
                    let title = item
                        .get("Title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if title.is_empty() {
                        continue;
                    }
                    let id = item
                        .get("ProductId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let image = item
                        .get("ImageUrl")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    games.push(serde_json::json!({
                        "id": format!("xb_{}", id),
                        "name": title,
                        "developer": "",
                        "genre": "游戏",
                        "description": "",
                        "header_image": image,
                        "is_free": false,
                        "platform": "xbox",
                        "store_url": format!("https://www.xbox.com/zh-CN/games/store/{}", id.to_lowercase()),
                        "tags": [],
                        "price": { "formatted": "" },
                    }));
                }
            }
        }
    }

    info!("Xbox Store Edge: {} 款", games.len());
    Ok(games)
}

// ============================================================================
// 每日推荐 Top 30
// ============================================================================

/// GET /api/v1/wasm-store/recommendations - 每日 Top 30 游戏推荐
///
/// 聚合来源：
/// 1. Steam 热门新品（New & Trending）
/// 2. Steam 特惠游戏
/// 3. Epic 免费 / 限免游戏
/// 4. 本地 WASM 应用
///
/// 结果按以下权重排序：
/// - 免费游戏加权 +50
/// - 有折扣的加权 +(discount_percent)
/// - Steam 精选加权 +20
/// - 用户已拥有的标记但不排到前面
pub async fn get_daily_recommendations() -> Result<HttpResponse, AppError> {
    info!("获取每日 Top 30 推荐");

    // 尝试从缓存读取（24 小时有效）
    let cache_key = "daily_recommendations";
    if let Some(cached) = cache_get(cache_key).await {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "items": cached,
            "total": cached.len(),
            "cached": true,
            "generated_at": now_epoch(),
        })));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let owned_appids = get_owned_steam_appids_from_cache().await;

    // 并行获取 Steam 精选 + Epic 免费
    let (steam_data, epic_data) = tokio::join!(
        fetch_steam_featured_cached(&client),
        fetch_epic_free_cached(&client),
    );

    let mut scored_items: Vec<(i64, Value)> = Vec::new();

    // ── Steam 精选 → 加入推荐池 ──────────────────────────────────
    if let Ok(steam_games) = steam_data {
        for mut game in steam_games {
            let mut score: i64 = 20; // 精选基础分

            let is_free = game
                .get("is_free")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_free {
                score += 50;
            }

            let final_price = game
                .pointer("/price/final")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let original_price = game
                .pointer("/price/original")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if original_price > 0 && final_price < original_price {
                let discount = ((original_price - final_price) * 100 / original_price) as i64;
                score += discount;
            }

            let app_id = game
                .get("app_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let is_owned = owned_appids.contains(&app_id);

            if let Some(obj) = game.as_object_mut() {
                obj.insert("owned".to_string(), serde_json::json!(is_owned));
                obj.insert("recommendation_score".to_string(), serde_json::json!(score));
                obj.insert("recommendation_source".to_string(), serde_json::json!("steam_featured"));
            }

            scored_items.push((score, game));
        }
    }

    // ── Epic 免费 → 加入推荐池 ──────────────────────────────────
    if let Ok(epic_games) = epic_data {
        for mut game in epic_games {
            let mut score: i64 = 50; // 免费游戏高基础分

            let has_promo = game
                .get("has_active_promo")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if has_promo {
                score += 30; // 限时免费额外加分
            }

            if let Some(obj) = game.as_object_mut() {
                obj.insert("owned".to_string(), serde_json::json!(false));
                obj.insert("recommendation_score".to_string(), serde_json::json!(score));
                obj.insert("recommendation_source".to_string(), serde_json::json!("epic_free"));
            }

            scored_items.push((score, game));
        }
    }

    // ── 本地 WASM 应用 → 推荐未安装的 ──────────────────────────
    let wasm_apps = load_wasm_registry_async().await.unwrap_or_default();
    for app in &wasm_apps {
        if !app.installed {
            let score: i64 = 30;
            let item = serde_json::json!({
                "name": app.name,
                "id": app.id,
                "header_image": app.icon_url,
                "is_free": true,
                "platform": "wasm",
                "owned": false,
                "short_description": app.description,
                "store_url": "",
                "price": { "formatted": "免费" },
                "recommendation_score": score,
                "recommendation_source": "wasm_store",
                "genres": [],
            });
            scored_items.push((score, item));
        }
    }

    // 按分数降序排序
    scored_items.sort_by(|a, b| b.0.cmp(&a.0));

    // 每个平台取前 30（而非总共 30）
    let mut steam_items: Vec<Value> = Vec::new();
    let mut epic_items: Vec<Value> = Vec::new();
    let mut wasm_items: Vec<Value> = Vec::new();
    let mut other_items: Vec<Value> = Vec::new();

    for (_, item) in scored_items {
        let platform = item
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        match platform {
            "steam" if steam_items.len() < 30 => steam_items.push(item),
            "epic" if epic_items.len() < 30 => epic_items.push(item),
            "wasm" if wasm_items.len() < 30 => wasm_items.push(item),
            _ if other_items.len() < 30 => other_items.push(item),
            _ => {}
        }
    }

    // Combine all — frontend can filter by platform
    let mut recommendations: Vec<Value> = Vec::new();
    recommendations.extend(steam_items.iter().cloned());
    recommendations.extend(epic_items.iter().cloned());
    recommendations.extend(wasm_items.iter().cloned());
    recommendations.extend(other_items.iter().cloned());

    let total = recommendations.len();

    // 缓存 1 小时
    cache_set(cache_key, recommendations.clone(), 3600).await;

    info!(
        "每日推荐: Steam {} / Epic {} / WASM {} / 其他 {} = 总计 {}",
        steam_items.len(),
        epic_items.len(),
        wasm_items.len(),
        other_items.len(),
        total,
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": recommendations,
        "total": total,
        "per_platform": {
            "steam": steam_items.len(),
            "epic": epic_items.len(),
            "wasm": wasm_items.len(),
        },
        "cached": false,
        "generated_at": now_epoch(),
    })))
}

/// GET /api/v1/wasm-store/steam/search - Steam 商店搜索（独立端点）
pub async fn search_steam_store(
    query: web::Query<SearchQuery>,
) -> Result<HttpResponse, AppError> {
    let search_term = query.q.clone().unwrap_or_default();
    if search_term.is_empty() {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "items": [],
            "total": 0,
        })));
    }

    info!("Steam 商店搜索: {}", search_term);

    let cache_key = format!("steam_store_search_{}", search_term.to_lowercase());
    if let Some(cached) = cache_get(&cache_key).await {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "items": cached,
            "total": cached.len(),
            "cached": true,
        })));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    let url = format!(
        "https://store.steampowered.com/api/storesearch/?term={}&l=schinese&cc=CN",
        urlencoding::encode(&search_term)
    );

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("Steam 搜索 API 失败: {}", e);
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "items": [],
                "total": 0,
            })));
        }
    };

    if !resp.status().is_success() {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "items": [],
            "total": 0,
        })));
    }

    let json: Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => {
            return Ok(HttpResponse::Ok().json(serde_json::json!({
                "items": [],
                "total": 0,
            })));
        }
    };

    let owned_appids = get_owned_steam_appids_from_cache().await;
    let mut games = Vec::new();

    if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
        for item in items {
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let app_id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            if name.is_empty() || app_id == 0 {
                continue;
            }

            let tiny_image = item
                .get("tiny_image")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let price_info = item.get("price");
            let final_price = price_info
                .and_then(|p| p.get("final"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let is_free = final_price == 0;
            let formatted_price = if is_free {
                "免费".to_string()
            } else {
                format!("¥{:.2}", final_price as f64 / 100.0)
            };

            let platforms = item.get("platforms");
            let header_image = format!(
                "https://cdn.akamai.steamstatic.com/steam/apps/{}/header.jpg",
                app_id
            );

            games.push(serde_json::json!({
                "name": name,
                "app_id": app_id,
                "header_image": header_image,
                "tiny_image": tiny_image,
                "is_free": is_free,
                "platform": "steam",
                "owned": owned_appids.contains(&app_id),
                "store_url": format!("https://store.steampowered.com/app/{}", app_id),
                "price": {
                    "final": final_price,
                    "formatted": formatted_price,
                },
                "platforms": {
                    "windows": platforms.and_then(|p| p.get("windows")).and_then(|v| v.as_bool()).unwrap_or(false),
                    "linux": platforms.and_then(|p| p.get("linux")).and_then(|v| v.as_bool()).unwrap_or(false),
                    "mac": platforms.and_then(|p| p.get("mac")).and_then(|v| v.as_bool()).unwrap_or(false),
                },
                "short_description": "",
                "genres": [],
            }));
        }
    }

    let total = games.len();
    cache_set(&cache_key, games.clone(), 180).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": games,
        "total": total,
        "cached": false,
    })))
}
