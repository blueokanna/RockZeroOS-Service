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
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    if data.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&data).map_err(|e| {
        warn!("WASM registry JSON parse error: {}, returning empty", e);
        AppError::BadRequest(e.to_string())
    })
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
            warn!("Epic API 请求失败 (网络/超时): {}", e);
            return Ok(Vec::new());
        }
    };

    if !resp.status().is_success() {
        warn!("Epic API 返回非 200: {}", resp.status());
        return Ok(Vec::new());
    }

    let json: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("Epic JSON 解析失败: {}", e);
            return Ok(Vec::new());
        }
    };

    let mut games = Vec::new();

    if let Some(elements) = json
        .pointer("/data/Catalog/searchStore/elements")
        .and_then(|v| v.as_array())
    {
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
    }

    info!("Epic 免费游戏: 获取到 {} 款", games.len());
    Ok(games)
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

/// GET /api/v1/wasm-store/search - 搜索游戏和应用
pub async fn search_wasm_apps(query: web::Query<SearchQuery>) -> Result<HttpResponse, AppError> {
    let search_term = query.q.clone().unwrap_or_default().to_lowercase();
    let category_filter = query.category.clone();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).min(100);

    info!(
        "搜索游戏和应用: q={}, category={:?}",
        search_term, category_filter
    );

    let mut results: Vec<Value> = Vec::new();

    // 搜索本地 WASM 应用
    let apps = load_wasm_registry_async().await.unwrap_or_default();
    for app in &apps {
        let matches_category = category_filter.as_ref().is_none_or(|cat| {
            let app_cat = serde_json::to_string(&app.category)
                .unwrap_or_default()
                .trim_matches('"')
                .to_lowercase();
            app_cat == cat.to_lowercase()
        });

        let matches_search = search_term.is_empty()
            || app.name.to_lowercase().contains(&search_term)
            || app.description.to_lowercase().contains(&search_term)
            || app.author.to_lowercase().contains(&search_term);

        if matches_category && matches_search {
            results.push(serde_json::json!({
                "name": app.name,
                "id": app.id,
                "header_image": app.icon_url,
                "is_free": true,
                "platform": "wasm",
                "short_description": app.description,
                "store_url": "",
                "price": { "formatted": "免费" },
                "genres": [],
            }));
        }
    }

    // 如果有搜索词，也搜索已缓存的 Steam 游戏（不发起新请求）
    if !search_term.is_empty() && category_filter.is_none() {
        if let Some(steam_games) = cache_get("steam_featured").await {
            for game in steam_games {
                let name = game
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if name.contains(&search_term) {
                    results.push(game);
                }
            }
        }
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
