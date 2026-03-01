use actix_web::{web, HttpRequest, HttpResponse};
use reqwest::Client;
use rockzero_common::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

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

/// WASM 应用分类
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

/// 插件接口定义
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

/// 商店分类
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreCategory {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub count: i64,
}

// ============================================================================
// 请求/响应模型
// ============================================================================

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

fn load_wasm_registry() -> Result<Vec<WasmApp>, AppError> {
    let path = wasm_registry_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| AppError::IoError(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AppError::BadRequest(e.to_string()))
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
pub async fn get_store_overview() -> Result<HttpResponse, AppError> {
    info!("🏪 获取 WASM 商店概览");

    let wasm_apps = load_wasm_registry().unwrap_or_default();
    let plugins = load_plugin_registry().unwrap_or_default();

    // 并行获取 Steam 精选和 Epic 免费游戏
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let (steam_result, epic_result) = tokio::join!(
        fetch_steam_featured_internal(&client),
        fetch_epic_free_internal(&client),
    );

    let featured_games = steam_result.unwrap_or_default();
    let free_games = epic_result.unwrap_or_default();

    let categories = vec![
        StoreCategory {
            id: "wasm_apps".to_string(),
            name: "WASM 应用".to_string(),
            icon: "�".to_string(),
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
            icon: "�".to_string(),
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
// Steam / Epic 数据获取
// ============================================================================

/// 内部函数：获取 Steam 精选游戏列表
async fn fetch_steam_featured_internal(client: &Client) -> Result<Vec<Value>, AppError> {
    let resp = client
        .get("https://store.steampowered.com/api/featured/")
        .header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
        .send()
        .await
        .map_err(|e| {
            info!("Steam API 请求失败: {}", e);
            AppError::InternalServerError(format!("Steam API error: {}", e))
        })?;

    if !resp.status().is_success() {
        info!("Steam API 返回非 200: {}", resp.status());
        return Ok(Vec::new());
    }

    let json: Value = resp.json().await.map_err(|e| {
        AppError::InternalServerError(format!("Steam JSON parse error: {}", e))
    })?;

    let mut games = Vec::new();

    // 从 featured_win (Windows 精选) 和 large_capsules 中提取游戏
    for section_key in &["featured_win", "featured_mac", "featured_linux", "large_capsules"] {
        if let Some(items) = json.get(section_key).and_then(|v| v.as_array()) {
            for item in items {
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let app_id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                if name.is_empty() || app_id == 0 {
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
                    "".to_string()
                };

                let game = serde_json::json!({
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
                });

                // 去重
                if !games.iter().any(|g: &Value| g.get("app_id") == Some(&serde_json::json!(app_id))) {
                    games.push(game);
                }
            }
        }
    }

    info!("Steam 精选: 获取到 {} 款游戏", games.len());
    Ok(games)
}

/// 内部函数：获取 Epic 免费游戏列表
async fn fetch_epic_free_internal(client: &Client) -> Result<Vec<Value>, AppError> {
    // Epic Games Store 免费游戏 GraphQL API
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

    let resp = client
        .post("https://graphql.epicgames.com/graphql")
        .header("Content-Type", "application/json")
        .json(&query_body)
        .send()
        .await
        .map_err(|e| {
            info!("Epic API 请求失败: {}", e);
            AppError::InternalServerError(format!("Epic API error: {}", e))
        })?;

    if !resp.status().is_success() {
        info!("Epic API 返回非 200: {}", resp.status());
        return Ok(Vec::new());
    }

    let json: Value = resp.json().await.map_err(|e| {
        AppError::InternalServerError(format!("Epic JSON parse error: {}", e))
    })?;

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

            // 获取封面图
            let header_image = elem
                .get("keyImages")
                .and_then(|v| v.as_array())
                .and_then(|images| {
                    images
                        .iter()
                        .find(|img| {
                            img.get("type")
                                .and_then(|t| t.as_str())
                                .map(|t| t == "OfferImageWide" || t == "DieselStoreFrontWide" || t == "Thumbnail")
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

            // 检查是否当前有促销（真正免费领取）
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

            let namespace = elem.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
            let store_url = if !namespace.is_empty() {
                format!("https://store.epicgames.com/zh-CN/p/{}", namespace)
            } else {
                "https://store.epicgames.com/zh-CN/free-games".to_string()
            };

            let game = serde_json::json!({
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
            });

            games.push(game);
        }
    }

    info!("Epic 免费游戏: 获取到 {} 款", games.len());
    Ok(games)
}

/// GET /api/v1/wasm-store/steam/featured - Steam 精选游戏
pub async fn get_steam_featured() -> Result<HttpResponse, AppError> {
    info!("🎮 获取 Steam 精选游戏");
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let games = fetch_steam_featured_internal(&client).await.unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": games,
        "total": games.len(),
    })))
}

/// GET /api/v1/wasm-store/steam/app/{app_id} - Steam 游戏详情
pub async fn get_steam_app_details(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("🎮 获取 Steam 游戏详情: {}", app_id);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
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
        return Err(AppError::InternalServerError("Steam API 请求失败".to_string()));
    }

    let json: Value = resp
        .json()
        .await
        .map_err(|e| AppError::InternalServerError(format!("JSON parse error: {}", e)))?;

    // Steam API 返回 { "app_id": { "success": true, "data": {...} } }
    let data = json
        .get(&app_id)
        .and_then(|v| v.get("data"))
        .cloned()
        .unwrap_or(serde_json::json!({}));

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/v1/wasm-store/epic/free - Epic 免费游戏
pub async fn get_epic_free_games() -> Result<HttpResponse, AppError> {
    info!("🎁 获取 Epic 免费游戏");
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let games = fetch_epic_free_internal(&client).await.unwrap_or_default();

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
        "🔍 搜索游戏和应用: q={}, category={:?}",
        search_term, category_filter
    );

    let mut results: Vec<Value> = Vec::new();

    // 搜索本地 WASM 应用
    let apps = load_wasm_registry().unwrap_or_default();
    for app in &apps {
        let matches_category = category_filter.as_ref().map_or(true, |cat| {
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

    // 如果有搜索词，也搜索 Steam 游戏
    if !search_term.is_empty() && category_filter.is_none() {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        // 使用 Steam 搜索 API
        if let Ok(steam_games) = fetch_steam_featured_internal(&client).await {
            for game in steam_games {
                let name = game.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name.to_lowercase().contains(&search_term) {
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
    info!("📦 获取 WASM 应用列表");
    let apps = load_wasm_registry()?;
    Ok(HttpResponse::Ok().json(apps))
}

/// GET /api/v1/wasm-store/wasm/apps/{app_id} - 获取单个 WASM 应用详情
pub async fn get_wasm_app_details(path: web::Path<String>) -> Result<HttpResponse, AppError> {
    let app_id = path.into_inner();
    info!("📦 获取 WASM 应用详情: {}", app_id);

    let apps = load_wasm_registry()?;
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

    info!("📦 安装 WASM 应用: {}", body.name);

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

    // 验证是有效的 WASM 模块
    let engine = wasmtime::Engine::default();
    wasmtime::Module::new(&engine, &bytes)
        .map_err(|e| AppError::BadRequest(format!("无效的 WASM 模块: {}", e)))?;

    // 保存到磁盘
    let store_dir = wasm_store_root().join("modules");
    std::fs::create_dir_all(&store_dir).map_err(|e| AppError::IoError(e.to_string()))?;

    let filename = format!("{}_{}.wasm", body.app_id, &hash_hex[..8]);
    let file_path = store_dir.join(&filename);
    std::fs::write(&file_path, &bytes).map_err(|e| AppError::IoError(e.to_string()))?;

    // 更新注册表
    let mut apps = load_wasm_registry()?;

    if let Some(existing) = apps.iter_mut().find(|a| a.id == body.app_id) {
        existing.installed = true;
        existing.installed_path = Some(file_path.to_string_lossy().to_string());
        existing.updated_at = now_epoch();
    } else {
        apps.push(WasmApp {
            id: body.app_id.clone(),
            name: body.name.clone(),
            description: String::new(),
            version: "1.0.0".to_string(),
            author: String::new(),
            icon_url: String::new(),
            wasm_url: body.wasm_url.clone(),
            category: WasmAppCategory::Other,
            size_bytes: bytes.len() as u64,
            installed: true,
            installed_path: Some(file_path.to_string_lossy().to_string()),
            permissions: Vec::new(),
            created_at: now_epoch(),
            updated_at: now_epoch(),
        });
    }

    save_wasm_registry(&apps)?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "installed",
        "app_id": body.app_id,
        "hash": hash_hex,
        "size": bytes.len(),
    })))
}

/// POST /api/v1/wasm-store/wasm/{app_id}/run - 运行 WASM 应用
pub async fn run_wasm_app(
    path: web::Path<String>,
    body: web::Json<RunWasmAppRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("▶️ 运行 WASM 应用: {}", app_id);

    let apps = load_wasm_registry()?;
    let app = apps
        .iter()
        .find(|a| a.id == app_id && a.installed)
        .ok_or_else(|| AppError::NotFound(format!("WASM 应用 {} 未安装", app_id)))?;

    let wasm_path = app
        .installed_path
        .as_ref()
        .ok_or_else(|| AppError::NotFound("WASM 模块路径未找到".to_string()))?;

    if !Path::new(wasm_path).exists() {
        return Err(AppError::NotFound("WASM 模块文件不存在".to_string()));
    }

    let engine = wasmtime::Engine::default();
    let module = wasmtime::Module::from_file(&engine, wasm_path)
        .map_err(|e| AppError::BadRequest(format!("加载 WASM 模块失败: {}", e)))?;

    let mut linker = wasmtime::Linker::new(&engine);
    wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let mut builder = wasmtime_wasi::sync::WasiCtxBuilder::new();
    builder.inherit_stdio();

    if let Some(args) = &body.args {
        for arg in args {
            builder
                .arg(arg)
                .map_err(|e| AppError::ValidationError(format!("无效参数: {}", e)))?;
        }
    }

    if let Some(env) = &body.env {
        for (key, value) in env {
            builder
                .env(key, value)
                .map_err(|e| AppError::ValidationError(format!("无效环境变量: {}", e)))?;
        }
    }

    let mut store = wasmtime::Store::new(&engine, builder.build());
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| AppError::BadRequest(format!("实例化 WASM 失败: {}", e)))?;

    let func_name = body
        .function
        .clone()
        .unwrap_or_else(|| "_start".to_string());

    if let Ok(entry) = instance.get_typed_func::<(), ()>(&mut store, &func_name) {
        entry
            .call(&mut store, ())
            .map_err(|e| AppError::BadRequest(format!("WASM 执行失败: {}", e)))?;
    } else if let Some(func) = instance.get_func(&mut store, &func_name) {
        func.call(&mut store, &[], &mut [])
            .map_err(|e| AppError::BadRequest(format!("WASM 执行失败: {}", e)))?;
    } else {
        return Err(AppError::NotFound(format!(
            "函数 '{}' 在 WASM 模块中未找到",
            func_name
        )));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "completed",
        "app_id": app_id,
        "function": func_name,
    })))
}

/// DELETE /api/v1/wasm-store/wasm/{app_id} - 卸载 WASM 应用
pub async fn uninstall_wasm_app(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let app_id = path.into_inner();
    info!("🗑️ 卸载 WASM 应用: {}", app_id);

    let mut apps = load_wasm_registry()?;

    if let Some(app) = apps.iter_mut().find(|a| a.id == app_id) {
        if let Some(path) = &app.installed_path {
            let _ = std::fs::remove_file(path);
        }
        app.installed = false;
        app.installed_path = None;
        save_wasm_registry(&apps)?;

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "uninstalled",
            "app_id": app_id,
        })))
    } else {
        Err(AppError::NotFound(format!("WASM 应用 {} 未找到", app_id)))
    }
}

// ============================================================================
// 插件系统
// ============================================================================

/// GET /api/v1/wasm-store/plugins - 获取已注册插件列表
pub async fn list_plugins() -> Result<HttpResponse, AppError> {
    info!("🔌 获取插件列表");
    let plugins = load_plugin_registry()?;
    Ok(HttpResponse::Ok().json(plugins))
}

/// POST /api/v1/wasm-store/plugins/register - 注册新插件
pub async fn register_plugin(
    body: web::Json<RegisterPluginRequest>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    info!("🔌 注册插件: {}", body.manifest.name);

    let mut plugins = load_plugin_registry()?;

    if plugins.iter().any(|p| p.id == body.manifest.id) {
        if let Some(existing) = plugins.iter_mut().find(|p| p.id == body.manifest.id) {
            *existing = body.manifest.clone();
        }
    } else {
        plugins.push(body.manifest.clone());
    }

    save_plugin_registry(&plugins)?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "status": "registered",
        "plugin_id": body.manifest.id,
    })))
}

/// DELETE /api/v1/wasm-store/plugins/{plugin_id} - 注销插件
pub async fn unregister_plugin(
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    crate::middleware::verify_fido2_or_passkey(&req).await?;

    let plugin_id = path.into_inner();
    info!("🔌 注销插件: {}", plugin_id);

    let mut plugins = load_plugin_registry()?;
    let original_len = plugins.len();
    plugins.retain(|p| p.id != plugin_id);

    if plugins.len() == original_len {
        return Err(AppError::NotFound(format!("插件 {} 未找到", plugin_id)));
    }

    save_plugin_registry(&plugins)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "unregistered",
        "plugin_id": plugin_id,
    })))
}
