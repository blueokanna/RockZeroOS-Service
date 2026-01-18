use actix_web::{web, HttpResponse, Responder};
use sqlx::SqlitePool;
use tracing::info;
use uuid::Uuid;
use validator::Validate;

use crate::db;
use rockzero_common::AppError;
use rockzero_common::models::{CreateWidgetRequest, UpdateWidgetRequest, Widget, WidgetResponse};

pub async fn list_widgets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
) -> Result<impl Responder, AppError> {
    let widgets = db::list_widgets_by_user(&pool, &claims.sub).await?;

    let responses: Vec<WidgetResponse> = widgets
        .into_iter()
        .map(|w| WidgetResponse {
            id: w.id,
            widget_type: w.widget_type,
            title: w.title,
            config: serde_json::from_str(&w.config_json).unwrap_or(serde_json::json!({})),
            position_x: w.position_x,
            position_y: w.position_y,
            width: w.width,
            height: w.height,
            is_visible: w.is_visible,
            created_at: w.created_at,
            updated_at: w.updated_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

pub async fn create_widget(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CreateWidgetRequest>,
) -> Result<impl Responder, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let widget = Widget {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        widget_type: body.widget_type.clone(),
        title: body.title.clone(),
        config_json: body.config.to_string(),
        position_x: body.position_x,
        position_y: body.position_y,
        width: body.width,
        height: body.height,
        is_visible: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    db::create_widget(&pool, &widget).await?;

    info!("Widget created: {} - User: {}", widget.title, claims.sub);

    Ok(HttpResponse::Created().json(WidgetResponse {
        id: widget.id,
        widget_type: widget.widget_type,
        title: widget.title,
        config: body.config.clone(),
        position_x: widget.position_x,
        position_y: widget.position_y,
        width: widget.width,
        height: widget.height,
        is_visible: widget.is_visible,
        created_at: widget.created_at,
        updated_at: widget.updated_at,
    }))
}

pub async fn update_widget(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    widget_id: web::Path<String>,
    body: web::Json<UpdateWidgetRequest>,
) -> Result<impl Responder, AppError> {
    let widgets = db::list_widgets_by_user(&pool, &claims.sub).await?;
    let mut widget = widgets
        .into_iter()
        .find(|w| w.id == *widget_id)
        .ok_or_else(|| AppError::NotFound("Widget not found".to_string()))?;

    if let Some(title) = &body.title {
        widget.title = title.clone();
    }
    if let Some(config) = &body.config {
        widget.config_json = config.to_string();
    }
    if let Some(x) = body.position_x {
        widget.position_x = x;
    }
    if let Some(y) = body.position_y {
        widget.position_y = y;
    }
    if let Some(w) = body.width {
        widget.width = w;
    }
    if let Some(h) = body.height {
        widget.height = h;
    }
    if let Some(visible) = body.is_visible {
        widget.is_visible = visible;
    }

    widget.updated_at = chrono::Utc::now();

    db::update_widget(&pool, &widget_id, &claims.sub, &widget).await?;

    info!("Widget updated: {} - User: {}", widget.title, claims.sub);

    Ok(HttpResponse::Ok().json(WidgetResponse {
        id: widget.id,
        widget_type: widget.widget_type,
        title: widget.title,
        config: serde_json::from_str(&widget.config_json).unwrap_or(serde_json::json!({})),
        position_x: widget.position_x,
        position_y: widget.position_y,
        width: widget.width,
        height: widget.height,
        is_visible: widget.is_visible,
        created_at: widget.created_at,
        updated_at: widget.updated_at,
    }))
}

pub async fn delete_widget(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    widget_id: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let deleted = db::delete_widget(&pool, &widget_id, &claims.sub).await?;

    if !deleted {
        return Err(AppError::NotFound("Widget not found".to_string()));
    }

    info!("Widget deleted: {} - User: {}", widget_id, claims.sub);

    Ok(HttpResponse::NoContent().finish())
}
