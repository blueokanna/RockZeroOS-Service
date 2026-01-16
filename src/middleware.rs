use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::AUTHORIZATION,
    Error, HttpMessage, HttpRequest, HttpResponse,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use std::rc::Rc;

use crate::auth::JwtHandler;
use crate::config::AppConfig;
use crate::error::AppError;

/// 验证FIDO2或Passkey认证
/// 检查请求头中的 X-FIDO2-Assertion 或 X-Passkey-Assertion
pub async fn verify_fido2_or_passkey(req: &HttpRequest) -> Result<(), AppError> {
    // 检查FIDO2断言
    if let Some(fido2_assertion) = req.headers().get("X-FIDO2-Assertion") {
        if let Ok(assertion_str) = fido2_assertion.to_str() {
            // 验证FIDO2断言
            if crate::fido::verify_fido2_assertion(assertion_str).await.is_ok() {
                return Ok(());
            }
        }
    }
    
    // 检查Passkey断言
    if let Some(passkey_assertion) = req.headers().get("X-Passkey-Assertion") {
        if let Ok(assertion_str) = passkey_assertion.to_str() {
            // 验证Passkey断言（Passkey是FIDO2的一种实现）
            if crate::fido::verify_passkey_assertion(assertion_str).await.is_ok() {
                return Ok(());
            }
        }
    }
    
    Err(AppError::Unauthorized(
        "FIDO2 or Passkey authentication required for this operation".to_string()
    ))
}

pub struct JwtAuth;

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtAuthMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct JwtAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let config = req
                .app_data::<actix_web::web::Data<AppConfig>>()
                .expect("AppConfig not configured");

            let auth_header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok());

            match auth_header {
                Some(header) => {
                    match JwtHandler::extract_token_from_header(header) {
                        Ok(token) => {
                            let jwt_handler = JwtHandler::new(config.get_ref());
                            
                            match jwt_handler.verify_access_token(token).await {
                                Ok(claims) => {
                                    req.extensions_mut().insert(claims);
                                    
                                    let res = service.call(req).await?;
                                    Ok(res.map_into_left_body())
                                }
                                Err(e) => {
                                    let response = HttpResponse::Unauthorized()
                                        .json(serde_json::json!({
                                            "error": "UNAUTHORIZED",
                                            "message": e.to_string()
                                        }));
                                    Ok(req.into_response(response).map_into_right_body())
                                }
                            }
                        }
                        Err(e) => {
                            let response = HttpResponse::Unauthorized()
                                .json(serde_json::json!({
                                    "error": "UNAUTHORIZED",
                                    "message": e.to_string()
                                }));
                            Ok(req.into_response(response).map_into_right_body())
                        }
                    }
                }
                None => {
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "UNAUTHORIZED",
                            "message": "Missing Authorization header"
                        }));
                    Ok(req.into_response(response).map_into_right_body())
                }
            }
        })
    }
}
