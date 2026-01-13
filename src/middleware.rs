use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header::AUTHORIZATION,
    Error, HttpMessage, HttpResponse,
};
use futures::future::{ok, LocalBoxFuture, Ready};
use std::rc::Rc;

use crate::auth::JwtHandler;
use crate::config::AppConfig;

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
