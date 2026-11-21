// lumzel:remote-link#relay-mcp lumzel:remote-link#r-mcp lumzel:remote-link-08#m-bot lumzel:remote-link-08#a-mcp lumzel:remote-link-08#a-oauth
//! Bot reverse proxy endpoints on Relay.
//! Terminates TLS, proxies HTTP requests to Host over `/host` WS (`t: "http"`),
//! supports unified single-entry routing via `lzm_<host_id>.` prefixes and stateless HMAC DCR (`lzc_`),
//! and renders OAuth authorize pages with a fixed HTML template (escaping Host content).

use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE,
    HOST, REFERRER_POLICY, RETRY_AFTER, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::inbox::{BotHostStatus, HttpDispatchError, MAX_HOST_WS_MSG};
use crate::limits::PeerAddr;
use crate::ops::AppState;
use crate::routes::valid_route_id;

const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
const MAX_RES_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const PROXY_TIMEOUT: Duration = Duration::from_secs(60);

const BOT_SCOPES_SUPPORTED: &[&str] = &[
    "sessions",
    "files",
    "new_session",
    "projects",
    "workflows",
    "browser",
    "computer",
    "terminal",
    "all_files",
];

const ALLOWED_REQ_HEADERS: &[&str] = &[
    "authorization",
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
];

const ALLOWED_RES_HEADERS: &[&str] = &[
    "content-type",
    "www-authenticate",
    "cache-control",
    "location",
    "mcp-session-id",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/mcp", post(handle_mcp_single_entry))
        .route("/mcp/{*rest}", any(handle_mcp))
        .route("/oauth/register", post(handle_oauth_register))
        .route("/oauth/authorize", get(handle_oauth_authorize))
        .route(
            "/oauth/authorize/status",
            get(handle_oauth_authorize_status),
        )
        .route("/oauth/token", post(handle_oauth_token))
        .route(
            "/.well-known/openai-apps-challenge",
            get(handle_openai_apps_challenge),
        )
        .route("/.well-known/{*rest}", any(handle_well_known))
}

/// Extracts `host_id` from `lzm_<host_id>.<rest>` if syntactically valid.
pub fn extract_host_prefix(token: &str) -> Option<&str> {
    let rest = token.strip_prefix("lzm_")?;
    let (host_id, secret) = rest.split_once('.')?;
    if secret.is_empty() || !valid_route_id(host_id) {
        return None;
    }
    Some(host_id)
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

const MAX_STATELESS_CLIENT_ID_LEN: usize = 4096;

fn sign_stateless_client_id(
    secret: &[u8; 32],
    client_name: &str,
    redirect_uris: &[String],
) -> Option<String> {
    let json_bytes = serde_json::to_vec(&json!({
        "n": client_name,
        "u": redirect_uris,
    }))
    .ok()?;
    let payload_b64 = B64URL.encode(&json_bytes);
    let sig = hmac_sha256(secret, payload_b64.as_bytes());
    let sig_b64 = B64URL.encode(sig);
    let token = format!("lzc_{payload_b64}.{sig_b64}");
    (token.len() <= MAX_STATELESS_CLIENT_ID_LEN).then_some(token)
}

fn verify_stateless_client_id(secret: &[u8; 32], client_id: &str) -> Option<(String, Vec<String>)> {
    if client_id.len() > MAX_STATELESS_CLIENT_ID_LEN {
        return None;
    }
    let rest = client_id.strip_prefix("lzc_")?;
    let (payload_b64, sig_b64) = rest.split_once('.')?;
    if payload_b64.is_empty() || sig_b64.is_empty() {
        return None;
    }
    let sig_bytes = B64URL.decode(sig_b64).ok()?;
    let expected_sig = hmac_sha256(secret, payload_b64.as_bytes());
    if sig_bytes.len() != expected_sig.len()
        || !bool::from(sig_bytes.as_slice().ct_eq(expected_sig.as_slice()))
    {
        return None;
    }
    let payload_bytes = B64URL.decode(payload_b64).ok()?;
    let val: Value = serde_json::from_slice(&payload_bytes).ok()?;
    let name = val.get("n")?.as_str()?.to_owned();
    let uris: Vec<String> = val
        .get("u")?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    if uris.is_empty() || uris.len() > 16 {
        return None;
    }
    if !uris.iter().all(|u| is_safe_redirect_uri(u)) {
        return None;
    }
    Some((name, uris))
}

fn is_valid_host_authority(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 256
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

fn derive_public_base(
    state: &AppState,
    peer: Option<std::net::IpAddr>,
    headers: &HeaderMap,
) -> String {
    if let Some(configured) = state.public_url() {
        return configured.to_owned();
    }
    let trusted_proxy = state.limits().is_trusted_proxy(peer);
    let forwarded_host = if trusted_proxy {
        headers.get("x-forwarded-host")
    } else {
        None
    };
    let raw_host = forwarded_host
        .or_else(|| headers.get(HOST))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|h| is_valid_host_authority(h))
        .unwrap_or("localhost");

    let forwarded_proto = if trusted_proxy {
        headers.get("x-forwarded-proto")
    } else {
        None
    };
    let proto = forwarded_proto
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|p| *p == "http" || *p == "https")
        .unwrap_or_else(|| {
            if raw_host.starts_with("localhost")
                || raw_host.starts_with("127.0.0.1")
                || raw_host.starts_with("[::1]")
            {
                "http"
            } else {
                "https"
            }
        });
    format!("{proto}://{raw_host}")
}

fn unauthorized_single_entry_response(base: &str) -> Response {
    let mut headers = HeaderMap::new();
    let www_auth =
        format!(r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource""#);
    if let Ok(val) = HeaderValue::from_str(&www_auth) {
        headers.insert(WWW_AUTHENTICATE, val);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (
        StatusCode::UNAUTHORIZED,
        headers,
        Json(json!({
            "error": "unauthorized",
            "message": "Valid access token required"
        })),
    )
        .into_response()
}

async fn handle_openai_apps_challenge(State(state): State<AppState>) -> Response {
    let Some(token) = state.openai_apps_challenge() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    (StatusCode::OK, headers, token.to_owned()).into_response()
}

async fn handle_mcp_single_entry(
    State(state): State<AppState>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    let query_params = parse_query(req.uri().query().unwrap_or(""));
    let bearer_token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.strip_prefix("Bearer "))
        .map(str::trim);

    let host_id = bearer_token
        .and_then(extract_host_prefix)
        .or_else(|| {
            query_params
                .get("host")
                .map(String::as_str)
                .filter(|h| valid_route_id(h))
        })
        .map(str::to_owned);

    let Some(host_id) = host_id else {
        let base = derive_public_base(&state, peer.0, req.headers());
        return unauthorized_single_entry_response(&base);
    };

    forward_request(
        state,
        peer,
        &host_id,
        "/mcp".to_owned(),
        req,
        false,
        true,
        None,
    )
    .await
}

async fn handle_oauth_register(
    State(state): State<AppState>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    let query_params = parse_query(req.uri().query().unwrap_or(""));
    if let Some(host_id) = query_params
        .get("host")
        .filter(|h| valid_route_id(h))
        .cloned()
    {
        return forward_request(
            state,
            peer,
            &host_id,
            "/oauth/register".to_owned(),
            req,
            false,
            true,
            None,
        )
        .await;
    }

    if state.lock().admit().is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(_http_permit) = state.limits().try_acquire_http(peer.0, req.headers()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let Some(body_bytes) = read_bounded_body(req).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(val) = serde_json::from_slice::<Value>(&body_bytes) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "invalid json body" })),
        )
            .into_response();
    };

    let client_name: String = val["client_name"]
        .as_str()
        .unwrap_or("Bot Client")
        .chars()
        .take(256)
        .collect();
    let redirect_uris: Vec<String> = match val.get("redirect_uris") {
        None | Some(Value::Null) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_redirect_uri", "error_description": "redirect_uris is required" })),
            )
                .into_response();
        }
        Some(Value::Array(arr)) => {
            if arr.is_empty() || arr.len() > 16 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid_redirect_uri", "error_description": "redirect_uris must contain 1 to 16 entries" })),
                )
                    .into_response();
            }
            let mut uris = Vec::with_capacity(arr.len());
            for item in arr {
                let Some(s) = item.as_str() else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "invalid_redirect_uri", "error_description": "redirect_uri must be string" })),
                    )
                        .into_response();
                };
                if !is_safe_redirect_uri(s) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "invalid_redirect_uri", "error_description": "unsafe redirect_uri" })),
                    )
                        .into_response();
                }
                uris.push(s.to_owned());
            }
            uris
        }
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_redirect_uri", "error_description": "redirect_uris must be an array" })),
            )
                .into_response();
        }
    };

    let Some(client_id) =
        sign_stateless_client_id(state.dcr_secret(), &client_name, &redirect_uris)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
        })),
    )
        .into_response()
}

async fn handle_oauth_authorize(
    State(state): State<AppState>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    let query = req.uri().query().unwrap_or("").to_owned();
    let query_params = parse_query(&query);
    let client_id = query_params
        .get("client_id")
        .map(String::as_str)
        .unwrap_or("");
    let resolved_host = extract_host_prefix(client_id)
        .or_else(|| {
            query_params
                .get("host")
                .or_else(|| query_params.get("host_id"))
                .map(String::as_str)
                .filter(|h| valid_route_id(h))
        })
        .map(str::to_owned);

    let Some(host_id) = resolved_host else {
        if state.lock().admit().is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let Some(_http_permit) = state.limits().try_acquire_http(peer.0, req.headers()) else {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        };
        let mut nonce_raw = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_raw);
        let nonce = B64.encode(nonce_raw);
        let html = render_host_select_template(&query, &nonce);
        return html_response_with_csp(html, &nonce);
    };

    let mut extra_headers = HashMap::new();
    if client_id.starts_with("lzc_") {
        let Some((client_name, redirect_uris)) =
            verify_stateless_client_id(state.dcr_secret(), client_id)
        else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_client",
                    "error_description": "invalid stateless client_id"
                })),
            )
                .into_response();
        };
        let payload = serde_json::to_vec(&json!({
            "client_name": client_name,
            "redirect_uris": redirect_uris,
        }))
        .unwrap_or_default();
        extra_headers.insert("x-lumzel-dcr-client".to_owned(), B64.encode(payload));
    }

    forward_request(
        state,
        peer,
        &host_id,
        "/oauth/authorize".to_owned(),
        req,
        true,
        true,
        Some(extra_headers),
    )
    .await
}

async fn handle_oauth_authorize_status(
    State(state): State<AppState>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    let query_params = parse_query(req.uri().query().unwrap_or(""));
    let host_id = query_params
        .get("request")
        .and_then(|r| extract_host_prefix(r))
        .or_else(|| {
            query_params
                .get("host")
                .map(String::as_str)
                .filter(|h| valid_route_id(h))
        })
        .map(str::to_owned);

    let Some(host_id) = host_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_request", "error_description": "missing host routing prefix" })),
        )
            .into_response();
    };

    forward_request(
        state,
        peer,
        &host_id,
        "/oauth/authorize/status".to_owned(),
        req,
        false,
        true,
        None,
    )
    .await
}

async fn handle_oauth_token(
    State(state): State<AppState>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    if state.lock().admit().is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(_http_permit) = state.limits().try_acquire_http(peer.0, req.headers()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let query = req.uri().query().unwrap_or("").to_owned();
    let query_params = parse_query(&query);
    let filtered_headers = filter_request_headers(req.headers(), None);
    let Some(body_bytes) = read_bounded_body(req).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };

    let body_str = String::from_utf8_lossy(&body_bytes);
    let params = parse_form_or_json(&body_str, &body_bytes);
    let host_id = params
        .get("code")
        .and_then(|c| extract_host_prefix(c))
        .or_else(|| {
            params
                .get("refresh_token")
                .and_then(|t| extract_host_prefix(t))
        })
        .or_else(|| params.get("client_id").and_then(|c| extract_host_prefix(c)))
        .or_else(|| {
            query_params
                .get("host")
                .map(String::as_str)
                .filter(|h| valid_route_id(h))
        })
        .map(str::to_owned);

    let Some(host_id) = host_id else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "missing or invalid host routing prefix"
            })),
        )
            .into_response();
    };

    if !valid_route_id(&host_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.bot_host_status(&host_id) {
        BotHostStatus::Ready => {}
        BotHostStatus::Offline => return host_offline_response(),
        BotHostStatus::NotFound => return StatusCode::NOT_FOUND.into_response(),
    }

    let b64_body = B64.encode(&body_bytes);
    dispatch_and_build_response(
        &state,
        &host_id,
        "POST".to_owned(),
        "/oauth/token".to_owned(),
        query,
        filtered_headers,
        b64_body,
        false,
        true,
    )
    .await
}

async fn handle_mcp(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let host_id = parts[0];
    let method = req.method().clone();

    let is_valid = match parts.as_slice() {
        [_host] if method == Method::POST => true,
        [_host, "register"] if method == Method::POST => true,
        [_host, "token"] if method == Method::POST => true,
        [_host, "authorize"] if method == Method::GET => true,
        [_host, "authorize", "status"] if method == Method::GET => true,
        _ => false,
    };

    if !is_valid {
        return StatusCode::NOT_FOUND.into_response();
    }

    let is_authorize_page = parts.len() == 2 && parts[1] == "authorize" && method == Method::GET;
    forward_request(
        state,
        peer,
        host_id,
        format!("/mcp/{rest}"),
        req,
        is_authorize_page,
        false,
        None,
    )
    .await
}

async fn handle_well_known(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    peer: PeerAddr,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return StatusCode::NOT_FOUND.into_response();
    }
    let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match parts.as_slice() {
        ["oauth-protected-resource"] | ["oauth-protected-resource", "mcp"] => {
            let base = derive_public_base(&state, peer.0, req.headers());
            Json(json!({
                "resource": format!("{base}/mcp"),
                "authorization_servers": [base],
                "scopes_supported": BOT_SCOPES_SUPPORTED,
                "bearer_methods_supported": ["header"]
            }))
            .into_response()
        }
        ["oauth-authorization-server"] | ["oauth-authorization-server", "mcp"] => {
            let base = derive_public_base(&state, peer.0, req.headers());
            Json(json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/oauth/authorize"),
                "token_endpoint": format!("{base}/oauth/token"),
                "registration_endpoint": format!("{base}/oauth/register"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "scopes_supported": BOT_SCOPES_SUPPORTED,
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"]
            }))
            .into_response()
        }
        ["oauth-protected-resource", "mcp", host_id]
        | ["oauth-authorization-server", "mcp", host_id] => {
            forward_request(
                state,
                peer,
                host_id,
                format!("/.well-known/{rest}"),
                req,
                false,
                false,
                None,
            )
            .await
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn filter_request_headers(
    headers: &HeaderMap,
    extra_trusted: Option<HashMap<String, String>>,
) -> HashMap<String, String> {
    let mut filtered_headers = HashMap::new();
    for (k, v) in headers {
        let name = k.as_str().to_ascii_lowercase();
        if name.starts_with("x-lumzel-") {
            continue;
        }
        if ALLOWED_REQ_HEADERS.contains(&name.as_str()) {
            if let Ok(val) = v.to_str() {
                filtered_headers.insert(name, val.to_string());
            }
        }
    }
    if let Some(extra) = extra_trusted {
        for (k, v) in extra {
            filtered_headers.insert(k.to_ascii_lowercase(), v);
        }
    }
    filtered_headers
}

async fn read_bounded_body(req: Request) -> Option<Bytes> {
    if let Some(cl) = req.headers().get(CONTENT_LENGTH) {
        if let Ok(cl_str) = cl.to_str() {
            if let Ok(len) = cl_str.parse::<usize>() {
                if len > MAX_BODY_BYTES {
                    return None;
                }
            }
        }
    }
    let body_bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES + 1)
        .await
        .ok()?;
    if body_bytes.len() > MAX_BODY_BYTES {
        return None;
    }
    Some(body_bytes)
}

#[allow(clippy::too_many_arguments)]
async fn forward_request(
    state: AppState,
    peer: PeerAddr,
    host_id: &str,
    path: String,
    req: Request,
    is_authorize_page: bool,
    single_entry: bool,
    extra_headers: Option<HashMap<String, String>>,
) -> Response {
    if state.lock().admit().is_err() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if !valid_route_id(host_id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(_http_permit) = state.limits().try_acquire_http(peer.0, req.headers()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    match state.bot_host_status(host_id) {
        BotHostStatus::Ready => {}
        BotHostStatus::Offline => return host_offline_response(),
        BotHostStatus::NotFound => return StatusCode::NOT_FOUND.into_response(),
    }

    let method = req.method().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let filtered_headers = filter_request_headers(req.headers(), extra_headers);

    let Some(body_bytes) = read_bounded_body(req).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let b64_body = B64.encode(&body_bytes);

    dispatch_and_build_response(
        &state,
        host_id,
        method,
        path,
        query,
        filtered_headers,
        b64_body,
        is_authorize_page,
        single_entry,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_and_build_response(
    state: &AppState,
    host_id: &str,
    method: String,
    path: String,
    query: String,
    filtered_headers: HashMap<String, String>,
    b64_body: String,
    is_authorize_page: bool,
    single_entry: bool,
) -> Response {
    let (req_id, rx) =
        match state.dispatch_http(host_id, method, path, query, filtered_headers, b64_body) {
            Ok(pair) => pair,
            Err(HttpDispatchError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(HttpDispatchError::Offline) => return host_offline_response(),
            Err(HttpDispatchError::Unavailable) => {
                return StatusCode::GATEWAY_TIMEOUT.into_response()
            }
            Err(HttpDispatchError::Busy) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };

    let res = match tokio::time::timeout(PROXY_TIMEOUT, rx).await {
        Ok(Ok(res)) => res,
        Ok(Err(_)) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
        Err(_) => {
            state.cancel_http(req_id);
            return StatusCode::GATEWAY_TIMEOUT.into_response();
        }
    };

    if res.body.len() > MAX_HOST_WS_MSG {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let Ok(body_vec) = B64.decode(&res.body) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if body_vec.len() > MAX_RES_BODY_BYTES {
        return StatusCode::BAD_GATEWAY.into_response();
    }

    if is_authorize_page && res.status == 200 {
        let Ok(val) = serde_json::from_slice::<Value>(&body_vec) else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        let request = val.get("request").and_then(Value::as_str).unwrap_or("");
        if request.is_empty() {
            return StatusCode::BAD_GATEWAY.into_response();
        }
        let host_name = val.get("host_name").and_then(Value::as_str).unwrap_or("");
        let user_code = val.get("user_code").and_then(Value::as_str).unwrap_or("");

        let mut nonce_raw = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_raw);
        let nonce = B64.encode(nonce_raw);

        let html =
            render_authorize_template(host_id, request, host_name, user_code, &nonce, single_entry);
        return html_response_with_csp(html, &nonce);
    }

    let status = StatusCode::from_u16(res.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_headers = HeaderMap::new();
    for (k, v) in res.headers {
        let lower = k.to_ascii_lowercase();
        if ALLOWED_RES_HEADERS.contains(&lower.as_str()) {
            if lower == "content-type" && !is_safe_api_content_type(&v) {
                continue;
            }
            if let (Ok(hname), Ok(hval)) = (
                HeaderName::from_bytes(lower.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                response_headers.insert(hname, hval);
            }
        }
    }
    response_headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response_headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response_headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    (status, response_headers, Bytes::from(body_vec)).into_response()
}

fn html_response_with_csp(html: String, nonce: &str) -> Response {
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(csp_val) = HeaderValue::from_str(&csp) {
        headers.insert(HeaderName::from_static("content-security-policy"), csp_val);
    }
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, html).into_response()
}

fn host_offline_response() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::SERVICE_UNAVAILABLE, headers).into_response()
}

fn is_safe_api_content_type(ct: &str) -> bool {
    let media_type = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/json" | "application/problem+json" | "text/plain" | "application/octet-stream"
    )
}

fn is_safe_redirect_uri(uri: &str) -> bool {
    if uri.is_empty()
        || uri.len() > 2048
        || uri
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'#' || b == b'\\')
    {
        return false;
    }
    if let Some(rest) = uri.strip_prefix("https://") {
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            return false;
        }
        let host = if authority.starts_with('[') {
            authority
                .split_once(']')
                .map(|(h, _)| h.trim_start_matches('['))
                .unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        return !host.is_empty();
    }
    if let Some(rest) = uri.strip_prefix("http://") {
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            return false;
        }
        if let Some(after_bracket) = authority.strip_prefix('[') {
            let Some((host, port_part)) = after_bracket.split_once(']') else {
                return false;
            };
            if host != "::1" {
                return false;
            }
            if port_part.is_empty() {
                return true;
            }
            return port_part
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.parse::<u16>().is_ok());
        }
        let (host, port_valid) = match authority.split_once(':') {
            Some((h, p)) => (h, !p.is_empty() && p.parse::<u16>().is_ok()),
            None => (authority, true),
        };
        return port_valid && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1");
    }
    false
}

fn url_decode(s: &str) -> String {
    let mut bytes = Vec::new();
    let mut chars = s.as_bytes().iter();
    while let Some(&b) = chars.next() {
        match b {
            b'%' => {
                if let (Some(&h1), Some(&h2)) = (chars.next(), chars.next()) {
                    let hex_slice = [h1, h2];
                    if let Ok(byte) =
                        u8::from_str_radix(std::str::from_utf8(&hex_slice).unwrap_or(""), 16)
                    {
                        bytes.push(byte);
                        continue;
                    }
                    bytes.push(b'%');
                    bytes.push(h1);
                    bytes.push(h2);
                } else {
                    bytes.push(b'%');
                }
            }
            b'+' => bytes.push(b' '),
            other => bytes.push(other),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.to_string(), url_decode(v));
        }
    }
    map
}

fn parse_form_or_json(body_str: &str, body_bytes: &[u8]) -> HashMap<String, String> {
    if let Ok(val) = serde_json::from_slice::<Value>(body_bytes) {
        if let Some(obj) = val.as_object() {
            let mut map = HashMap::new();
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    map.insert(k.clone(), s.to_string());
                }
            }
            return map;
        }
    }
    parse_query(body_str)
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

fn js_string_literal(input: &str) -> String {
    let json = serde_json::to_string(input).unwrap_or_else(|_| "\"\"".to_owned());
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('/', "\\/")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn render_host_select_template(raw_query: &str, nonce: &str) -> String {
    let js_query = js_string_literal(raw_query);
    format!(
        r#"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Select Host - Lumzel</title>
<style nonce="{nonce}">
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f8fafc; color: #0f172a; }}
.card {{ background: #fff; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 420px; width: 100%; }}
h1 {{ font-size: 1.25rem; margin: 0 0 0.75rem; text-align: center; }}
.tip {{ font-size: 0.875rem; color: #64748b; line-height: 1.5; margin-bottom: 1rem; }}
input {{ width: 100%; box-sizing: border-box; padding: 0.625rem 0.75rem; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 0.9375rem; font-family: monospace; }}
button {{ width: 100%; margin-top: 1rem; padding: 0.625rem; border: 0; border-radius: 8px; background: #2563eb; color: #fff; font-size: 0.9375rem; font-weight: 600; cursor: pointer; }}
</style>
</head>
<body>
<div class="card">
<h1>输入 Lumzel Host ID</h1>
<p class="tip">请在 Lumzel 设置 &rarr; 远程访问中复制您的 Host ID，继续完成授权。</p>
<input id="host-input" type="text" placeholder="Host ID" autocomplete="off" />
<button id="continue-btn" type="button">继续授权</button>
</div>
<script nonce="{nonce}">
(function() {{
  const baseQuery = {js_query};
  const input = document.getElementById("host-input");
  const btn = document.getElementById("continue-btn");
  function submitHost() {{
    const host = input.value.trim();
    if (!host) return;
    const params = new URLSearchParams(baseQuery);
    const liveParams = new URLSearchParams(window.location.search);
    for (const k of ["token", "password", "relay_token", "relay_password"]) {{
      if (liveParams.has(k) && !params.has(k)) params.set(k, liveParams.get(k));
    }}
    params.set("host", host);
    window.location.href = "/oauth/authorize?" + params.toString();
  }}
  btn.addEventListener("click", submitHost);
  input.addEventListener("keydown", function(e) {{ if (e.key === "Enter") submitHost(); }});
}})();
</script>
</body>
</html>"#
    )
}

fn render_authorize_template(
    host_id: &str,
    request: &str,
    host_name: &str,
    user_code: &str,
    nonce: &str,
    single_entry: bool,
) -> String {
    let js_host_id = js_string_literal(host_id);
    let js_req = js_string_literal(request);
    let esc_host_name = escape_html(host_name);
    let esc_user_code = escape_html(user_code);
    let js_single_entry = if single_entry { "true" } else { "false" };

    format!(
        r#"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Bot - Lumzel</title>
<style nonce="{nonce}">
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f8fafc; color: #0f172a; }}
.card {{ background: #fff; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); max-width: 420px; width: 100%; text-align: center; }}
h1 {{ font-size: 1.25rem; margin-bottom: 1rem; }}
.code {{ font-size: 2rem; font-weight: 700; letter-spacing: 0.2em; color: #2563eb; margin: 1.5rem 0; font-family: monospace; }}
.tip {{ font-size: 0.875rem; color: #64748b; line-height: 1.5; }}
.status {{ margin-top: 1rem; font-size: 0.875rem; color: #94a3b8; }}
</style>
</head>
<body>
<div class="card">
<h1>授权 Bot 连接</h1>
<p class="tip">来自 Host: <strong>{esc_host_name}</strong></p>
<p class="tip">请在您的 Mac 或手机上核对并确认校验码：</p>
<div class="code" id="user-code">{esc_user_code}</div>
<p class="status" id="status">等待确认中...</p>
</div>
<script nonce="{nonce}">
(function() {{
  const req = {js_req};
  const hostId = {js_host_id};
  const singleEntry = {js_single_entry};
  function isSafeRedirect(raw) {{
    try {{
      const u = new URL(raw);
      if (u.protocol === "https:") return true;
      if (u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]")) return true;
      return false;
    }} catch (_) {{
      return false;
    }}
  }}
  async function check() {{
    try {{
      const pollParams = new URLSearchParams();
      pollParams.set("request", req);
      const liveParams = new URLSearchParams(window.location.search);
      for (const k of ["token", "password", "relay_token", "relay_password"]) {{
        if (liveParams.has(k)) pollParams.set(k, liveParams.get(k));
      }}
      const url = singleEntry
        ? `/oauth/authorize/status?${{pollParams.toString()}}`
        : `/mcp/${{encodeURIComponent(hostId)}}/authorize/status?${{pollParams.toString()}}`;
      const res = await fetch(url);
      if (res.ok) {{
        const data = await res.json();
        if (data.status === "approved" && data.redirect_uri) {{
          if (isSafeRedirect(data.redirect_uri)) {{
            document.getElementById("status").textContent = "已确认，正在跳回...";
            window.location.href = data.redirect_uri;
          }} else {{
            document.getElementById("status").textContent = "回调地址无效，已阻止跳转";
          }}
          return;
        }} else if (data.status === "denied") {{
          document.getElementById("status").textContent = "授权已被拒绝";
          return;
        }}
      }}
    }} catch (e) {{}}
    setTimeout(check, 1000);
  }}
  check();
}})();
</script>
</body>
</html>"#
    )
}
