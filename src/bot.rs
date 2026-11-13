// lumzel:remote-link#relay-mcp lumzel:remote-link#r-mcp lumzel:remote-link-08#m-bot lumzel:remote-link-08#a-mcp lumzel:remote-link-08#a-oauth
//! Bot reverse proxy endpoints on Relay.
//! Terminates TLS, proxies HTTP requests to Host over `/host` WS (`t: "http"`),
//! and renders OAuth authorize page with a fixed HTML template (escaping Host content).

use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;

use crate::inbox::HttpDispatchError;
use crate::ops::AppState;

const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
const PROXY_TIMEOUT: Duration = Duration::from_secs(60);

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
        .route("/mcp/{*rest}", any(handle_mcp))
        .route("/.well-known/{*rest}", any(handle_well_known))
}

async fn handle_mcp(
    State(state): State<AppState>,
    Path(rest): Path<String>,
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
        host_id,
        format!("/mcp/{rest}"),
        req,
        is_authorize_page,
    )
    .await
}

async fn handle_well_known(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    req: Request,
) -> Response {
    if req.method() != Method::GET {
        return StatusCode::NOT_FOUND.into_response();
    }
    let parts: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    // Path should be oauth-protected-resource/mcp/<host_id> or oauth-authorization-server/mcp/<host_id>
    let host_id = match parts.as_slice() {
        ["oauth-protected-resource", "mcp", host_id] => *host_id,
        ["oauth-authorization-server", "mcp", host_id] => *host_id,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    forward_request(state, host_id, format!("/.well-known/{rest}"), req, false).await
}

async fn forward_request(
    state: AppState,
    host_id: &str,
    path: String,
    req: Request,
    is_authorize_page: bool,
) -> Response {
    if !state.is_bot_enabled(host_id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Check Content-Length header early
    if let Some(cl) = req.headers().get(CONTENT_LENGTH) {
        if let Ok(cl_str) = cl.to_str() {
            if let Ok(len) = cl_str.parse::<usize>() {
                if len > MAX_BODY_BYTES {
                    return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                }
            }
        }
    }

    let method = req.method().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    let mut filtered_headers = HashMap::new();
    for (k, v) in req.headers() {
        let name = k.as_str().to_ascii_lowercase();
        if ALLOWED_REQ_HEADERS.contains(&name.as_str()) {
            if let Ok(val) = v.to_str() {
                filtered_headers.insert(name, val.to_string());
            }
        }
    }

    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    if body_bytes.len() > MAX_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    let b64_body = B64.encode(&body_bytes);

    let (req_id, rx) =
        match state.dispatch_http(host_id, method, path, query, filtered_headers, b64_body) {
            Ok(pair) => pair,
            Err(HttpDispatchError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(HttpDispatchError::Unavailable) => {
                return StatusCode::GATEWAY_TIMEOUT.into_response()
            }
        };

    let res = match tokio::time::timeout(PROXY_TIMEOUT, rx).await {
        Ok(Ok(res)) => res,
        Ok(Err(_)) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
        Err(_) => {
            state.cancel_http(req_id);
            return StatusCode::GATEWAY_TIMEOUT.into_response();
        }
    };

    let body_vec = B64.decode(&res.body).unwrap_or_default();

    if is_authorize_page && res.status == 200 {
        if let Ok(val) = serde_json::from_slice::<Value>(&body_vec) {
            let request = val.get("request").and_then(Value::as_str).unwrap_or("");
            let host_name = val.get("host_name").and_then(Value::as_str).unwrap_or("");
            let user_code = val.get("user_code").and_then(Value::as_str).unwrap_or("");

            let html = render_authorize_template(host_id, request, host_name, user_code);
            return (
                StatusCode::OK,
                [(CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response();
        }
    }

    let status = StatusCode::from_u16(res.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_headers = HeaderMap::new();
    for (k, v) in res.headers {
        let lower = k.to_ascii_lowercase();
        if ALLOWED_RES_HEADERS.contains(&lower.as_str()) {
            if let (Ok(hname), Ok(hval)) = (
                HeaderName::from_bytes(lower.as_bytes()),
                HeaderValue::from_str(&v),
            ) {
                response_headers.insert(hname, hval);
            }
        }
    }

    (status, response_headers, Bytes::from(body_vec)).into_response()
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

fn render_authorize_template(
    host_id: &str,
    request: &str,
    host_name: &str,
    user_code: &str,
) -> String {
    let esc_host_id = escape_html(host_id);
    let esc_req = escape_html(request);
    let esc_host_name = escape_html(host_name);
    let esc_user_code = escape_html(user_code);

    format!(
        r#"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Bot - Lumzel</title>
<style>
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
<script>
(function() {{
  const req = "{esc_req}";
  const hostId = "{esc_host_id}";
  async function check() {{
    try {{
      const res = await fetch(`/mcp/${{hostId}}/authorize/status?request=${{encodeURIComponent(req)}}`);
      if (res.ok) {{
        const data = await res.json();
        if (data.status === "approved" && data.redirect_uri) {{
          document.getElementById("status").textContent = "已确认，正在跳回...";
          window.location.href = data.redirect_uri;
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
