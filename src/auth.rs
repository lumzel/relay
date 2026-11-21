// lumzel:remote-link#relay-limits
//! Optional shared-secret authentication for personal/private Relay deployments,
//! plus dependency-free CLI flag parsing for the `lumzel-relay` binary.

use axum::extract::{Request, State};
use axum::http::header::{HeaderMap, AUTHORIZATION, CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::limits::PeerAddr;
use crate::ops::AppState;

pub const ENV_LUMZEL_RELAY_PASSWORD: &str = "LUMZEL_RELAY_PASSWORD";
pub const ENV_RELAY_PASSWORD: &str = "RELAY_PASSWORD";

const HEADER_RELAY_PASSWORD: &str = "x-relay-password";
const HEADER_RELAY_TOKEN: &str = "x-relay-token";
const QUERY_AUTH_KEYS: &[&str] = &["token", "password", "relay_token", "relay_password"];

/// Parsed command-line options for `lumzel-relay`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CliArgs {
    pub bind: Option<String>,
    pub stun_bind: Option<String>,
    pub password: Option<String>,
    pub help: bool,
}

impl std::fmt::Debug for CliArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliArgs")
            .field("bind", &self.bind)
            .field("stun_bind", &self.stun_bind)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("help", &self.help)
            .finish()
    }
}

impl CliArgs {
    pub fn usage() -> &'static str {
        "Usage: lumzel-relay [OPTIONS]\n\
         \n\
         Options:\n\
           --bind <ADDR>         TCP listen address (overrides RELAY_BIND, default 0.0.0.0:8080)\n\
           --stun-bind <ADDRS>   Comma-separated UDP STUN addresses (overrides RELAY_STUN_BIND)\n\
           --password <SECRET>   Require shared secret on Relay endpoints (overrides LUMZEL_RELAY_PASSWORD / RELAY_PASSWORD)\n\
           -h, --help            Print this help message\n"
    }

    pub fn parse<I, S>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Self::default();
        let mut iter = args.into_iter();
        while let Some(raw) = iter.next() {
            let arg = raw.as_ref();
            match arg {
                "-h" | "--help" => {
                    out.help = true;
                }
                "--bind" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --bind".to_owned())?;
                    out.bind = Some(val.as_ref().to_owned());
                }
                "--stun-bind" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --stun-bind".to_owned())?;
                    out.stun_bind = Some(val.as_ref().to_owned());
                }
                "--password" => {
                    let val = iter
                        .next()
                        .ok_or_else(|| "missing value for --password".to_owned())?;
                    out.password = Some(val.as_ref().to_owned());
                }
                _ if arg.starts_with("--bind=") => {
                    out.bind = Some(arg["--bind=".len()..].to_owned());
                }
                _ if arg.starts_with("--stun-bind=") => {
                    out.stun_bind = Some(arg["--stun-bind=".len()..].to_owned());
                }
                _ if arg.starts_with("--password=") => {
                    out.password = Some(arg["--password=".len()..].to_owned());
                }
                other => {
                    return Err(format!("unknown argument: {other}"));
                }
            }
        }
        Ok(out)
    }
}

pub(crate) fn hash_password(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

pub(crate) fn password_from_env() -> Option<String> {
    if let Ok(val) = std::env::var(ENV_LUMZEL_RELAY_PASSWORD) {
        if !val.is_empty() {
            return Some(val);
        }
    }
    if let Ok(val) = std::env::var(ENV_RELAY_PASSWORD) {
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}

pub(crate) fn constant_time_matches(candidate: &str, expected_hash: &[u8; 32]) -> bool {
    let digest = Sha256::digest(candidate.as_bytes());
    bool::from(digest.as_slice().ct_eq(expected_hash))
}

fn strip_bearer(raw: &str) -> Option<&str> {
    if raw.len() > 7
        && raw.as_bytes()[..6].eq_ignore_ascii_case(b"bearer")
        && raw.as_bytes()[6] == b' '
    {
        Some(&raw[7..])
    } else {
        None
    }
}

fn percent_decode(s: &str, plus_as_space: bool) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut iter = s.as_bytes().iter();
    while let Some(&b) = iter.next() {
        match b {
            b'%' => {
                let mut clone = iter.clone();
                if let (Some(&h1), Some(&h2)) = (clone.next(), clone.next()) {
                    let hex_pair = [h1, h2];
                    if let Ok(hex_str) = std::str::from_utf8(&hex_pair) {
                        if let Ok(decoded) = u8::from_str_radix(hex_str, 16) {
                            let _ = iter.next();
                            let _ = iter.next();
                            bytes.push(decoded);
                            continue;
                        }
                    }
                }
                bytes.push(b'%');
            }
            b'+' if plus_as_space => bytes.push(b' '),
            other => bytes.push(other),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn query_value_matches(raw_val: &str, expected_hash: &[u8; 32]) -> bool {
    let rfc3986 = percent_decode(raw_val, false);
    let mut matched = constant_time_matches(&rfc3986, expected_hash);
    if raw_val.contains('+') {
        let form = percent_decode(raw_val, true);
        matched |= constant_time_matches(&form, expected_hash);
    }
    matched
}

fn is_matching_query_param(part: &str, expected_hash: &[u8; 32]) -> bool {
    let Some((key, raw_val)) = part.split_once('=') else {
        return false;
    };
    if !QUERY_AUTH_KEYS.contains(&key) || raw_val.is_empty() {
        return false;
    }
    query_value_matches(raw_val, expected_hash)
}

struct AuthCheck {
    authenticated: bool,
    matched_authorization_header: bool,
    matched_query_param: bool,
}

fn check_request_credentials(
    headers: &HeaderMap,
    uri: &Uri,
    expected_hash: &[u8; 32],
) -> AuthCheck {
    let mut authenticated = false;
    let mut matched_authorization_header = false;
    let mut matched_query_param = false;

    for header_name in [HEADER_RELAY_PASSWORD, HEADER_RELAY_TOKEN] {
        if let Some(val) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            if constant_time_matches(val, expected_hash) {
                authenticated = true;
            }
        }
    }

    if let Some(auth_val) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = strip_bearer(auth_val) {
            if constant_time_matches(token, expected_hash) {
                authenticated = true;
                matched_authorization_header = true;
            }
        }
    }

    if let Some(query) = uri.query() {
        for part in query.split('&') {
            if is_matching_query_param(part, expected_hash) {
                authenticated = true;
                matched_query_param = true;
            }
        }
    }

    AuthCheck {
        authenticated,
        matched_authorization_header,
        matched_query_param,
    }
}

fn strip_matched_query_params(uri: &Uri, expected_hash: &[u8; 32]) -> Uri {
    let Some(query) = uri.query() else {
        return uri.clone();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|part| !is_matching_query_param(part, expected_hash))
        .collect();
    let path = uri.path();
    let new_pq = if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    let mut parts = uri.clone().into_parts();
    if let Ok(pq) = axum::http::uri::PathAndQuery::try_from(new_pq) {
        parts.path_and_query = Some(pq);
        if let Ok(rebuilt) = Uri::from_parts(parts) {
            return rebuilt;
        }
    }
    uri.clone()
}

fn unauthorized_response() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Bearer realm="lumzel-relay""#),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::UNAUTHORIZED, headers).into_response()
}

pub(crate) async fn require_password(
    State(state): State<AppState>,
    peer: PeerAddr,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(expected_hash) = state.password_hash() else {
        return next.run(req).await;
    };

    let check = check_request_credentials(req.headers(), req.uri(), expected_hash);
    if !check.authenticated {
        if state
            .limits()
            .try_acquire_http(peer.0, req.headers())
            .is_none()
        {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        return unauthorized_response();
    }

    // Sanitize Relay-level credentials before passing to handlers so secrets never
    // leak into proxied Host HTTP requests or rendered HTML templates.
    req.headers_mut().remove(HEADER_RELAY_PASSWORD);
    req.headers_mut().remove(HEADER_RELAY_TOKEN);
    if check.matched_authorization_header {
        req.headers_mut().remove(AUTHORIZATION);
    }
    if check.matched_query_param {
        let sanitized_uri = strip_matched_query_params(req.uri(), expected_hash);
        *req.uri_mut() = sanitized_uri;
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_args_parse_flags_and_redact_debug() {
        let parsed = CliArgs::parse([
            "--bind",
            "127.0.0.1:9000",
            "--stun-bind=127.0.0.1:3478",
            "--password",
            "top-secret-value",
        ])
        .unwrap();
        assert_eq!(parsed.bind.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(parsed.stun_bind.as_deref(), Some("127.0.0.1:3478"));
        assert_eq!(parsed.password.as_deref(), Some("top-secret-value"));
        assert!(!parsed.help);

        let dbg = format!("{parsed:?}");
        assert!(!dbg.contains("top-secret-value"));
        assert!(dbg.contains("[redacted]"));

        assert!(CliArgs::parse(["--unknown"]).is_err());
        assert!(CliArgs::parse(["--password"]).is_err());
    }
}
