// lumzel:mobile-companion#relay-push
//! Wake hint only. No title, body, or path. Absent keys means push does not exist.

use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wake {
    pub host_id: String,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    Unavailable,
    BadPayload,
}

#[derive(Clone)]
pub struct Sender {
    inner: Arc<Inner>,
}

struct Inner {
    available: bool,
    log: Mutex<Vec<Wake>>,
}

impl Sender {
    pub fn from_env() -> Self {
        let apns = std::env::var("RELAY_APNS_KEY").unwrap_or_default();
        let fcm = std::env::var("RELAY_FCM_KEY").unwrap_or_default();
        Self::configured(!apns.is_empty() || !fcm.is_empty())
    }

    /// Test constructor. `key` is not a credential and is not stored.
    pub fn with_fake_key(key: &str) -> Self {
        Self::configured(!key.is_empty())
    }

    pub(crate) fn unavailable() -> Self {
        Self::configured(false)
    }

    fn configured(available: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                available,
                log: Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn available(&self) -> bool {
        self.inner.available
    }

    pub fn send(&self, wake: Wake) -> Result<(), PushError> {
        if !self.available() {
            return Err(PushError::Unavailable);
        }
        if !valid_host(&wake.host_id) {
            return Err(PushError::BadPayload);
        }
        self.inner.log.lock().expect("push log").push(wake);
        Ok(())
    }

    pub(crate) fn recorded(&self) -> String {
        let log = self.inner.log.lock().expect("push log");
        let mut out = String::new();
        for wake in log.iter() {
            out.push_str(&wake.host_id);
            out.push(' ');
            out.push_str(&wake.count.to_string());
            out.push('\n');
        }
        out
    }
}

pub(crate) fn accept(sender: &Sender, body: &[u8]) -> Result<(), PushError> {
    if !sender.available() {
        return Err(PushError::Unavailable);
    }
    let wake = parse_wake(body)?;
    sender.send(wake)
}

fn parse_wake(body: &[u8]) -> Result<Wake, PushError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| PushError::BadPayload)?;
    let obj = value.as_object().ok_or(PushError::BadPayload)?;
    if obj.len() != 2 {
        return Err(PushError::BadPayload);
    }
    let host_id = match obj.get("host_id") {
        Some(serde_json::Value::String(host_id)) => host_id.clone(),
        _ => return Err(PushError::BadPayload),
    };
    if !valid_host(&host_id) {
        return Err(PushError::BadPayload);
    }
    let count = match obj.get("count") {
        Some(serde_json::Value::Number(count)) => count.as_u64().ok_or(PushError::BadPayload)?,
        _ => return Err(PushError::BadPayload),
    };
    Ok(Wake { host_id, count })
}

fn valid_host(host_id: &str) -> bool {
    (1..=256).contains(&host_id.len())
}
