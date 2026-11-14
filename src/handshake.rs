// lumzel:mobile-companion#relay-fwd lumzel:remote-link#g-claim lumzel:remote-link#r-control lumzel:remote-link-02#m-relay lumzel:remote-link-03#m-claim lumzel:remote-link-03#a-hello
//! Admission. The first text on a socket is `link_hello`: the route it wants, an
//! optional single-use Host ticket, and no key. The handshake that follows is between
//! the two ends and travels in frames; the relay forwards it, does not take part, and
//! cannot open a lumzel-frame.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub host: String,
    pub sid: String,
    pub ticket: Option<String>,
}

impl Hello {
    pub fn sanitized_text(&self, raw: &str) -> String {
        if self.ticket.is_none() {
            raw.to_owned()
        } else {
            serde_json::json!({
                "type": "link_hello",
                "v": VERSION,
                "host": self.host,
                "sid": self.sid,
            })
            .to_string()
        }
    }
}

/// The wire version this relay routes. A hello for any other is refused, and so is
/// the v1 `e2ee_hello`.
const VERSION: u64 = 2;

pub fn check_hello(text: &str) -> Result<Hello, ()> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if value.get("type").and_then(|v| v.as_str()) != Some("link_hello") {
        return Err(());
    }
    if value.get("v").and_then(|v| v.as_u64()) != Some(VERSION) {
        return Err(());
    }
    let host = value.get("host").and_then(|v| v.as_str()).ok_or(())?;
    let sid = value.get("sid").and_then(|v| v.as_str()).ok_or(())?;
    if !crate::routes::valid_route_id(host) || !crate::routes::valid_route_id(sid) {
        return Err(());
    }
    let ticket = match value.get("ticket") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let s = v.as_str().ok_or(())?;
            if !valid_ticket(s) {
                return Err(());
            }
            Some(s.to_owned())
        }
    };
    Ok(Hello {
        host: host.to_owned(),
        sid: sid.to_owned(),
        ticket,
    })
}

fn valid_ticket(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_a_v2_hello_and_refuses_v1_and_other_versions() {
        assert_eq!(
            check_hello(r#"{"type":"link_hello","v":2,"host":"h","sid":"s"}"#).unwrap(),
            Hello {
                host: "h".into(),
                sid: "s".into(),
                ticket: None,
            }
        );
        assert_eq!(
            check_hello(r#"{"type":"link_hello","v":2,"host":"h","sid":"s","ticket":"t1"}"#)
                .unwrap(),
            Hello {
                host: "h".into(),
                sid: "s".into(),
                ticket: Some("t1".into()),
            }
        );
        assert!(
            check_hello(r#"{"type":"link_hello","v":2,"host":"h","sid":"s","ticket":""}"#).is_err()
        );
        // The v1 hello, key and all.
        assert!(check_hello(
            r#"{"type":"e2ee_hello","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","host":"h","sid":"s"}"#
        )
        .is_err());
        assert!(check_hello(r#"{"type":"link_hello","v":1,"host":"h","sid":"s"}"#).is_err());
        assert!(check_hello(r#"{"type":"link_hello","host":"h","sid":"s"}"#).is_err());
        assert!(check_hello(r#"{"type":"link_hello","v":2,"host":"","sid":"s"}"#).is_err());
        assert!(check_hello(r#"{"type":"link_hello","v":2,"host":"h"}"#).is_err());
    }
}
