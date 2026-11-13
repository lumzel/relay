// lumzel:mobile-companion#relay-punch
//! Punch text is a literal ip:port. Hostnames and schemes are rejected.

use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Punch {
    pub addr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchError;

pub fn parse_punch(text: &str) -> Result<Punch, PunchError> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| PunchError)?;
    let obj = value.as_object().ok_or(PunchError)?;
    if obj.get("t").and_then(|item| item.as_str()) != Some("punch") {
        return Err(PunchError);
    }
    let addr = obj
        .get("addr")
        .and_then(|item| item.as_str())
        .ok_or(PunchError)?;
    validate_addr(addr)?;
    Ok(Punch {
        addr: addr.to_owned(),
    })
}

fn validate_addr(addr: &str) -> Result<(), PunchError> {
    if addr.is_empty() || addr.contains("://") || addr.contains('/') {
        return Err(PunchError);
    }
    let socket: SocketAddr = addr.parse().map_err(|_| PunchError)?;
    if socket.port() == 0 {
        return Err(PunchError);
    }
    Ok(())
}
