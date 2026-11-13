// lumzel:mobile-companion#relay-data lumzel:remote-link#relay-pair lumzel:remote-link#r-data
//! Data plane. Text is rejected. Bytes go only to the other data socket.

use axum::extract::{State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::control;
use crate::limits::PeerAddr;
use crate::ops::AppState;
use crate::routes::Plane;

pub async fn ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
) -> Response {
    control::accept(ws, state, plane_data(), peer, headers)
}

fn plane_data() -> Plane {
    Plane::Data
}
