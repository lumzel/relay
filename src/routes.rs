// lumzel:mobile-companion#relay-meta lumzel:remote-link#g-claim lumzel:remote-link#relay-pair
//! Who owns a sid, which two sockets are live, and the last punch addr.
//! No ciphertext is opened here.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::limits::HandshakeWatch;

pub const DATA_QUEUE_CAP: usize = 32;
pub const CONTROL_QUEUE_CAP: usize = 256;
const PENDING_HOST_CAP: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plane {
    Control,
    Data,
}

impl Plane {
    pub fn as_str(self) -> &'static str {
        match self {
            Plane::Control => "control",
            Plane::Data => "data",
        }
    }
}

// lumzel:remote-link-03#m-claim lumzel:remote-link-03#a-claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Host,
    Peer,
}

impl Side {
    fn index(self) -> usize {
        match self {
            Side::Host => 0,
            Side::Peer => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Side::Host => Side::Peer,
            Side::Peer => Side::Host,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(u64);

impl ConnId {
    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RouteError {
    OwnedBy { node: String },
    Busy,
    NoPeer,
    Draining,
    BadId,
}

#[derive(Debug)]
pub enum Outbound {
    Binary(Vec<u8>),
    Text(String),
}

#[derive(Default)]
pub struct RouteMeta {
    owners: Mutex<HashMap<Key, String>>,
}

impl RouteMeta {
    pub fn new() -> Self {
        Self::default()
    }
}

type Key = (String, String);

struct Conn {
    key: Key,
    plane: Plane,
    side: Side,
    outbound: VecDeque<Outbound>,
    notify: Arc<Notify>,
}

struct Route {
    control: [Option<ConnId>; 2],
    data: [Option<ConnId>; 2],
    handshake_control: Option<Arc<HandshakeWatch>>,
    handshake_data: Option<Arc<HandshakeWatch>>,
    pending_control_for_host: VecDeque<Outbound>,
    pending_data_for_host: VecDeque<Outbound>,
    punch: Option<String>,
}

pub struct RouteTable {
    node_id: String,
    max_conns: usize,
    meta: Arc<RouteMeta>,
    draining: bool,
    live: usize,
    next_id: u64,
    routes: HashMap<Key, Route>,
    conns: HashMap<ConnId, Conn>,
}

impl RouteTable {
    pub fn new(node_id: impl Into<String>, max_conns: usize) -> Self {
        Self::with_meta(node_id, max_conns, Arc::new(RouteMeta::new()))
    }

    pub fn with_meta(node_id: impl Into<String>, max_conns: usize, meta: Arc<RouteMeta>) -> Self {
        Self {
            node_id: node_id.into(),
            max_conns,
            meta,
            draining: false,
            live: 0,
            next_id: 1,
            routes: HashMap::new(),
            conns: HashMap::new(),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn meta(&self) -> Arc<RouteMeta> {
        Arc::clone(&self.meta)
    }

    pub fn ready(&self) -> bool {
        self.admit().is_ok()
    }

    pub fn admit(&self) -> Result<(), RouteError> {
        if self.draining {
            return Err(RouteError::Draining);
        }
        if self.live >= self.max_conns {
            return Err(RouteError::Busy);
        }
        Ok(())
    }

    pub fn drain(&mut self) {
        self.draining = true;
    }

    pub fn reserve(&mut self) -> Result<(), RouteError> {
        self.admit()?;
        self.live += 1;
        Ok(())
    }

    pub fn unreserve(&mut self) {
        self.live = self.live.saturating_sub(1);
    }

    pub fn has_host(&self, host: &str, sid: &str, plane: Plane) -> bool {
        let Some(route) = self.routes.get(&(host.to_owned(), sid.to_owned())) else {
            return false;
        };
        let slots = match plane {
            Plane::Control => &route.control,
            Plane::Data => &route.data,
        };
        slots[Side::Host.index()].is_some()
    }

    // lumzel:remote-link-03#m-claim lumzel:remote-link-03#a-claim
    pub fn claim(
        &mut self,
        node_id: &str,
        host: &str,
        sid: &str,
        plane: Plane,
        side: Side,
    ) -> Result<(ConnId, Arc<Notify>), RouteError> {
        if self.draining {
            return Err(RouteError::Draining);
        }
        if !(1..=256).contains(&host.len()) || !(1..=256).contains(&sid.len()) {
            return Err(RouteError::BadId);
        }
        let key: Key = (host.to_owned(), sid.to_owned());
        {
            let mut owners = self.meta.owners.lock().expect("route meta");
            match owners.get(&key) {
                Some(owner) if owner != node_id => {
                    return Err(RouteError::OwnedBy {
                        node: owner.clone(),
                    });
                }
                Some(_) => {}
                None => {
                    owners.insert(key.clone(), node_id.to_owned());
                }
            }
        }
        let pos = side.index();
        {
            let route = self.routes.entry(key.clone()).or_insert_with(|| Route {
                control: [None, None],
                data: [None, None],
                handshake_control: None,
                handshake_data: None,
                pending_control_for_host: VecDeque::new(),
                pending_data_for_host: VecDeque::new(),
                punch: None,
            });
            let slots = match plane {
                Plane::Control => &route.control,
                Plane::Data => &route.data,
            };
            if slots[pos].is_some() {
                return Err(RouteError::Busy);
            }
        }
        let id = ConnId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let notify = Arc::new(Notify::new());
        let mut outbound = VecDeque::new();
        {
            let route = self.routes.get_mut(&key).expect("route just inserted");
            let (slots, pending) = match plane {
                Plane::Control => (&mut route.control, &mut route.pending_control_for_host),
                Plane::Data => (&mut route.data, &mut route.pending_data_for_host),
            };
            slots[pos] = Some(id);
            if side == Side::Host {
                outbound.append(pending);
            }
        }
        if !outbound.is_empty() {
            notify.notify_one();
        }
        self.conns.insert(
            id,
            Conn {
                key,
                plane,
                side,
                outbound,
                notify: Arc::clone(&notify),
            },
        );
        Ok((id, notify))
    }

    pub fn release(&mut self, id: ConnId) {
        let Some(conn) = self.conns.remove(&id) else {
            return;
        };
        conn.notify.notify_one();
        let mut peer_to_close = None;
        let mut empty = false;
        if let Some(route) = self.routes.get_mut(&conn.key) {
            let (slots, pending) = match conn.plane {
                Plane::Control => (&mut route.control, &mut route.pending_control_for_host),
                Plane::Data => (&mut route.data, &mut route.pending_data_for_host),
            };
            if slots[conn.side.index()] == Some(id) {
                slots[conn.side.index()] = None;
            }
            match conn.side {
                Side::Host => {
                    peer_to_close = slots[Side::Peer.index()].take();
                }
                Side::Peer => {
                    pending.clear();
                }
            }
            empty = route.control.iter().all(Option::is_none)
                && route.data.iter().all(Option::is_none)
                && route.punch.is_none();
        }
        if let Some(peer_id) = peer_to_close {
            if let Some(peer_conn) = self.conns.remove(&peer_id) {
                peer_conn.notify.notify_one();
            }
        }
        if empty {
            if let Some(route) = self.routes.get(&conn.key) {
                if route.control.iter().all(Option::is_none)
                    && route.data.iter().all(Option::is_none)
                {
                    self.routes.remove(&conn.key);
                }
            }
        }
    }

    pub fn close_route(&mut self, host: &str, sid: &str) {
        let key = (host.to_owned(), sid.to_owned());
        let Some(route) = self.routes.remove(&key) else {
            return;
        };
        for id in route.control.into_iter().chain(route.data).flatten() {
            if let Some(conn) = self.conns.remove(&id) {
                conn.notify.notify_one();
            }
        }
    }

    pub(crate) fn start_peer_handshake(&mut self, id: ConnId) -> Option<Arc<HandshakeWatch>> {
        let conn = self.conns.get(&id)?;
        if conn.side != Side::Peer {
            return None;
        }
        let route = self.routes.get_mut(&conn.key)?;
        let watch = HandshakeWatch::new();
        match conn.plane {
            Plane::Control => route.handshake_control = Some(Arc::clone(&watch)),
            Plane::Data => route.handshake_data = Some(Arc::clone(&watch)),
        }
        Some(watch)
    }

    pub(crate) fn satisfy_handshake(&mut self, id: ConnId) {
        let Some(conn) = self.conns.get(&id) else {
            return;
        };
        if conn.side != Side::Host {
            return;
        }
        let Some(route) = self.routes.get(&conn.key) else {
            return;
        };
        let watch = match conn.plane {
            Plane::Control => route.handshake_control.as_ref(),
            Plane::Data => route.handshake_data.as_ref(),
        };
        if let Some(watch) = watch {
            watch.satisfy();
        }
    }

    /// Copy `bytes` onto the peer's outbound queue. `NoPeer` stores nothing unless
    /// a Peer is waiting for the Host to dial in with its ticket.
    pub fn forward(&mut self, id: ConnId, bytes: &[u8]) -> Result<(), RouteError> {
        self.enqueue(id, Outbound::Binary(bytes.to_vec()))
    }

    /// Copy the `link_hello` text to the peer. It names a route and carries no key.
    pub fn forward_text(&mut self, id: ConnId, raw: &str) -> Result<(), RouteError> {
        self.enqueue(id, Outbound::Text(raw.to_owned()))
    }

    /// Remember `addr` on the route, then copy the raw text to the control peer.
    pub fn forward_punch(&mut self, id: ConnId, raw: &str, addr: &str) -> Result<(), RouteError> {
        let (key, plane) = {
            let conn = self.conns.get(&id).ok_or(RouteError::NoPeer)?;
            (conn.key.clone(), conn.plane)
        };
        if plane != Plane::Control {
            return Err(RouteError::NoPeer);
        }
        if let Some(route) = self.routes.get_mut(&key) {
            route.punch = Some(addr.to_owned());
        }
        self.enqueue(id, Outbound::Text(raw.to_owned()))
    }

    pub fn punch_addr(&self, host: &str, sid: &str) -> Option<String> {
        self.routes
            .get(&(host.to_owned(), sid.to_owned()))
            .and_then(|route| route.punch.clone())
    }

    pub fn connection_count(&self, host: &str, sid: &str, plane: Plane) -> usize {
        let Some(route) = self.routes.get(&(host.to_owned(), sid.to_owned())) else {
            return 0;
        };
        let slots = match plane {
            Plane::Control => &route.control,
            Plane::Data => &route.data,
        };
        slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn outbound_len(&self, id: ConnId) -> Option<usize> {
        self.conns.get(&id).map(|conn| conn.outbound.len())
    }

    /// `None` if `id` is gone. Empty if the peer has not been written yet.
    pub fn take_outbound(&mut self, id: ConnId) -> Option<Vec<Outbound>> {
        let conn = self.conns.get_mut(&id)?;
        Some(conn.outbound.drain(..).collect())
    }

    fn enqueue(&mut self, id: ConnId, msg: Outbound) -> Result<(), RouteError> {
        let (key, plane, side) = {
            let conn = self.conns.get(&id).ok_or(RouteError::NoPeer)?;
            (conn.key.clone(), conn.plane, conn.side)
        };
        let cap = match plane {
            Plane::Data => DATA_QUEUE_CAP,
            Plane::Control => CONTROL_QUEUE_CAP,
        };
        match self.peer(&key, plane, side) {
            Some(peer) => {
                let peer_conn = self.conns.get_mut(&peer).ok_or(RouteError::NoPeer)?;
                if peer_conn.outbound.len() >= cap {
                    return Err(RouteError::Busy);
                }
                peer_conn.outbound.push_back(msg);
                peer_conn.notify.notify_one();
                Ok(())
            }
            None if side == Side::Peer => {
                let route = self.routes.get_mut(&key).ok_or(RouteError::NoPeer)?;
                let pending = match plane {
                    Plane::Control => &mut route.pending_control_for_host,
                    Plane::Data => &mut route.pending_data_for_host,
                };
                if pending.len() >= PENDING_HOST_CAP {
                    return Err(RouteError::Busy);
                }
                pending.push_back(msg);
                Ok(())
            }
            None => Err(RouteError::NoPeer),
        }
    }

    fn peer(&self, key: &Key, plane: Plane, side: Side) -> Option<ConnId> {
        let route = self.routes.get(key)?;
        let slots = match plane {
            Plane::Control => &route.control,
            Plane::Data => &route.data,
        };
        slots[side.other().index()]
    }
}
