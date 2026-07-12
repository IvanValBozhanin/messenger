use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use crate::auth::AuthUser;
use crate::AppState;

type Tx = mpsc::UnboundedSender<Message>;

struct Client {
    id: u64,
    token_hash: String,
    tx: Tx,
}

/// In-memory registry of connected sockets, keyed by user id. One user can
/// hold several sockets (laptop + phone). Single-instance only by design —
/// fine at this scale, revisit if the app ever runs more than one replica.
#[derive(Clone, Default)]
pub struct Hub {
    clients: Arc<Mutex<HashMap<i64, Vec<Client>>>>,
    next_id: Arc<AtomicU64>,
}

impl Hub {
    fn register(&self, user_id: i64, token_hash: String, tx: Tx) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.clients
            .lock()
            .unwrap()
            .entry(user_id)
            .or_default()
            .push(Client { id, token_hash, tx });
        id
    }

    fn unregister(&self, user_id: i64, client_id: u64) {
        let mut clients = self.clients.lock().unwrap();
        if let Some(list) = clients.get_mut(&user_id) {
            list.retain(|c| c.id != client_id);
            if list.is_empty() {
                clients.remove(&user_id);
            }
        }
    }

    /// Push a JSON event to every socket of every listed user.
    pub fn send_to_users(&self, user_ids: &[i64], event: &str) {
        let clients = self.clients.lock().unwrap();
        for uid in user_ids {
            if let Some(list) = clients.get(uid) {
                for client in list {
                    let _ = client.tx.send(Message::Text(event.to_string().into()));
                }
            }
        }
    }

    /// Kick every socket belonging to one session (used on revoke/logout):
    /// sends a session_revoked event, then closes by dropping the sender.
    pub fn kick_session(&self, token_hash: &str) {
        let mut clients = self.clients.lock().unwrap();
        for list in clients.values_mut() {
            list.retain(|c| {
                if c.token_hash == token_hash {
                    let _ = c
                        .tx
                        .send(Message::Text(r#"{"type":"session_revoked"}"#.to_string().into()));
                    let _ = c.tx.send(Message::Close(None));
                    false
                } else {
                    true
                }
            });
        }
        clients.retain(|_, list| !list.is_empty());
    }
}

pub async fn ws_handler(
    State(state): State<AppState>,
    user: AuthUser,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, user))
}

async fn handle_socket(socket: WebSocket, state: AppState, user: AuthUser) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let client_id = state.hub.register(user.user_id, user.token_hash.clone(), tx);

    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let closing = matches!(msg, Message::Close(_));
            if sink.send(msg).await.is_err() || closing {
                break;
            }
        }
    });

    // Incoming frames are ignored (clients send via REST); the read loop only
    // detects disconnects and answers pings, which axum does automatically.
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
    state.hub.unregister(user.user_id, client_id);
}
