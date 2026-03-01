use std::{collections::HashMap, sync::Arc, time::Instant};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{Mutex, oneshot},
    time::{Duration, timeout},
};
use tracing::{debug, error, info, warn};

use crate::{
    error::{RcrocError, Result},
    protocol::message::{PlainMessage, recv_plain_message, send_plain_message},
};

const ROOM_TTL: Duration = Duration::from_secs(3 * 60 * 60);
const ROOM_CLEANUP_INTERVAL: Duration = Duration::from_secs(10 * 60);
const ROOM_WAIT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

struct WaitingRoom {
    created: Instant,
    tx: oneshot::Sender<TcpStream>,
}

type Rooms = Arc<Mutex<HashMap<String, WaitingRoom>>>;

pub async fn run_relay(listen_addr: &str, relay_password: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    run_relay_on_listener(listener, relay_password).await
}

pub async fn run_relay_on_listener(listener: TcpListener, relay_password: &str) -> Result<()> {
    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));

    let listen_addr = listener.local_addr()?;
    info!("relay listening on {listen_addr}");

    spawn_cleanup_task(rooms.clone());

    loop {
        let (stream, remote) = listener.accept().await?;
        let rooms = rooms.clone();
        let relay_password = relay_password.to_string();

        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, rooms, &relay_password).await {
                debug!("relay client {remote} closed with error: {err}");
            }
        });
    }
}

fn spawn_cleanup_task(rooms: Rooms) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ROOM_CLEANUP_INTERVAL);
        loop {
            ticker.tick().await;
            let mut guard = rooms.lock().await;
            let before = guard.len();
            guard.retain(|_, wait| wait.created.elapsed() <= ROOM_TTL);
            let removed = before.saturating_sub(guard.len());
            if removed > 0 {
                debug!("relay cleanup removed {removed} expired room(s)");
            }
        }
    });
}

async fn handle_client(mut stream: TcpStream, rooms: Rooms, relay_password: &str) -> Result<()> {
    let join = recv_plain_message(&mut stream).await?;
    let (room, client_password) = match join {
        PlainMessage::JoinRoom {
            room,
            relay_password,
        } => (room, relay_password),
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected JoinRoom, got {other:?}"
            )));
        }
    };

    if client_password != relay_password {
        let _ = send_plain_message(
            &mut stream,
            &PlainMessage::JoinError {
                message: "invalid relay password".to_string(),
            },
        )
        .await;
        return Err(RcrocError::Authentication);
    }

    let rx = {
        let mut guard = rooms.lock().await;
        if let Some(waiting) = guard.remove(&room) {
            return match waiting.tx.send(stream) {
                Ok(()) => {
                    info!("room matched: {room}");
                    Ok(())
                }
                Err(mut stream) => {
                    let message = "peer left before room matched".to_string();
                    let _ = send_plain_message(
                        &mut stream,
                        &PlainMessage::JoinError {
                            message: message.clone(),
                        },
                    )
                    .await;
                    Err(RcrocError::Protocol(message))
                }
            };
        }

        let (tx, receiver) = oneshot::channel();
        guard.insert(
            room.clone(),
            WaitingRoom {
                created: Instant::now(),
                tx,
            },
        );
        receiver
    };

    send_plain_message(&mut stream, &PlainMessage::JoinWaiting).await?;

    let mut rx = rx;
    let deadline = tokio::time::Instant::now() + ROOM_TTL;
    let mut peer_stream = loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            warn!("room timeout waiting for peer: {room}");
            remove_waiting_room(&rooms, &room).await;
            let _ = send_plain_message(
                &mut stream,
                &PlainMessage::JoinError {
                    message: "timed out waiting for peer".to_string(),
                },
            )
            .await;
            return Err(RcrocError::Protocol(
                "timed out waiting for peer".to_string(),
            ));
        }

        let wait_for = (deadline - now).min(ROOM_WAIT_KEEPALIVE_INTERVAL);
        match timeout(wait_for, &mut rx).await {
            Ok(Ok(peer)) => break peer,
            Ok(Err(_)) => {
                return Err(RcrocError::Protocol(
                    "room channel closed before peer arrived".to_string(),
                ));
            }
            Err(_) => {
                if let Err(err) = send_plain_message(&mut stream, &PlainMessage::JoinWaiting).await
                {
                    warn!("room {room} waiting keepalive failed: {err}");
                    remove_waiting_room(&rooms, &room).await;
                    return Err(err);
                }
            }
        }
    };

    send_plain_message(&mut peer_stream, &PlainMessage::JoinOk).await?;
    send_plain_message(&mut stream, &PlainMessage::JoinOk).await?;

    if let Err(err) = pipe(stream, peer_stream).await {
        error!("room {room} pipe error: {err}");
    }

    Ok(())
}

async fn pipe(mut a: TcpStream, mut b: TcpStream) -> Result<()> {
    let _ = copy_bidirectional(&mut a, &mut b).await?;
    Ok(())
}

async fn remove_waiting_room(rooms: &Rooms, room: &str) {
    let mut guard = rooms.lock().await;
    guard.remove(room);
}
