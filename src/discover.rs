use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    sync::watch,
    time::{Duration, Instant, sleep},
};
use tracing::{debug, info};

use crate::{
    error::{RcrocError, Result},
    models::DISCOVERY_ADDR,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscoveryMessage {
    room: String,
    relay_addr: String,
}

pub fn spawn_advertiser(
    room: String,
    relay_addr: String,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        if let Err(err) = advertise_loop(&room, &relay_addr, &mut shutdown_rx).await {
            debug!("lan advertise stopped: {err}");
        }
    });

    (shutdown_tx, handle)
}

async fn advertise_loop(
    room: &str,
    relay_addr: &str,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_ttl_v4(1)?;

    let msg = DiscoveryMessage {
        room: room.to_string(),
        relay_addr: relay_addr.to_string(),
    };
    let payload = serde_json::to_vec(&msg)?;

    info!("lan discovery advertise on {DISCOVERY_ADDR}");

    loop {
        if *shutdown.borrow() {
            break;
        }

        let _ = socket.send_to(&payload, DISCOVERY_ADDR).await;

        tokio::select! {
            _ = sleep(Duration::from_millis(500)) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

pub async fn discover_relay(room: &str, timeout: Duration) -> Result<Option<String>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 35678)).await?;
    socket.join_multicast_v4(Ipv4Addr::new(239, 255, 255, 250), Ipv4Addr::UNSPECIFIED)?;
    socket.set_multicast_loop_v4(true)?;

    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 2048];

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }

        let remain = deadline - now;
        let recv = tokio::time::timeout(remain, socket.recv_from(&mut buf)).await;
        let (n, _) = match recv {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => return Err(RcrocError::Io(err)),
            Err(_) => return Ok(None),
        };

        let parsed = serde_json::from_slice::<DiscoveryMessage>(&buf[..n]);
        let msg = match parsed {
            Ok(v) => v,
            Err(_) => continue,
        };

        if msg.room == room {
            info!("lan discovery found relay {}", msg.relay_addr);
            return Ok(Some(msg.relay_addr));
        }
    }
}
