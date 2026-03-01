use std::net::ToSocketAddrs;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_socks::tcp::Socks5Stream;
use url::Url;

use crate::error::{RcrocError, Result};

pub async fn connect_target(target: &str, proxy: Option<&str>) -> Result<TcpStream> {
    match proxy {
        None => Ok(TcpStream::connect(target).await?),
        Some(proxy_url) => connect_via_proxy(target, proxy_url).await,
    }
}

async fn connect_via_proxy(target: &str, proxy_url: &str) -> Result<TcpStream> {
    let url = Url::parse(proxy_url)
        .map_err(|e| RcrocError::Protocol(format!("invalid proxy url: {proxy_url}: {e}")))?;

    let host = url
        .host_str()
        .ok_or_else(|| RcrocError::Protocol("proxy url missing host".to_string()))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        RcrocError::Protocol(format!(
            "proxy url missing port and no default: {proxy_url}"
        ))
    })?;
    let proxy_addr = format!("{host}:{port}");

    match url.scheme() {
        "socks5" | "socks5h" => {
            let stream = Socks5Stream::connect(proxy_addr.as_str(), target)
                .await
                .map_err(|e| RcrocError::Protocol(format!("socks5 connect failed: {e}")))?;
            Ok(stream.into_inner())
        }
        "http" => http_connect_tunnel(&proxy_addr, target).await,
        scheme => Err(RcrocError::Protocol(format!(
            "unsupported proxy scheme: {scheme}"
        ))),
    }
}

async fn http_connect_tunnel(proxy_addr: &str, target: &str) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    let mut buf = vec![0u8; 8192];
    let mut used = 0usize;
    loop {
        if used == buf.len() {
            return Err(RcrocError::Protocol(
                "http proxy response headers too large".to_string(),
            ));
        }

        let n = stream.read(&mut buf[used..]).await?;
        if n == 0 {
            return Err(RcrocError::Protocol(
                "http proxy closed before CONNECT response".to_string(),
            ));
        }
        used += n;

        if let Some(end) = find_headers_end(&buf[..used]) {
            let head = String::from_utf8_lossy(&buf[..end]);
            let first_line = head.lines().next().unwrap_or_default();
            if !first_line.contains(" 200 ") {
                return Err(RcrocError::Protocol(format!(
                    "http proxy CONNECT failed: {first_line}"
                )));
            }
            return Ok(stream);
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

pub fn local_ipv4_for_advertise() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    if addr.ip().is_ipv4() {
        Some(addr.ip().to_string())
    } else {
        None
    }
}

pub fn normalize_advertise_addr(relay_addr: &str) -> String {
    let mut parts = relay_addr.rsplitn(2, ':').collect::<Vec<_>>();
    parts.reverse();
    if parts.len() != 2 {
        return relay_addr.to_string();
    }

    let host = parts[0];
    let port = parts[1];

    let host_is_local = matches!(host, "127.0.0.1" | "0.0.0.0" | "localhost");
    if !host_is_local {
        return relay_addr.to_string();
    }

    if let Some(local_ip) = local_ipv4_for_advertise() {
        let candidate = format!("{local_ip}:{port}");
        if candidate.to_socket_addrs().is_ok() {
            return candidate;
        }
    }

    relay_addr.to_string()
}
