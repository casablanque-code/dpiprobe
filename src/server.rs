//! The ground-truth side: records what actually reached this host.
//!
//! Data port: accepts connections, parses the ClientHello, replies with a TLS
//! alert, then keeps counting bytes so uploads can be accounted for.
//! Control port: the probe asks "what did you see for token X?" (JSON line).

use crate::quic;
use crate::wire::*;
use serde::Serialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

pub type State = Arc<Mutex<HashMap<String, Obs>>>;

/// What the server observed for one connection.
#[derive(Clone, Serialize)]
pub struct Obs {
    /// "tcp", "udp-quic" (QUIC Initial) or "udp" (plain datagram).
    pub proto: &'static str,
    pub peer: String,
    /// SNI, or None when the ClientHello arrived only partially.
    pub sni: Option<String>,
    /// Total bytes received on the connection (padding + ClientHello + uploads).
    pub bytes: usize,
    /// Number of padding records received before the ClientHello.
    pub pad: usize,
    /// True if the connection ended with a reset instead of a clean close.
    pub rst: bool,
}

async fn data_conn(mut s: TcpStream, peer: SocketAddr, st: State) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut rst = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, s.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if ch_complete(skip_pad(&buf)) {
                    break;
                }
            }
            Ok(Err(_)) => {
                rst = true;
                break;
            }
        }
    }
    let rec = skip_pad(&buf);
    let Some(h) = parse_client_hello(rec) else { return };
    let pad = (buf.len() - rec.len()) / CCS.len();
    let obs = Obs { proto: "tcp", peer: peer.to_string(), sni: h.sni.clone(), bytes: buf.len(), pad, rst };
    println!("{}", json!({"ev": "seen", "id": h.id, "obs": obs}));
    st.lock().unwrap().insert(h.id.clone(), obs);
    let _ = s.write_all(&ALERT).await;
    // Keep draining so that uploaded bytes are counted until the flow goes idle.
    loop {
        match timeout(Duration::from_secs(2), s.read(&mut tmp)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                if let Some(o) = st.lock().unwrap().get_mut(&h.id) {
                    o.bytes += n;
                }
            }
            Ok(Err(_)) => {
                if let Some(o) = st.lock().unwrap().get_mut(&h.id) {
                    o.rst = true;
                }
                break;
            }
        }
    }
}

/// UDP side: answers QUIC Initials with Version Negotiation and anything else
/// with an echo marker, recording what arrived under the same kind of token.
async fn udp_loop(sock: UdpSocket, st: State) {
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let dg = &buf[..n];
        if let Some(init) = quic::parse_initial(dg) {
            if let Some(h) = quic::hello_of(&init) {
                let obs = Obs { proto: "udp-quic", peer: peer.to_string(), sni: h.sni.clone(), bytes: n, pad: 0, rst: false };
                println!("{}", json!({"ev": "seen", "id": h.id, "obs": obs}));
                st.lock().unwrap().insert(h.id, obs);
                let _ = sock.send_to(&quic::version_negotiation(&init.dcid, &init.scid), peer).await;
            }
        } else if n >= 33 {
            let id = hex(&dg[1..33]);
            let obs = Obs { proto: "udp", peer: peer.to_string(), sni: None, bytes: n, pad: 0, rst: false };
            println!("{}", json!({"ev": "seen", "id": id, "obs": obs}));
            st.lock().unwrap().insert(id, obs);
            let _ = sock.send_to(quic::UDP_ECHO, peer).await;
        }
    }
}

async fn ctl_conn(s: TcpStream, st: State) {
    let (r, mut w) = s.into_split();
    let mut line = String::new();
    if BufReader::new(r).read_line(&mut line).await.is_ok() {
        let req: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
        let id = req["id"].as_str().unwrap_or("").to_string();
        let obs = st.lock().unwrap().get(&id).cloned();
        let resp = json!({"id": id, "seen": obs.is_some(), "obs": obs});
        let _ = w.write_all(format!("{}\n", resp).as_bytes()).await;
    }
}

/// Addresses to bind for `addr`. A wildcard IPv6 address ("[::]:PORT") also tries the
/// IPv4 wildcard: on a dual-stack host the second bind simply fails and is ignored,
/// on a v6-only host it keeps IPv4 working.
fn variants(addr: &str) -> Vec<String> {
    match addr.strip_prefix("[::]:") {
        Some(port) => vec![addr.to_string(), format!("0.0.0.0:{port}")],
        None => vec![addr.to_string()],
    }
}

async fn bind_tcp(addr: &str) -> Vec<TcpListener> {
    let mut out = vec![];
    let mut last = None;
    for a in variants(addr) {
        match TcpListener::bind(&a).await {
            Ok(l) => out.push(l),
            Err(e) => last = Some(e),
        }
    }
    if out.is_empty() {
        fatal(addr, last.expect("an error"));
    }
    out
}

pub async fn run(data: String, ctl: String) {
    let st: State = Default::default();
    for c in bind_tcp(&ctl).await {
        let st2 = st.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((s, _)) = c.accept().await {
                    tokio::spawn(ctl_conn(s, st2.clone()));
                }
            }
        });
    }
    let mut udp = 0;
    for a in variants(&data) {
        if let Ok(sock) = UdpSocket::bind(&a).await {
            udp += 1;
            tokio::spawn(udp_loop(sock, st.clone()));
        }
    }
    if udp == 0 {
        eprintln!("warning: UDP {data} unavailable; QUIC/UDP measurements will not work");
    }
    let mut accepts = vec![];
    for d in bind_tcp(&data).await {
        let st2 = st.clone();
        accepts.push(tokio::spawn(async move {
            loop {
                if let Ok((s, p)) = d.accept().await {
                    tokio::spawn(data_conn(s, p, st2.clone()));
                }
            }
        }));
    }
    eprintln!("listening data={data} ctl={ctl}");
    for h in accepts {
        let _ = h.await;
    }
}

fn fatal(addr: &str, e: std::io::Error) -> ! {
    eprintln!("error: cannot bind {addr}: {e}");
    std::process::exit(1);
}
