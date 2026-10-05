use clap::{Parser, Subcommand};
use rand::RngCore;
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
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

type State = Arc<Mutex<HashMap<String, Obs>>>;

#[derive(Clone, Serialize)]
struct Obs {
    peer: String,
    sni: Option<String>,
    bytes: usize,
    rst: bool,
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Server {
        #[arg(long, default_value = "0.0.0.0:443")]
        data: String,
        #[arg(long, default_value = "0.0.0.0:9001")]
        ctl: String,
    },
    Probe {
        #[arg(long)]
        server: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long, default_value_t = 9001)]
        ctl: u16,
        #[arg(long, default_value = "allowed.example")]
        control_sni: String,
        #[arg(long)]
        test_sni: String,
        #[arg(long, default_value_t = 3)]
        repeats: u32,
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn build_client_hello(sni: &str, random: &[u8; 32]) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sn = Vec::new();
    sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sn.push(0);
    sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn.extend_from_slice(name);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sn);
    ext.extend_from_slice(&[0, 0x0a, 0, 4, 0, 2, 0, 0x1d]); // groups: x25519
    ext.extend_from_slice(&[0, 0x0d, 0, 4, 0, 2, 8, 4]); // sigalgs
    ext.extend_from_slice(&[0, 0x2b, 0, 3, 2, 3, 4]); // TLS 1.3
    let mut body = vec![3, 3];
    body.extend_from_slice(random);
    body.push(0); // session id
    body.extend_from_slice(&[0, 6, 0x13, 1, 0x13, 2, 0xc0, 0x2f]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn parse_client_hello(b: &[u8]) -> Option<(String, Option<String>)> {
    if b.len() < 44 || b[0] != 0x16 || b[5] != 1 {
        return None;
    }
    let random = hex(&b[11..43]);
    let mut p = 43;
    p += 1 + *b.get(p)? as usize;
    p += 2 + u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 1 + *b.get(p)? as usize;
    let el = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2;
    let end = (p + el).min(b.len());
    let mut sni = None;
    while p + 4 <= end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        if t == 0 && l >= 5 && p + 4 + l <= end {
            let d = &b[p + 4..p + 4 + l];
            let nl = u16::from_be_bytes([d[3], d[4]]) as usize;
            if let Some(n) = d.get(5..5 + nl) {
                sni = Some(String::from_utf8_lossy(n).to_string());
            }
        }
        p += 4 + l;
    }
    Some((random, sni))
}

fn ch_complete(b: &[u8]) -> bool {
    b.len() >= 5 && b.len() >= 5 + u16::from_be_bytes([b[3], b[4]]) as usize
}

async fn data_conn(mut s: TcpStream, peer: SocketAddr, st: State) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut rst = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match timeout(left, s.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if ch_complete(&buf) {
                    break;
                }
            }
            Ok(Err(_)) => {
                rst = true;
                break;
            }
            Err(_) => break,
        }
    }
    if let Some((id, sni)) = parse_client_hello(&buf) {
        let obs = Obs { peer: peer.to_string(), sni, bytes: buf.len(), rst };
        println!("{}", json!({"ev": "seen", "id": id, "obs": obs}));
        st.lock().unwrap().insert(id, obs);
        let _ = s.write_all(&[0x15, 3, 3, 0, 2, 2, 40]).await; // alert handshake_failure
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

async fn server(data: String, ctl: String) {
    let st: State = Default::default();
    let d = TcpListener::bind(&data).await.expect("bind data");
    let c = TcpListener::bind(&ctl).await.expect("bind ctl");
    let st2 = st.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((s, _)) = c.accept().await {
                tokio::spawn(ctl_conn(s, st2.clone()));
            }
        }
    });
    eprintln!("listening data={data} ctl={ctl}");
    loop {
        if let Ok((s, p)) = d.accept().await {
            tokio::spawn(data_conn(s, p, st.clone()));
        }
    }
}

async fn ground(server: &str, ctl: u16, id: &str) -> serde_json::Value {
    let r = timeout(Duration::from_secs(3), async {
        let mut s = TcpStream::connect((server, ctl)).await.ok()?;
        s.write_all(format!("{}\n", json!({"id": id})).as_bytes()).await.ok()?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await.ok()?;
        serde_json::from_str::<serde_json::Value>(&line).ok()
    })
    .await;
    match r {
        Ok(Some(v)) => v,
        _ => json!(null),
    }
}

async fn attempt(server: &str, port: u16, ctl: u16, sni: &str, to: u64) -> serde_json::Value {
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    let id = hex(&random);
    let ch = build_client_hello(sni, &random);
    let t0 = Instant::now();
    let mut rx = 0usize;
    let outcome: String = match timeout(Duration::from_secs(5), TcpStream::connect((server, port))).await {
        Err(_) => "connect_timeout".into(),
        Ok(Err(e)) => format!("connect_err:{:?}", e.kind()),
        Ok(Ok(mut s)) => {
            if let Err(e) = s.write_all(&ch).await {
                format!("send_err:{:?}", e.kind())
            } else {
                let mut buf = [0u8; 4096];
                match timeout(Duration::from_secs(to), s.read(&mut buf)).await {
                    Err(_) => "timeout".into(),
                    Ok(Ok(0)) => "eof".into(),
                    Ok(Ok(n)) => {
                        rx = n;
                        if buf[0] == 0x15 { "tls_alert".into() } else { "data".into() }
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => "rst".into(),
                    Ok(Err(e)) => format!("read_err:{:?}", e.kind()),
                }
            }
        }
    };
    let ms = t0.elapsed().as_millis() as u64;
    sleep(Duration::from_millis(300)).await;
    let g = ground(server, ctl, &id).await;
    json!({"sni": sni, "outcome": outcome, "rx": rx, "ms": ms, "id": id, "server": g})
}

async fn probe(server: String, port: u16, ctl: u16, csni: String, tsni: String, n: u32, to: u64) {
    for (kind, sni) in [("control", &csni), ("test", &tsni)] {
        let (mut ok, mut seen) = (0, 0);
        for _ in 0..n {
            let mut r = attempt(&server, port, ctl, sni, to).await;
            r["kind"] = json!(kind);
            if r["outcome"] == "tls_alert" {
                ok += 1;
            }
            if r["server"]["seen"] == true {
                seen += 1;
            }
            println!("{}", r);
        }
        let verdict = if ok == n {
            "no_block"
        } else if seen == 0 {
            "forward_path_blocked (server never saw ClientHello)"
        } else {
            "server_saw_ch_but_client_failed (reply blocked or RST injected)"
        };
        println!("{}", json!({"summary": kind, "sni": sni, "ok": ok, "server_seen": seen, "of": n, "verdict": verdict}));
    }
}

#[tokio::main]
async fn main() {
    match Cli::parse().cmd {
        Cmd::Server { data, ctl } => server(data, ctl).await,
        Cmd::Probe { server, port, ctl, control_sni, test_sni, repeats, timeout } => {
            probe(server, port, ctl, control_sni, test_sni, repeats, timeout).await
        }
    }
}
