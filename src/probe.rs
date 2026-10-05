//! The client side: `probe`, `depth` and `threshold` measurements.
//! Every measurement is cross-checked against what the server really received.

use crate::ui::{self, colored, line, Row};
use crate::wire::*;
use clap::Args;
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::{sleep, timeout},
};

/// Where to send traffic and how to report.
#[derive(Args, Clone)]
pub struct Target {
    /// Address of the machine running `dpiprobe server`
    #[arg(long)]
    pub server: String,
    /// Server data port (TLS-like traffic)
    #[arg(long, default_value_t = 443)]
    pub port: u16,
    /// Server control port (ground-truth queries)
    #[arg(long, default_value_t = 9001)]
    pub ctl: u16,
    /// Seconds to wait for a reaction before calling it a silent drop
    #[arg(long, default_value_t = 3)]
    pub timeout: u64,
    /// Print JSON lines instead of the report (for scripts and tests)
    #[arg(long)]
    pub json: bool,
}

/// How the ClientHello is put on the wire.
#[derive(Args, Clone)]
pub struct Shape {
    /// Split the ClientHello into two TCP segments after N bytes (0 = off)
    #[arg(long, default_value_t = 0)]
    pub split: usize,
    /// Split the ClientHello in the middle of the SNI hostname
    #[arg(long)]
    pub split_sni: bool,
    /// Pause between the two segments, in ms
    #[arg(long, default_value_t = 50)]
    pub split_delay: u64,
    /// Send N padding packets before the ClientHello
    #[arg(long, default_value_t = 0)]
    pub pad: usize,
    /// Pause after each padding packet, in ms
    #[arg(long, default_value_t = 20)]
    pub pad_delay: u64,
}

impl Default for Shape {
    fn default() -> Self {
        Shape { split: 0, split_sni: false, split_delay: 50, pad: 0, pad_delay: 20 }
    }
}

impl Shape {
    fn describe(&self) -> String {
        let mut v = vec![];
        if self.split_sni {
            v.push("split inside SNI".to_string());
        } else if self.split > 0 {
            v.push(format!("split at byte {}", self.split));
        }
        if self.pad > 0 {
            v.push(format!("{} padding packets", self.pad));
        }
        if v.is_empty() { "plain".to_string() } else { v.join(", ") }
    }
}

/// One connection attempt, as seen by the client and by the server.
#[derive(Serialize)]
pub struct Attempt {
    pub sni: String,
    /// tls_alert (normal), rst, timeout, eof, data, or *_err:<kind>
    pub outcome: String,
    pub ms: u64,
    pub split: Option<usize>,
    pub pad: usize,
    pub id: String,
    /// Ground truth from the server (null if the control channel failed).
    pub server: Value,
}

impl Attempt {
    pub fn ok(&self) -> bool {
        self.outcome == "tls_alert"
    }
    fn seen(&self) -> Option<bool> {
        if self.server.is_null() { None } else { Some(self.server["seen"] == true) }
    }
    fn partial(&self) -> bool {
        self.seen() == Some(true) && self.server["obs"]["sni"].is_null()
    }
    fn server_label(&self) -> &'static str {
        match self.seen() {
            None => "control channel down",
            Some(false) => "never saw it",
            Some(true) if self.partial() => "saw part of it",
            Some(true) => "saw it",
        }
    }
}

fn io_outcome(stage: &str, e: std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | BrokenPipe | ConnectionAborted => "rst".to_string(),
        k => format!("{stage}_err:{k:?}"),
    }
}

async fn ground(t: &Target, id: &str) -> Value {
    let r = timeout(Duration::from_secs(3), async {
        let mut s = TcpStream::connect((t.server.as_str(), t.ctl)).await.ok()?;
        s.write_all(format!("{}\n", json!({"id": id})).as_bytes()).await.ok()?;
        let mut l = String::new();
        BufReader::new(s).read_line(&mut l).await.ok()?;
        serde_json::from_str::<Value>(&l).ok()
    })
    .await;
    match r {
        Ok(Some(v)) => v,
        _ => Value::Null,
    }
}

async fn connect(t: &Target) -> Result<TcpStream, String> {
    match timeout(Duration::from_secs(5), TcpStream::connect((t.server.as_str(), t.port))).await {
        Err(_) => Err("connect_timeout".to_string()),
        Ok(Err(e)) => Err(format!("connect_err:{:?}", e.kind())),
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
    }
}

async fn send_hello(s: &mut TcpStream, ch: &[u8], cut: Option<usize>, sh: &Shape) -> std::io::Result<()> {
    for _ in 0..sh.pad {
        s.write_all(&CCS).await?;
        s.flush().await?;
        sleep(Duration::from_millis(sh.pad_delay)).await;
    }
    match cut {
        Some(c) => {
            s.write_all(&ch[..c]).await?;
            s.flush().await?;
            sleep(Duration::from_millis(sh.split_delay)).await;
            s.write_all(&ch[c..]).await
        }
        None => s.write_all(ch).await,
    }
}

async fn read_reaction(s: &mut TcpStream, secs: u64) -> String {
    let mut buf = [0u8; 4096];
    match timeout(Duration::from_secs(secs), s.read(&mut buf)).await {
        Err(_) => "timeout".to_string(),
        Ok(Ok(0)) => "eof".to_string(),
        Ok(Ok(_)) => if buf[0] == 0x15 { "tls_alert".to_string() } else { "data".to_string() },
        Ok(Err(e)) => io_outcome("read", e),
    }
}

fn new_token() -> [u8; 32] {
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    random
}

pub async fn attempt(t: &Target, sni: &str, sh: &Shape) -> Attempt {
    let random = new_token();
    let id = hex(&random);
    let ch = build_client_hello(sni, &random);
    let cut = if sh.split_sni {
        sni_split_point(&ch, sni)
    } else if sh.split > 0 {
        Some(sh.split.min(ch.len() - 1))
    } else {
        None
    };
    let t0 = Instant::now();
    let outcome = match connect(t).await {
        Err(o) => o,
        Ok(mut s) => match send_hello(&mut s, &ch, cut, sh).await {
            Err(e) => io_outcome("send", e),
            Ok(()) => read_reaction(&mut s, t.timeout).await,
        },
    };
    let ms = t0.elapsed().as_millis() as u64;
    sleep(Duration::from_millis(300)).await;
    let server = ground(t, &id).await;
    Attempt { sni: sni.to_string(), outcome, ms, split: cut, pad: sh.pad, id, server }
}

fn outcome_color(a: &Attempt) -> &'static str {
    if a.ok() { ui::GREEN } else { ui::RED }
}

fn print_json(v: &Value) {
    println!("{}", v);
}

// ---------------------------------------------------------------- probe

fn probe_verdict(result: &str, seen: usize, partial: usize) -> String {
    if result == "tls_alert" {
        return "No interference: the ClientHello reached the server and was answered.".to_string();
    }
    let how = match result {
        "rst" => "RST injected",
        "timeout" => "silent drop",
        "eof" => "connection closed",
        _ => "mixed or unusual reaction",
    };
    if seen == 0 {
        format!("BLOCKED on the forward path ({how}): the server never saw the ClientHello.")
    } else if partial > 0 {
        format!("BLOCKED mid-handshake ({how}): the server got only part of the ClientHello,\nso the DPI reacted after the first segment was already delivered (likely stateful).")
    } else {
        format!("Failed although the server got the full ClientHello ({how}):\nreply path blocked, or RST injected after delivery.")
    }
}

pub async fn cmd_probe(t: Target, control_sni: String, test_sni: String, repeats: u32, sh: Shape) {
    let mut ctl = vec![];
    let mut tst = vec![];
    for _ in 0..repeats {
        ctl.push(attempt(&t, &control_sni, &sh).await);
    }
    for _ in 0..repeats {
        tst.push(attempt(&t, &test_sni, &sh).await);
    }
    let control_ok = ctl.iter().all(|a| a.ok());
    let outcomes: BTreeSet<&str> = tst.iter().map(|a| a.outcome.as_str()).collect();
    let seen = tst.iter().filter(|a| a.seen() == Some(true)).count();
    let partial = tst.iter().filter(|a| a.partial()).count();
    let (result, verdict) = if !control_ok {
        (
            "control_failed".to_string(),
            "Control SNI failed: the path itself is unhealthy, do not trust the test rows.".to_string(),
        )
    } else {
        let r = outcomes.iter().cloned().collect::<Vec<_>>().join(",");
        let v = probe_verdict(&r, seen, partial);
        (r, v)
    };

    if t.json {
        for (kind, set) in [("control", &ctl), ("test", &tst)] {
            for a in set {
                let mut v = serde_json::to_value(a).unwrap();
                v["kind"] = json!(kind);
                print_json(&v);
            }
        }
        print_json(&json!({"cmd": "probe", "result": result, "verdict": verdict}));
        return;
    }

    let w = control_sni.len().max(test_sni.len());
    let mut rows = vec![
        line(format!("target   {}:{}   repeats {}   timeout {}s", t.server, t.port, repeats, t.timeout)),
        line(format!("shape    {}", sh.describe())),
        Row::Sep,
        line(format!("{:<8} {:<w$} {:<12} {:>7}   {}", "KIND", "SNI", "REACTION", "TIME", "SERVER", w = w)),
    ];
    for (kind, set) in [("control", &ctl), ("test", &tst)] {
        for a in set {
            rows.push(colored(
                format!("{:<8} {:<w$} {:<12} {:>5}ms   {}", kind, a.sni, a.outcome, a.ms, a.server_label(), w = w),
                outcome_color(a),
            ));
        }
    }
    rows.push(Row::Sep);
    let color = if result == "tls_alert" { ui::GREEN } else if result == "control_failed" { ui::YELLOW } else { ui::RED };
    for l in verdict.lines() {
        rows.push(colored(l, color));
    }
    ui::boxed(&format!("probe: {} vs control {}", test_sni, control_sni), &rows);
}

// ---------------------------------------------------------------- depth

pub async fn cmd_depth(t: Target, sni: String, control_sni: String, max_pad: usize) {
    let c = attempt(&t, &control_sni, &Shape::default()).await;
    let mut tried: Vec<Attempt> = vec![];
    let mut result = String::new();
    if !c.ok() {
        result = "control_failed".to_string();
    } else {
        for p in 0..=max_pad {
            let a = attempt(&t, &sni, &Shape { pad: p, ..Shape::default() }).await;
            let passed = a.ok();
            tried.push(a);
            if passed {
                result = if p == 0 { "not_blocked".to_string() } else { format!("depth={}", p) };
                break;
            }
        }
        if result.is_empty() {
            result = format!("depth>{}", max_pad);
        }
    }
    let verdict = match result.as_str() {
        "control_failed" => "Control SNI failed: the path itself is unhealthy.".to_string(),
        "not_blocked" => format!("{} is not blocked at all: nothing to measure.", sni),
        r if r.starts_with("depth>") => format!(
            "Still blocked with {} padding packets: inspection depth is above {}.\nTry a higher --max-pad.",
            max_pad, max_pad
        ),
        r => {
            let n: usize = r[6..].parse().unwrap_or(0);
            format!(
                "The DPI inspects only the first {n} client packets.\nA ClientHello in packet {} or later is not examined.",
                n + 1
            )
        }
    };

    if t.json {
        let mut v = serde_json::to_value(&c).unwrap();
        v["kind"] = json!("control");
        print_json(&v);
        for a in &tried {
            let mut v = serde_json::to_value(a).unwrap();
            v["kind"] = json!("test");
            print_json(&v);
        }
        print_json(&json!({"cmd": "depth", "result": result, "verdict": verdict}));
        return;
    }

    let mut rows = vec![
        line(format!("target   {}:{}   max padding {}   timeout {}s", t.server, t.port, max_pad, t.timeout)),
        line(format!("control  {}  ->  {}", control_sni, c.outcome)),
        Row::Sep,
        line(format!("{:<9} {:<14} {:<12} {:>7}   {}", "PADDING", "CH IS PACKET", "REACTION", "TIME", "SERVER")),
    ];
    for a in &tried {
        rows.push(colored(
            format!("{:<9} {:<14} {:<12} {:>5}ms   {}", a.pad, a.pad + 1, a.outcome, a.ms, a.server_label()),
            outcome_color(a),
        ));
    }
    rows.push(Row::Sep);
    let color = if result.starts_with("depth=") { ui::GREEN } else { ui::YELLOW };
    for l in verdict.lines() {
        rows.push(colored(l, color));
    }
    rows.push(colored("note: padding packets are 6 bytes; a byte-limited DPI looks the same (see `threshold`).", ui::DIM));
    ui::boxed(&format!("depth: how many packets does the DPI inspect? ({})", sni), &rows);
}

// ------------------------------------------------------------ threshold

pub async fn cmd_threshold(t: Target, sni: String, max_kb: usize, chunk: usize) {
    let random = new_token();
    let id = hex(&random);
    let ch = build_client_hello(&sni, &random);
    let chunk = chunk.max(1);
    let total = max_kb * 1024;

    let mut sent = 0usize;
    let mut client_err: Option<String> = None;
    match connect(&t).await {
        Err(o) => {
            // Connection failed before any upload.
            report_threshold(&t, &sni, max_kb, chunk, &Value::Null, 0, ch.len(), 0, false, &o, &o);
        }
        Ok(mut s) => {
            let hello_outcome = match send_hello(&mut s, &ch, None, &Shape::default()).await {
                Err(e) => io_outcome("send", e),
                Ok(()) => read_reaction(&mut s, t.timeout).await,
            };
            if hello_outcome == "tls_alert" {
                let data = vec![0x41u8; chunk];
                while sent < total {
                    let n = chunk.min(total - sent);
                    match s.write_all(&data[..n]).await {
                        Ok(()) => sent += n,
                        Err(e) => {
                            client_err = Some(io_outcome("send", e));
                            break;
                        }
                    }
                    sleep(Duration::from_millis(2)).await;
                }
                sleep(Duration::from_millis(300)).await;
            }
            // Keep `s` alive until the ground-truth query is done.
            let g = ground(&t, &id).await;
            let server_rx = g["obs"]["bytes"].as_u64().unwrap_or(0) as usize;
            let server_rst = g["obs"]["rst"] == true;
            let expected = ch.len() + sent;
            let reaction = if hello_outcome != "tls_alert" {
                hello_outcome.clone()
            } else if server_rx >= expected {
                "none".to_string()
            } else if let Some(e) = &client_err {
                e.clone()
            } else {
                match timeout(Duration::from_secs(1), s.read(&mut [0u8; 64])).await {
                    Ok(Err(e)) => io_outcome("read", e),
                    _ => "drop".to_string(),
                }
            };
            report_threshold(&t, &sni, max_kb, chunk, &g, sent, ch.len(), server_rx, server_rst, &reaction, &hello_outcome);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn report_threshold(
    t: &Target, sni: &str, max_kb: usize, chunk: usize, g: &Value, sent: usize, hello: usize,
    server_rx: usize, server_rst: bool, reaction: &str, hello_outcome: &str,
) {
    let expected = hello + sent;
    let (result, verdict) = if hello_outcome != "tls_alert" || g.is_null() || g["seen"] != true {
        (
            "control_failed".to_string(),
            format!("The ClientHello for {sni} was disturbed before the upload ({hello_outcome}).\nPick an SNI the DPI does not match (it may be blocked)."),
        )
    } else if server_rx >= expected {
        (
            "cutoff=none".to_string(),
            format!("No cutoff: all {} bytes sent (up to {} KB) reached the server.", sent, max_kb),
        )
    } else {
        let est = server_rx + chunk / 2;
        let kb = (est as f64 / 1024.0).round() as usize;
        let how = if reaction == "rst" { "RST injected" } else { "silent drop" };
        (
            format!("cutoff={}KB", kb),
            format!(
                "Cutoff at about {} KB ({how}).\nThe server received {} bytes; the next packet (up to {} bytes) was lost.",
                kb, server_rx, chunk
            ),
        )
    };

    if t.json {
        print_json(&json!({
            "cmd": "threshold", "result": result, "verdict": verdict, "reaction": reaction,
            "sent": sent, "hello": hello, "server_rx": server_rx, "server_rst": server_rst, "chunk": chunk,
        }));
        return;
    }
    let color = if result == "cutoff=none" { ui::GREEN } else if result == "control_failed" { ui::YELLOW } else { ui::RED };
    let rows = vec![
        line(format!("target    {}:{}   chunk {} B   max {} KB", t.server, t.port, chunk, max_kb)),
        Row::Sep,
        line(format!("{:<18} {:>8} bytes  (ClientHello {} + upload {})", "client sent", expected, hello, sent)),
        line(format!("{:<18} {:>8} bytes", "server received", server_rx)),
        line(format!("{:<18} {}", "reaction", reaction)),
        line(format!("{:<18} {}", "server saw reset", if server_rst { "yes" } else { "no" })),
        Row::Sep,
    ];
    let mut rows = rows;
    for l in verdict.lines() {
        rows.push(colored(l, color));
    }
    ui::boxed(&format!("threshold: where does the upload get cut? ({})", sni), &rows);
}
