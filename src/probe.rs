//! The client side: `probe`, `depth` and `threshold` measurements.
//! Every measurement is cross-checked against what the server really received.

use crate::ui::{self, colored, line, Row};
use crate::quic;
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
    net::{TcpStream, UdpSocket},
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

/// Where to cut the ClientHello into two segments (used by `fingerprint`).
#[derive(Clone, Copy)]
pub enum Cut {
    /// After this many bytes of the ClientHello.
    At(usize),
    /// Right before the hostname.
    SniStart,
    /// In the middle of the hostname.
    SniMid,
    /// One byte before the end of the hostname.
    SniEnd,
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
    /// Pause between segments, in ms
    #[arg(long, default_value_t = 50)]
    pub split_delay: u64,
    /// Send the ClientHello in segments of N bytes (0 = off)
    #[arg(long, default_value_t = 0)]
    pub segment: usize,
    /// Send N padding packets before the ClientHello
    #[arg(long, default_value_t = 0)]
    pub pad: usize,
    /// Pause after each padding packet, in ms
    #[arg(long, default_value_t = 20)]
    pub pad_delay: u64,
    /// Put the SNI extension last in the ClientHello
    #[arg(long)]
    pub sni_last: bool,
    /// Add a padding extension of N bytes before the SNI (pushes the hostname deeper)
    #[arg(long, default_value_t = 0)]
    pub hello_pad: usize,
    #[arg(skip)]
    pub cut: Option<Cut>,
}

impl Default for Shape {
    fn default() -> Self {
        Shape {
            split: 0,
            split_sni: false,
            split_delay: 50,
            segment: 0,
            pad: 0,
            pad_delay: 20,
            sni_last: false,
            hello_pad: 0,
            cut: None,
        }
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
        if self.segment > 0 {
            v.push(format!("{}-byte segments", self.segment));
        }
        if self.pad > 0 {
            v.push(format!("{} padding packets", self.pad));
        }
        if self.sni_last {
            v.push("SNI extension last".to_string());
        }
        if self.hello_pad > 0 {
            v.push(format!("{}-byte padding extension", self.hello_pad));
        }
        if v.is_empty() { "plain".to_string() } else { v.join(", ") }
    }

    /// Where the ClientHello is cut into two segments, if anywhere.
    fn cut_point(&self, ch: &[u8], sni: &str) -> Option<usize> {
        let name_at = sni_offset(ch, sni);
        match self.cut {
            Some(Cut::At(n)) => Some(n.min(ch.len() - 1)),
            Some(Cut::SniStart) => name_at,
            Some(Cut::SniMid) => name_at.map(|p| p + sni.len() / 2),
            Some(Cut::SniEnd) => name_at.map(|p| p + sni.len().saturating_sub(1)),
            None if self.split_sni => name_at.map(|p| p + sni.len() / 2),
            None if self.split > 0 => Some(self.split.min(ch.len() - 1)),
            None => None,
        }
    }
}

/// One connection attempt, as seen by the client and by the server.
#[derive(Serialize)]
pub struct Attempt {
    /// "tcp", "quic" or "udp".
    pub proto: &'static str,
    pub sni: String,
    /// tls_alert (normal), rst, timeout, eof, data, or *_err:<kind>
    pub outcome: String,
    /// Milliseconds from connect to the first reaction (or to giving up).
    pub ms: u64,
    /// Milliseconds to the first response; None when nothing came back.
    pub first_response_ms: Option<u64>,
    pub client_rst: bool,
    pub split: Option<usize>,
    pub pad: usize,
    pub id: String,
    /// Did the server see this connection at all? None if the control channel failed.
    pub server_seen: Option<bool>,
    /// Bytes the server received on this connection.
    pub server_bytes: Option<u64>,
    /// Did the server's side of the connection end with a reset?
    pub server_rst: Option<bool>,
    /// Raw ground truth from the server (null if the control channel failed).
    pub server: Value,
}

impl Attempt {
    /// The normal, uninterfered reaction for this kind of attempt.
    pub fn ok(&self) -> bool {
        matches!(self.outcome.as_str(), "tls_alert" | "quic_reply" | "udp_echo")
    }
    pub fn seen(&self) -> Option<bool> {
        if self.server.is_null() { None } else { Some(self.server["seen"] == true) }
    }
    pub fn partial(&self) -> bool {
        self.proto == "tcp" && self.seen() == Some(true) && self.server["obs"]["sni"].is_null()
    }
    pub fn server_label(&self) -> &'static str {
        match self.seen() {
            None => "control channel down",
            Some(false) if self.proto == "tcp" => "no full CH",
            Some(false) => "not received",
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
    if sh.segment > 0 {
        for (i, piece) in ch.chunks(sh.segment).enumerate() {
            if i > 0 {
                sleep(Duration::from_millis(sh.split_delay)).await;
            }
            s.write_all(piece).await?;
            s.flush().await?;
        }
        return Ok(());
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
    let ch = build_client_hello(sni, &random, sh.sni_last, sh.hello_pad);
    let cut = sh.cut_point(&ch, sni);
    let t0 = Instant::now();
    let outcome = match connect(t).await {
        Err(o) => o,
        Ok(mut s) => match send_hello(&mut s, &ch, cut, sh).await {
            Err(e) => io_outcome("send", e),
            Ok(()) => read_reaction(&mut s, t.timeout).await,
        },
    };
    let ms = t0.elapsed().as_millis() as u64;
    finish(t, "tcp", sni, id, outcome, ms, cut, sh.pad).await
}

/// Ask the server what it saw, and assemble the evidence for one attempt.
async fn finish(t: &Target, proto: &'static str, sni: &str, id: String, outcome: String, ms: u64, split: Option<usize>, pad: usize) -> Attempt {
    sleep(Duration::from_millis(300)).await;
    let server = ground(t, &id).await;
    let no_answer = matches!(outcome.as_str(), "timeout" | "connect_timeout");
    let server_seen = if server.is_null() { None } else { Some(server["seen"] == true) };
    Attempt {
        proto,
        sni: sni.to_string(),
        client_rst: outcome == "rst",
        first_response_ms: if no_answer { None } else { Some(ms) },
        server_bytes: server["obs"]["bytes"].as_u64(),
        server_rst: server_seen.filter(|s| *s).map(|_| server["obs"]["rst"] == true),
        server_seen,
        outcome,
        ms,
        split,
        pad,
        id,
        server,
    }
}

// ------------------------------------------------------------ UDP / QUIC

/// Send one datagram and classify what comes back.
async fn udp_exchange(t: &Target, dgram: &[u8], is_quic: bool) -> (String, u64) {
    let t0 = Instant::now();
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return (format!("bind_err:{:?}", e.kind()), 0),
    };
    if let Err(e) = sock.connect((t.server.as_str(), t.port)).await {
        return (format!("connect_err:{:?}", e.kind()), 0);
    }
    if let Err(e) = sock.send(dgram).await {
        return (format!("send_err:{:?}", e.kind()), 0);
    }
    let mut buf = [0u8; 2048];
    let outcome = match timeout(Duration::from_secs(t.timeout), sock.recv(&mut buf)).await {
        Err(_) => "timeout".to_string(),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => "icmp_unreachable".to_string(),
        Ok(Err(e)) => format!("recv_err:{:?}", e.kind()),
        Ok(Ok(n)) => {
            let r = &buf[..n];
            if is_quic && quic::is_version_negotiation(r) {
                "quic_reply".to_string()
            } else if !is_quic && r.starts_with(quic::UDP_ECHO) {
                "udp_echo".to_string()
            } else {
                "data".to_string()
            }
        }
    };
    (outcome, t0.elapsed().as_millis() as u64)
}

/// One QUIC Initial carrying a ClientHello for `sni`.
pub async fn quic_attempt(t: &Target, sni: &str) -> Attempt {
    let random = new_token();
    let mut cid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut cid);
    let dg = quic::build_initial(sni, &random, &cid, &[0xaa, 0xbb, 0xcc, 0xdd]);
    let (outcome, ms) = udp_exchange(t, &dg, true).await;
    finish(t, "quic", sni, hex(&random), outcome, ms, None, 0).await
}

/// One plain, non-QUIC datagram: does UDP to this port work at all?
pub async fn udp_attempt(t: &Target) -> Attempt {
    let random = new_token();
    let mut dg = vec![0x40u8]; // short-header-looking first byte, not a QUIC long header
    dg.extend_from_slice(&random);
    dg.extend_from_slice(&[0u8; 31]);
    let (outcome, ms) = udp_exchange(t, &dg, false).await;
    finish(t, "udp", "(plain UDP)", hex(&random), outcome, ms, None, 0).await
}

/// Classify QUIC behaviour from three groups of attempts. The token is shared
/// by `quic` and `fingerprint`: udp=blocked | quic=blocked-all | quic=unaffected
/// | quic=sni-drop | quic=sni-icmp | quic=sni-other.
pub fn quic_class(raw: &[Attempt], ctl: &[Attempt], tst: &[Attempt]) -> (String, Vec<(String, &'static str)>) {
    let all_ok = |v: &[Attempt]| v.iter().all(|a| a.ok());
    let outs: BTreeSet<&str> = tst.iter().map(|a| a.outcome.as_str()).collect();
    let (token, lines): (String, Vec<(String, &'static str)>) = if !all_ok(raw) {
        (
            "udp=blocked".into(),
            vec![("Plain UDP to the server port gets no answer: UDP is blocked or unreachable, so QUIC cannot be judged.".into(), ui::YELLOW)],
        )
    } else if !all_ok(ctl) {
        (
            "quic=blocked-all".into(),
            vec![("UDP works but QUIC Initials with a control SNI fail too: QUIC is blocked regardless of the name (protocol-level).".into(), ui::RED)],
        )
    } else if all_ok(tst) {
        ("quic=unaffected".into(), vec![("QUIC is unaffected: an Initial with the test SNI gets an answer.".into(), ui::GREEN)])
    } else if outs.contains("timeout") && outs.len() == 1 {
        (
            "quic=sni-drop".into(),
            vec![("SNI-dependent QUIC interference: Initials with the test SNI are silently dropped, controls pass.".into(), ui::RED)],
        )
    } else if outs.contains("icmp_unreachable") && outs.len() == 1 {
        (
            "quic=sni-icmp".into(),
            vec![("SNI-dependent QUIC interference: Initials with the test SNI draw an ICMP unreachable, controls pass.".into(), ui::RED)],
        )
    } else {
        (
            "quic=sni-other".into(),
            vec![(format!("SNI-dependent QUIC interference with an unusual reaction ({}).", outs.iter().cloned().collect::<Vec<_>>().join("/")), ui::RED)],
        )
    };
    (token, lines)
}

pub async fn cmd_quic(t: Target, control_sni: String, test_sni: String, repeats: u32) {
    let mut raw = vec![];
    let mut ctl = vec![];
    let mut tst = vec![];
    for _ in 0..repeats {
        raw.push(udp_attempt(&t).await);
    }
    for _ in 0..repeats {
        ctl.push(quic_attempt(&t, &control_sni).await);
    }
    for _ in 0..repeats {
        tst.push(quic_attempt(&t, &test_sni).await);
    }
    let (result, lines) = quic_class(&raw, &ctl, &tst);
    let verdict = lines.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>().join(" ");

    if t.json {
        for (kind, set) in [("udp-raw", &raw), ("control", &ctl), ("test", &tst)] {
            for a in set {
                let mut v = serde_json::to_value(a).unwrap();
                v["kind"] = json!(kind);
                print_json(&v);
            }
        }
        print_json(&json!({"cmd": "quic", "result": result, "verdict": verdict}));
        return;
    }
    let w = control_sni.len().max(test_sni.len()).max("(plain UDP)".len());
    let mut rows = vec![
        line(format!("target   {}:{}/udp   repeats {}   timeout {}s", t.server, t.port, repeats, t.timeout)),
        Row::Sep,
        line(format!("{:<8} {:<w$} {:<17} {:>7}   {}", "KIND", "SNI", "REACTION", "TIME", "SERVER", w = w)),
    ];
    for (kind, set) in [("udp-raw", &raw), ("control", &ctl), ("test", &tst)] {
        for a in set {
            rows.push(colored(
                format!("{:<8} {:<w$} {:<17} {:>5}ms   {}", kind, a.sni, a.outcome, a.ms, a.server_label(), w = w),
                outcome_color(a),
            ));
        }
    }
    rows.push(Row::Sep);
    for (l, c) in lines {
        rows.push(colored(l, c));
    }
    rows.push(colored("note: compatible with DPI-style QUIC filtering; it does not identify a product.", ui::DIM));
    ui::boxed(&format!("quic: {} vs control {}", test_sni, control_sni), &rows);
}

fn outcome_color(a: &Attempt) -> &'static str {
    if a.ok() { ui::GREEN } else { ui::RED }
}

fn print_json(v: &Value) {
    println!("{}", v);
}

// ---------------------------------------------------------------- probe

/// Aggregated evidence over the test attempts.
struct Evidence {
    attempts: usize,
    interfered: usize,
    saw_full: usize,
    saw_partial: usize,
    never_saw: usize,
    client_rst: usize,
    server_rst: usize,
    median_ms: Option<u64>,
}

fn evidence(tst: &[Attempt]) -> Evidence {
    let mut ms: Vec<u64> = tst.iter().filter_map(|a| a.first_response_ms).collect();
    ms.sort_unstable();
    Evidence {
        attempts: tst.len(),
        interfered: tst.iter().filter(|a| !a.ok()).count(),
        saw_full: tst.iter().filter(|a| a.seen() == Some(true) && !a.partial()).count(),
        saw_partial: tst.iter().filter(|a| a.partial()).count(),
        never_saw: tst.iter().filter(|a| a.seen() == Some(false)).count(),
        client_rst: tst.iter().filter(|a| a.client_rst).count(),
        server_rst: tst.iter().filter(|a| a.server_rst == Some(true)).count(),
        median_ms: if ms.is_empty() { None } else { Some(ms[ms.len() / 2]) },
    }
}

/// Verdict lines as (text, colour). Wording is deliberately cautious: the
/// observed behaviour is compatible with DPI, it does not prove DPI.
fn probe_verdict(result: &str, e: &Evidence, control_clean: usize, control_n: usize) -> Vec<(String, &'static str)> {
    if result == "tls_alert" {
        return vec![(
            format!("No interference observed: the ClientHello reached the server and was answered {}/{}.", e.attempts, e.attempts),
            ui::GREEN,
        )];
    }
    let how = match result {
        "rst" => "RST",
        "timeout" => "silent drop",
        "eof" => "connection closed",
        _ => "mixed or unusual reaction",
    };
    let n = e.attempts;
    let reaction = match e.median_ms {
        Some(ms) => format!("median reaction {}ms", ms),
        None => "no reaction (timeout)".to_string(),
    };
    let meaning = if e.never_saw == n {
        format!("Forward path affected ({how}): the ClientHello never reached the server.")
    } else if e.saw_partial > 0 {
        "Cut mid-handshake: the first segment was delivered, so the middlebox tracks the stream across segments (likely stateful).".to_string()
    } else {
        format!("The server got the full ClientHello but the client still failed ({how}): reply path affected, or a reset after delivery.")
    };
    vec![
        (format!("SNI-dependent interference: {}/{} attempts (control clean {}/{}).", e.interfered, n, control_clean, control_n), ui::RED),
        (
            format!(
                "Evidence: server saw ClientHello {}/{} (partial {}), RST at client {}/{}, RST at server {}/{}, {}.",
                e.saw_full, n, e.saw_partial, e.client_rst, n, e.server_rst, n, reaction
            ),
            ui::RED,
        ),
        (meaning, ui::RED),
        ("note: compatible with DPI; one behaviour cannot prove that DPI is present.".to_string(), ui::DIM),
    ]
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
    let control_clean = ctl.iter().filter(|a| a.ok()).count();
    let control_ok = control_clean == ctl.len();
    let ev = evidence(&tst);
    let outcomes: BTreeSet<&str> = tst.iter().map(|a| a.outcome.as_str()).collect();
    let (result, lines) = if !control_ok {
        (
            "control_failed".to_string(),
            vec![("Control SNI failed: the path itself is unhealthy, do not trust the test rows.".to_string(), ui::YELLOW)],
        )
    } else {
        let r = outcomes.iter().cloned().collect::<Vec<_>>().join(",");
        let l = probe_verdict(&r, &ev, control_clean, ctl.len());
        (r, l)
    };
    let verdict = lines.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>().join(" ");

    if t.json {
        for (kind, set) in [("control", &ctl), ("test", &tst)] {
            for a in set {
                let mut v = serde_json::to_value(a).unwrap();
                v["kind"] = json!(kind);
                print_json(&v);
            }
        }
        print_json(&json!({
            "cmd": "probe", "result": result, "verdict": verdict,
            "features": {
                "attempts": ev.attempts, "interfered": ev.interfered,
                "server_saw_full": ev.saw_full, "server_saw_partial": ev.saw_partial, "server_never_saw": ev.never_saw,
                "client_rst": ev.client_rst, "server_rst": ev.server_rst,
                "median_response_ms": ev.median_ms, "timeout_ms": t.timeout * 1000,
                "control_clean": control_clean, "control_attempts": ctl.len(),
            }
        }));
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
    for (l, c) in lines {
        rows.push(colored(l, c));
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
                "The middlebox inspects only the first {n} client packets.\nA ClientHello in packet {} or later is not examined.",
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
    rows.push(colored("note: padding packets are 6 bytes; a byte-limited middlebox looks the same (see `threshold`).", ui::DIM));
    ui::boxed(&format!("depth: how many packets does the middlebox inspect? ({})", sni), &rows);
}

// ------------------------------------------------------------ threshold

pub async fn cmd_threshold(t: Target, sni: String, max_kb: usize, chunk: usize) {
    let random = new_token();
    let id = hex(&random);
    let ch = build_client_hello(&sni, &random, false, 0);
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
            format!("The ClientHello for {sni} was disturbed before the upload ({hello_outcome}).\nPick an SNI the middlebox does not match (it may be blocked)."),
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
