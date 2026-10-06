//! `fingerprint`: run a matrix of ClientHello perturbations against a test SNI
//! (each one cross-checked with control SNIs) and derive a behaviour profile of
//! the middlebox in the path.
//!
//! The profile describes what was observed; it is compatible with, but cannot
//! prove, a particular kind of device.

use crate::probe::{attempt, Attempt, Cut, Shape, Target};
use crate::ui::{self, colored, line, Row};
use serde_json::json;
use std::collections::BTreeSet;

struct Perturbation {
    key: &'static str,
    desc: &'static str,
    shape: Shape,
    sni: fn(&str) -> String,
}

fn same(s: &str) -> String {
    s.to_string()
}
fn upper(s: &str) -> String {
    s.to_uppercase()
}
fn dotted(s: &str) -> String {
    format!("{}.", s)
}

fn matrix() -> Vec<Perturbation> {
    let p = |key, desc, shape: Shape| Perturbation { key, desc, shape, sni: same };
    let cut = |c| Shape { cut: Some(c), ..Shape::default() };
    let pad = |n| Shape { pad: n, ..Shape::default() };
    vec![
        p("plain", "unmodified ClientHello", Shape::default()),
        p("split-1", "cut after the first byte", cut(Cut::At(1))),
        p("split-5", "cut after the TLS record header", cut(Cut::At(5))),
        p("split-sni-start", "cut right before the hostname", cut(Cut::SniStart)),
        p("split-sni-mid", "cut in the middle of the hostname", cut(Cut::SniMid)),
        p("split-sni-end", "cut one byte before the hostname end", cut(Cut::SniEnd)),
        p("seg-8", "8-byte segments", Shape { segment: 8, ..Shape::default() }),
        p("pad-1", "1 padding packet first", pad(1)),
        p("pad-2", "2 padding packets first", pad(2)),
        p("pad-3", "3 padding packets first", pad(3)),
        p("pad-4", "4 padding packets first", pad(4)),
        p("sni-last", "SNI extension moved last", Shape { sni_last: true, ..Shape::default() }),
        p("big-hello", "700-byte padding before the SNI", Shape { hello_pad: 700, ..Shape::default() }),
        Perturbation { key: "sni-upper", desc: "hostname in upper case", shape: Shape::default(), sni: upper },
        Perturbation { key: "sni-dot", desc: "hostname with a trailing dot", shape: Shape::default(), sni: dotted },
    ]
}

struct Cell {
    key: &'static str,
    desc: &'static str,
    tests: Vec<Attempt>,
    ctl: Vec<Attempt>,
}

impl Cell {
    fn ctl_clean(&self) -> usize {
        self.ctl.iter().filter(|a| a.ok()).count()
    }
    /// Controls were clean, so the test result means something.
    fn valid(&self) -> bool {
        self.ctl_clean() == self.ctl.len()
    }
    fn interfered(&self) -> usize {
        self.tests.iter().filter(|a| !a.ok()).count()
    }
    fn blocked(&self) -> bool {
        self.interfered() * 2 >= self.tests.len()
    }
    fn mixed(&self) -> bool {
        self.interfered() > 0 && self.interfered() < self.tests.len()
    }
    fn outcomes(&self) -> String {
        let set: BTreeSet<String> = self
            .tests
            .iter()
            .map(|a| if a.ok() { "pass".to_string() } else { a.outcome.clone() })
            .collect();
        set.into_iter().collect::<Vec<_>>().join("/")
    }
    fn server(&self) -> &'static str {
        let t = &self.tests;
        if t.iter().any(|a| a.seen().is_none()) {
            "ctl down"
        } else if t.iter().all(|a| a.seen() == Some(false)) {
            "never saw"
        } else if t.iter().all(|a| a.seen() == Some(true) && !a.partial()) {
            "saw it"
        } else if t.iter().any(|a| a.partial()) {
            "saw part"
        } else {
            "mixed"
        }
    }
}

struct Trait {
    token: String,
    label: String,
    text: String,
}

fn word(blocked: bool) -> &'static str {
    if blocked { "blocked" } else { "passes" }
}

fn derive(cells: &[Cell]) -> Vec<Trait> {
    let get = |k: &str| cells.iter().find(|c| c.key == k && c.valid());
    let tr = |token: &str, label: &str, text: String| Trait { token: token.to_string(), label: label.to_string(), text };
    let mut v = vec![];

    // Reaction type, from the plain ClientHello.
    let plain = get("plain").expect("plain cell");
    let outs: BTreeSet<&str> = plain.tests.iter().map(|a| a.outcome.as_str()).collect();
    if outs.contains("rst") {
        v.push(tr("rst", "RST injection", "Reaction: RST injected toward the client.".into()));
    } else if outs.len() == 1 && outs.contains("timeout") {
        v.push(tr("drop", "silent drop", "Reaction: silent drop, no reply of any kind.".into()));
    } else {
        let o = outs.iter().cloned().collect::<Vec<_>>().join("/");
        v.push(tr("other", "other reaction", format!("Reaction: {} (neither a clean RST nor a clean drop).", o)));
    }

    // Reassembly: splits that cut the hostname itself.
    let inside: Vec<(&str, bool)> = ["split-sni-mid", "split-sni-end"]
        .iter()
        .filter_map(|k| get(k).map(|c| (*k, c.blocked())))
        .collect();
    let ev = inside.iter().map(|(k, b)| format!("{} {}", k, word(*b))).collect::<Vec<_>>().join(", ");
    if inside.is_empty() {
        v.push(tr("reassembly-unknown", "reassembly unknown", "Reassembly: inconclusive (control failed on the split cells).".into()));
    } else if inside.iter().all(|(_, b)| *b) {
        v.push(tr("stateful", "reassembles segments", format!("Reassembles TCP segments: a hostname split across two segments is still caught ({}).", ev)));
    } else if inside.iter().all(|(_, b)| !*b) {
        v.push(tr("stateless", "per-packet matching", format!("Matches each packet on its own: a hostname split across two segments passes ({}).", ev)));
    } else {
        v.push(tr("partial", "partial reassembly", format!("Partial reassembly: splits inside the hostname give mixed results ({}).", ev)));
    }

    // Case sensitivity.
    match get("sni-upper") {
        Some(c) if c.blocked() => v.push(tr("case-insensitive", "case-insensitive match", "Hostname match is case-insensitive (upper-case hostname still blocked).".into())),
        Some(_) => v.push(tr("case-sensitive", "case-sensitive match", "Hostname match is case-sensitive (upper-case hostname passes).".into())),
        None => v.push(tr("case-unknown", "case unknown", "Case sensitivity: inconclusive.".into())),
    }

    // Inspection depth in packets.
    let mut depth = None;
    let mut unknown = false;
    for n in 1..=4 {
        match get(&format!("pad-{}", n)) {
            Some(c) if !c.blocked() => {
                depth = Some(n);
                break;
            }
            Some(_) => {}
            None => unknown = true,
        }
    }
    match (depth, unknown) {
        (Some(n), false) => v.push(tr(&format!("depth={}", n), &format!("first {} packet(s)", n), format!("Inspects only the first {} client packet(s); the ClientHello escapes in packet {}.", n, n + 1))),
        (None, false) => v.push(tr("depth>4", "depth above 4", "Still blocked behind 4 padding packets: depth above 4 (run `depth` for the exact value).".into())),
        _ => v.push(tr("depth-unknown", "depth unknown", "Inspection depth: inconclusive.".into())),
    }

    // Window size.
    match get("big-hello") {
        Some(c) if c.blocked() => v.push(tr("deep-scan", "scans deep into the ClientHello", "Finds the hostname behind a 700-byte padding extension: no small inspection window.".into())),
        Some(_) => v.push(tr("shallow-scan", "limited payload window", "Misses the hostname behind a 700-byte padding extension: only a limited window is inspected.".into())),
        None => v.push(tr("scan-unknown", "window unknown", "Payload window: inconclusive.".into())),
    }

    // Optional traits: only reported when they show up.
    let header_evades = ["split-1", "split-5", "split-sni-start"].iter().any(|k| get(k).map_or(false, |c| !c.blocked()));
    if header_evades {
        v.push(tr("evades-header-split", "needs full record header", "A cut before the hostname lets the ClientHello through: the middlebox seems to need a complete first segment.".into()));
    }
    if get("sni-last").map_or(false, |c| !c.blocked()) {
        v.push(tr("sni-position-sensitive", "SNI-position sensitive", "Moving the SNI extension last lets it through: position-sensitive parsing.".into()));
    }
    v
}

pub async fn cmd_fingerprint(t: Target, sni: String, controls: Vec<String>, repeats: u32) {
    let ms = matrix();
    let total = ms.len();
    let mut cells = vec![];
    for (i, p) in ms.iter().enumerate() {
        if !t.json {
            eprintln!("[{:>2}/{}] {:<16} {}", i + 1, total, p.key, p.desc);
        }
        let mut tests = vec![];
        let mut ctl = vec![];
        for _ in 0..repeats {
            tests.push(attempt(&t, &(p.sni)(&sni), &p.shape).await);
        }
        for c in &controls {
            for _ in 0..repeats {
                ctl.push(attempt(&t, &(p.sni)(c), &p.shape).await);
            }
        }
        cells.push(Cell { key: p.key, desc: p.desc, tests, ctl });
    }

    let plain = cells.iter().find(|c| c.key == "plain").expect("plain cell");
    let (result, traits, verdict) = if !plain.valid() {
        (
            "control_failed".to_string(),
            vec![],
            "Control SNIs failed on the plain ClientHello: the path itself is unhealthy.".to_string(),
        )
    } else if !plain.blocked() {
        ("not_blocked".to_string(), vec![], format!("{} is not interfered with: nothing to fingerprint.", sni))
    } else {
        let tr = derive(&cells);
        let result = tr.iter().map(|x| x.token.as_str()).collect::<Vec<_>>().join(",");
        let verdict = format!("Profile: {}", tr.iter().map(|x| x.label.as_str()).collect::<Vec<_>>().join(" / "));
        (result, tr, verdict)
    };

    if t.json {
        for c in &cells {
            for (kind, set) in [("test", &c.tests), ("control", &c.ctl)] {
                for a in set {
                    let mut v = serde_json::to_value(a).unwrap();
                    v["kind"] = json!(kind);
                    v["perturbation"] = json!(c.key);
                    println!("{}", v);
                }
            }
        }
        let matrix: Vec<_> = cells
            .iter()
            .map(|c| {
                json!({
                    "key": c.key, "desc": c.desc, "valid": c.valid(), "blocked": c.blocked(), "mixed": c.mixed(),
                    "outcomes": c.outcomes(), "server": c.server(),
                    "control_clean": c.ctl_clean(), "control_attempts": c.ctl.len(),
                })
            })
            .collect();
        let traits_json: Vec<_> = traits.iter().map(|x| json!({"token": x.token, "label": x.label, "text": x.text})).collect();
        println!("{}", json!({"cmd": "fingerprint", "result": result, "verdict": verdict, "traits": traits_json, "matrix": matrix}));
        return;
    }

    let mut rows = vec![
        line(format!("target    {}:{}   timeout {}s   repeats {}", t.server, t.port, t.timeout, repeats)),
        line(format!("controls  {}", controls.join(", "))),
        Row::Sep,
        line(format!("{:<16} {:<38} {:<12} {:<10} {}", "PERTURBATION", "WHAT IS SENT", "TEST", "SERVER", "CONTROL")),
    ];
    for c in &cells {
        let (test, color) = if !c.valid() {
            ("n/a".to_string(), ui::YELLOW)
        } else if c.blocked() {
            (c.outcomes(), ui::RED)
        } else {
            (c.outcomes(), ui::GREEN)
        };
        let mark = if c.mixed() { "~" } else { "" };
        rows.push(colored(
            format!(
                "{:<16} {:<38} {:<12} {:<10} {}/{}",
                c.key, c.desc, format!("{}{}", test, mark), c.server(), c.ctl_clean(), c.ctl.len()
            ),
            color,
        ));
    }
    rows.push(Row::Sep);
    let head_color = if traits.is_empty() { ui::YELLOW } else { ui::RED };
    rows.push(colored(&verdict, head_color));
    for x in &traits {
        rows.push(line(format!("- {}", x.text)));
    }
    rows.push(Row::Sep);
    rows.push(colored("note: observed behaviour compatible with this profile; it does not identify a product,", ui::DIM));
    rows.push(colored("and `~` marks a cell with mixed results (repeat with --repeats 3).", ui::DIM));
    ui::boxed(&format!("fingerprint: {}", sni), &rows);
}
