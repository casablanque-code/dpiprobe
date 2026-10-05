//! dpiprobe: a controlled DPI probe with ground truth.
//!
//! Run `dpiprobe server` on a machine you control and `dpiprobe probe` (or
//! `depth`, `threshold`) from behind the network under test. The server tells
//! the probe what really arrived, so every verdict is checked against reality.

mod probe;
mod server;
mod ui;
mod wire;

use clap::{Parser, Subcommand};
use probe::{Shape, Target};

#[derive(Parser)]
#[command(
    name = "dpiprobe",
    about = "Controlled DPI probe with ground truth: a client plus a server that records what really arrived.",
    after_help = "EXAMPLES:\n  dpiprobe server\n  dpiprobe probe --server 203.0.113.5 --test-sni blocked.example\n  dpiprobe probe --server 203.0.113.5 --test-sni blocked.example --split-sni\n  dpiprobe depth --server 203.0.113.5 --sni blocked.example\n  dpiprobe threshold --server 203.0.113.5"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the ground-truth server (the machine outside the censored network)
    Server {
        /// Data listener (probe traffic)
        #[arg(long, default_value = "0.0.0.0:443")]
        data: String,
        /// Control listener (ground-truth queries)
        #[arg(long, default_value = "0.0.0.0:9001")]
        ctl: String,
    },
    /// Compare a test SNI against a control SNI and classify the reaction (rst, drop, ...)
    Probe {
        #[command(flatten)]
        t: Target,
        /// SNI that should pass untouched
        #[arg(long, default_value = "allowed.example")]
        control_sni: String,
        /// SNI under test
        #[arg(long)]
        test_sni: String,
        /// Attempts per SNI
        #[arg(long, default_value_t = 3)]
        repeats: u32,
        #[command(flatten)]
        shape: Shape,
    },
    /// Measure inspection depth: how many client packets the DPI looks at
    Depth {
        #[command(flatten)]
        t: Target,
        /// SNI that triggers the DPI
        #[arg(long)]
        sni: String,
        /// SNI that should pass untouched
        #[arg(long, default_value = "allowed.example")]
        control_sni: String,
        /// Largest number of padding packets to try
        #[arg(long, default_value_t = 16)]
        max_pad: usize,
    },
    /// Measure the upload cutoff: after how many bytes the DPI kills or freezes the flow
    Threshold {
        #[command(flatten)]
        t: Target,
        /// SNI to use (must NOT trigger the DPI by name)
        #[arg(long, default_value = "allowed.example")]
        sni: String,
        /// Upload up to this many KB
        #[arg(long, default_value_t = 64)]
        max_kb: usize,
        /// Bytes per packet; also the measurement resolution
        #[arg(long, default_value_t = 256)]
        chunk: usize,
    },
}

#[tokio::main]
async fn main() {
    match Cli::parse().cmd {
        Cmd::Server { data, ctl } => server::run(data, ctl).await,
        Cmd::Probe { t, control_sni, test_sni, repeats, shape } => {
            probe::cmd_probe(t, control_sni, test_sni, repeats, shape).await
        }
        Cmd::Depth { t, sni, control_sni, max_pad } => probe::cmd_depth(t, sni, control_sni, max_pad).await,
        Cmd::Threshold { t, sni, max_kb, chunk } => probe::cmd_threshold(t, sni, max_kb, chunk).await,
    }
}
