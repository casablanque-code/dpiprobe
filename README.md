# dpiprobe

A controlled probe for network interference (DPI-like middleboxes) **with ground truth**.

Most censorship-measurement tools only see the client's side: "the connection failed".
dpiprobe also runs a server you control, and that server reports what *really* arrived.
That is the difference between "something blocked me" and "the ClientHello never left
the forward path" or "the first segment was delivered and the flow was reset after it".

## How an experiment works

```
   network under test (unknown middlebox?)
                 |
 +---------+     v      +--------------------------+
 |  probe  | ---------> |  dpiprobe server         |
 |  (you)  |  ClientHello  (a machine you control)  |
 +---------+  variants  |                          |
      ^                 |  records what arrived    |
      |   control       |  (bytes, SNI, resets)    |
      +-----------------+------+-------------------+
          ground truth query   |  control port 9001
                               v
                  "token X: saw CH, 103 bytes, no RST"
```

1. The probe builds a TLS ClientHello by hand. Its 32-byte `random` is a unique token.
2. It sends the ClientHello (plain, split across segments, behind padding packets, ...)
   for a **test SNI** and a **control SNI**, and classifies the client-side reaction.
3. It asks the server over a separate control connection what that token looked like on arrival.
4. The verdict is built from both sides: what the client saw, and what the server saw.

## Commands

| command | question it answers |
|---|---|
| `dpiprobe probe` | Does this SNI trigger interference, and what does it look like (RST, drop, ...)? |
| `dpiprobe fingerprint` | What does this middlebox look like? Runs 15 perturbations (split positions, tiny segments, padding packets, SNI position, big ClientHello, hostname case) and derives a profile: reaction, reassembly, case sensitivity, depth, payload window. Every cell is checked against several control SNIs. |
| `dpiprobe quic` | Is QUIC (UDP 443) treated differently? Sends a plain UDP datagram, then QUIC Initials for control and test SNIs; separates "UDP blocked", "QUIC blocked entirely" and "SNI-based QUIC filtering". |
| `dpiprobe depth` | How many client packets does the middlebox inspect? |
| `dpiprobe threshold` | After how many uploaded bytes does it cut the flow? |
| `dpiprobe server` | The ground-truth side. Run it outside the network under test. |

Add `--json` to any measurement for machine-readable output (per-attempt evidence plus
a final line with `result`, `verdict` and `features`). `dpiprobe <command> --help` lists all options.

## Reading the results

dpiprobe reports interference *compatible with DPI*. One observed behaviour can never
prove that DPI is present: an IP block, a router ACL or a flaky link can look similar.
The control SNI is there to separate "this name is treated differently" from "the path is
broken", and the evidence line (server saw ClientHello x/n, RST at client, RST at server,
reaction time) is there so you can judge for yourself.

## The lab

`bin/dpi` drives a self-contained lab made of network namespaces and a simulated
middlebox, so every measurement can be validated against a configuration you chose:

```
  cl (probe)  --- dpi (NFQUEUE middlebox, lab/dpi_sim.py) ---  sv (dpiprobe server)
  10.0.1.2        10.0.1.1 | 10.0.2.1                          10.0.2.2
```

```bash
dpi doctor            # check prerequisites
dpi on sni-drop       # start the lab with a profile
dpi probe             # measure it
dpi test              # run the whole validation table (lab/tests.tsv)
dpi help              # everything else
```

Profiles live in `lab/profiles/*.json`; each row of `lab/tests.tsv` is
`profile | dpiprobe args | expected result`. The simulator has its own unit tests:
`dpi selftest`.

## Build

```bash
cargo build --release
ln -sf "$PWD/bin/dpi" /usr/local/bin/dpi
```

The lab needs Linux, root, `nft`, and a Python with `netfilterqueue`, `scapy` and (for QUIC profiles) `cryptography`
(default `/root/lab/venv`, override with `DPI_PY`).
