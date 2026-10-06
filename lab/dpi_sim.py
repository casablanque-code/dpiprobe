#!/usr/bin/env python3
"""Simulated middlebox for the dpiprobe lab.

Reads TCP packets from an NFQUEUE, applies a configurable "DPI" model and either
accepts, drops, or injects TCP resets. It is a measurement fixture, not a product:
the point is to have a middlebox whose configuration is known, so that dpiprobe's
conclusions can be validated against ground truth.

Usage: dpi_sim.py CONFIG.json     (see lab/profiles/*.json)

Config keys:
  match         string looked for in client payload (empty = no content rule)
  action        "rst" or "drop"
  rst_to        "client", "server" or "both" (who receives the injected RST)
  max_pkts      inspect only the first N client data packets (0 = all)
  stateful      true: concatenate payloads of the inspected packets before matching
  threshold_kb  trigger after this many client bytes on a flow, regardless of content (0 = off)
  server_port   TCP port of the protected service
  flow_ttl      seconds of inactivity before per-flow counters are forgotten
  blocked_ttl   seconds a triggered flow stays marked as blocked
  tcp           false: leave TCP alone (useful for QUIC-only profiles), default true
  quic          UDP/QUIC model for datagrams to server_port:
                  "off"      leave UDP alone (default)
                  "sni"      decrypt QUIC Initials and react when `match` is in the ClientHello
                  "initial"  react to every QUIC Initial, whatever the SNI
                  "udp"      react to every UDP datagram to server_port
  quic_action   "drop" or "icmp" (answer with ICMP port unreachable)

The "sni" and "initial" modes need the `cryptography` package.
"""
import hashlib
import hmac
import json
import struct
import sys
import time

DEFAULTS = {
    "match": "",
    "action": "rst",
    "rst_to": "both",
    "max_pkts": 3,
    "stateful": False,
    "threshold_kb": 0,
    "server_port": 443,
    "queue": 0,
    "flow_ttl": 60,
    "blocked_ttl": 120,
    "gc_interval": 5,
    "tcp": True,
    "quic": "off",
    "quic_action": "drop",
}

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


# --- QUIC v1 Initial decryption (RFC 9001) ---------------------------------

QUIC_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def _varint(b, pos):
    first = b[pos]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[pos + i]
    return v, pos + n


def quic_initial_crypto(dg):
    """Return the CRYPTO data (the ClientHello) of a client Initial datagram, or None."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        if len(dg) < 21 or not dg[0] & 0x80 or (dg[0] >> 4) & 3 != 0 or dg[1:5] != b"\x00\x00\x00\x01":
            return None
        pos = 5
        dl = dg[pos]
        dcid = dg[pos + 1:pos + 1 + dl]
        pos += 1 + dl
        pos += 1 + dg[pos]                      # source connection id
        token_len, pos = _varint(dg, pos)
        pos += token_len
        length, pos = _varint(dg, pos)
        pn_off = pos
        initial = hmac.new(QUIC_SALT_V1, dcid, hashlib.sha256).digest()
        secret = _expand_label(initial, b"client in", 32)
        key = _expand_label(secret, b"quic key", 16)
        iv = _expand_label(secret, b"quic iv", 12)
        hp = _expand_label(secret, b"quic hp", 16)
        mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(dg[pn_off + 4:pn_off + 20])
        first = dg[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 3) + 1
        pn = bytes(a ^ b for a, b in zip(dg[pn_off:pn_off + pn_len], mask[1:1 + pn_len]))
        header = bytes([first]) + dg[1:pn_off] + pn
        nonce = (int.from_bytes(iv, "big") ^ int.from_bytes(pn, "big")).to_bytes(12, "big")
        plain = AESGCM(key).decrypt(nonce, dg[pn_off + pn_len:pn_off + length], header)
        crypto, p = b"", 0
        while p < len(plain):
            t = plain[p]
            if t in (0x00, 0x01):
                p += 1
            elif t == 0x06:
                off, p = _varint(plain, p + 1)
                ln, p = _varint(plain, p)
                if off == len(crypto):
                    crypto += plain[p:p + ln]
                p += ln
            else:
                break
        return crypto
    except Exception:  # not a decryptable Initial
        return None


def log(**kw):
    kw["t"] = round(time.time(), 3)
    print(json.dumps(kw), flush=True)


class Sim:
    def __init__(self, cfg, sender=None, clock=time.monotonic):
        self.cfg = dict(DEFAULTS)
        self.cfg.update(cfg)
        self.match = self.cfg["match"].encode()
        if self.cfg["quic"] in ("sni", "initial"):
            try:
                import cryptography  # noqa: F401
            except ImportError:
                raise SystemExit("quic mode '%s' needs the 'cryptography' package: pip install cryptography" % self.cfg["quic"])
        self.sender = sender
        self.clock = clock
        self.flows = {}    # key -> {n, bytes, buf, last}
        self.blocked = {}  # key -> expiry time
        self.last_gc = clock()

    # -- housekeeping -------------------------------------------------------
    def gc(self, now):
        if now - self.last_gc < self.cfg["gc_interval"]:
            return
        self.last_gc = now
        old = [k for k, f in self.flows.items() if now - f["last"] > self.cfg["flow_ttl"]]
        exp = [k for k, until in self.blocked.items() if until < now]
        for k in old:
            del self.flows[k]
        for k in exp:
            del self.blocked[k]
        if old or exp:
            log(ev="gc", flows_removed=len(old), blocked_removed=len(exp),
                flows=len(self.flows), blocked=len(self.blocked))

    # -- packet handling ----------------------------------------------------
    def process(self, raw):
        """Return True to accept the packet, False to drop it."""
        from scapy.all import IP, TCP, UDP, Raw
        ip = IP(raw)
        if UDP in ip:
            return self.process_udp(ip, raw)
        if TCP not in ip or not self.cfg["tcp"]:
            return True
        t = ip[TCP]
        cfg = self.cfg
        now = self.clock()
        self.gc(now)
        flags = int(t.flags)
        c2s = t.dport == cfg["server_port"]
        key = (ip.src, t.sport, ip.dst, t.dport) if c2s else (ip.dst, t.dport, ip.src, t.sport)

        # A fresh SYN means the 5-tuple is being reused: forget everything about it.
        if c2s and flags & SYN and not flags & ACK:
            self.flows.pop(key, None)
            self.blocked.pop(key, None)
            return True

        if key in self.blocked:
            if cfg["action"] == "drop":
                self.blocked[key] = now + cfg["blocked_ttl"]
                return False
            if flags & (FIN | RST):
                del self.blocked[key]
            return True

        if flags & (FIN | RST):
            self.flows.pop(key, None)
            return True
        if not c2s or Raw not in ip:
            return True

        data = bytes(ip[Raw])
        f = self.flows.setdefault(key, {"n": 0, "bytes": 0, "buf": b"", "last": now})
        f["last"] = now
        f["n"] += 1
        f["bytes"] += len(data)

        why = None
        if cfg["max_pkts"] == 0 or f["n"] <= cfg["max_pkts"]:
            if cfg["stateful"]:
                f["buf"] += data
                hit = bool(self.match) and self.match in f["buf"]
            else:
                hit = bool(self.match) and self.match in data
            if hit:
                why = "match"
        if not why and cfg["threshold_kb"] and f["bytes"] >= cfg["threshold_kb"] * 1024:
            why = "threshold"
        if not why:
            return True

        self.blocked[key] = now + cfg["blocked_ttl"]
        self.flows.pop(key, None)
        log(ev=why, flow=str(key), pkt=f["n"], bytes=f["bytes"], action=cfg["action"])
        if cfg["action"] == "rst":
            if cfg["rst_to"] in ("client", "both"):
                self.rst(ip.dst, ip.src, t.dport, t.sport, t.ack)
            if cfg["rst_to"] in ("server", "both"):
                self.rst(ip.src, ip.dst, t.sport, t.dport, t.seq)
        return False

    def process_udp(self, ip, raw):
        """UDP/QUIC model. Return True to accept the datagram, False to drop it."""
        from scapy.all import UDP
        cfg = self.cfg
        mode = cfg["quic"]
        u = ip[UDP]
        if mode == "off" or u.dport != cfg["server_port"]:
            return True
        why = None
        if mode == "udp":
            why = "udp"
        else:
            data = quic_initial_crypto(bytes(u.payload))
            if data is None:
                return True
            if mode == "initial":
                why = "quic-initial"
            elif self.match and self.match in data:
                why = "quic-sni"
        if not why:
            return True
        log(ev=why, flow=str((ip.src, u.sport, ip.dst, u.dport)), action=cfg["quic_action"])
        if cfg["quic_action"] == "icmp":
            self.icmp_unreachable(ip, raw)
        return False

    def icmp_unreachable(self, ip, raw):
        from scapy.all import IP, ICMP
        inner = raw[:ip.ihl * 4 + 8]
        self.sender(IP(src=ip.dst, dst=ip.src) / ICMP(type=3, code=3) / inner, verbose=0)

    def rst(self, src, dst, sport, dport, seq):
        from scapy.all import IP, TCP
        self.sender(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R", seq=seq), verbose=0)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: dpi_sim.py CONFIG.json")
    from netfilterqueue import NetfilterQueue
    from scapy.all import send

    sim = Sim(json.load(open(sys.argv[1])), sender=send)

    def cb(p):
        try:
            verdict = sim.process(p.get_payload())
        except Exception as e:  # never wedge the lab on a parsing error
            log(ev="error", err=str(e))
            verdict = True
        p.accept() if verdict else p.drop()

    nf = NetfilterQueue()
    nf.bind(sim.cfg["queue"], cb)
    log(ev="start", cfg=sim.cfg)
    nf.run()


if __name__ == "__main__":
    main()
