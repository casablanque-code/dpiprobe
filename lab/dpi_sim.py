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
"""
import json
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
}

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


def log(**kw):
    kw["t"] = round(time.time(), 3)
    print(json.dumps(kw), flush=True)


class Sim:
    def __init__(self, cfg, sender=None, clock=time.monotonic):
        self.cfg = dict(DEFAULTS)
        self.cfg.update(cfg)
        self.match = self.cfg["match"].encode()
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
        from scapy.all import IP, TCP, Raw
        ip = IP(raw)
        if TCP not in ip:
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
