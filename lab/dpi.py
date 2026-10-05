import json, sys, time
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw, send

cfg = {"match": "", "action": "rst", "rst_to": "both", "max_pkts": 3,
       "stateful": False, "threshold_kb": 0, "server_port": 443, "queue": 0}
cfg.update(json.load(open(sys.argv[1] if len(sys.argv) > 1 else "/root/lab/dpi.json")))
M = cfg["match"].encode()
flows, blocked = {}, set()

def log(**kw):
    kw["t"] = round(time.time(), 3)
    print(json.dumps(kw), flush=True)

def rst(src, dst, sport, dport, seq):
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R", seq=seq), verbose=0)

def cb(p):
    try:
        ip = IP(p.get_payload())
        if TCP not in ip:
            return p.accept()
        t = ip[TCP]
        c2s = t.dport == cfg["server_port"]
        key = (ip.src, t.sport, ip.dst, t.dport) if c2s else (ip.dst, t.dport, ip.src, t.sport)
        if key in blocked:
            return p.drop() if cfg["action"] == "drop" else p.accept()
        if int(t.flags) & 0x05:  # FIN/RST
            flows.pop(key, None)
            return p.accept()
        if not c2s or Raw not in ip:
            return p.accept()
        data = bytes(ip[Raw])
        f = flows.setdefault(key, {"n": 0, "bytes": 0, "buf": b""})
        f["n"] += 1
        f["bytes"] += len(data)
        why = None
        if cfg["max_pkts"] == 0 or f["n"] <= cfg["max_pkts"]:
            if cfg["stateful"]:
                f["buf"] += data
                hit = M and M in f["buf"]
            else:
                hit = M and M in data
            if hit:
                why = "match"
        if not why and cfg["threshold_kb"] and f["bytes"] >= cfg["threshold_kb"] * 1024:
            why = "threshold"
        if not why:
            return p.accept()
        blocked.add(key)
        log(ev=why, flow=str(key), pkt=f["n"], bytes=f["bytes"], action=cfg["action"])
        if cfg["action"] == "rst":
            if cfg["rst_to"] in ("client", "both"):
                rst(ip.dst, ip.src, t.dport, t.sport, t.ack)
            if cfg["rst_to"] in ("server", "both"):
                rst(ip.src, ip.dst, t.sport, t.dport, t.seq)
        return p.drop()
    except Exception as e:
        log(ev="error", err=str(e))
        p.accept()

nf = NetfilterQueue()
nf.bind(cfg["queue"], cb)
log(ev="start", cfg={k: v for k, v in cfg.items()})
nf.run()
