#!/usr/bin/env python3
"""Unit tests for dpi_sim.py. Needs scapy only (no NFQUEUE): python3 lab/test_dpi_sim.py"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.modules.setdefault("netfilterqueue", types.ModuleType("netfilterqueue"))

from scapy.all import IP, TCP, Raw  # noqa: E402
import dpi_sim  # noqa: E402

dpi_sim.log = lambda **kw: None  # keep test output clean

C, S = "10.0.1.2", "10.0.2.2"


def pkt(payload=b"", sport=40000, seq=1000, ack=5000, flags="PA", to_server=True):
    if to_server:
        ip, tcp = IP(src=C, dst=S), TCP(sport=sport, dport=443, seq=seq, ack=ack, flags=flags)
    else:
        ip, tcp = IP(src=S, dst=C), TCP(sport=443, dport=sport, seq=ack, ack=seq, flags=flags)
    p = ip / tcp
    if payload:
        p = p / Raw(payload)
    return bytes(p)


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def make(**cfg):
    sent = []
    clock = Clock()
    cfg.setdefault("match", "blocked.example")
    sim = dpi_sim.Sim(cfg, sender=lambda p, **kw: sent.append(p), clock=clock)
    return sim, sent, clock


class SimTests(unittest.TestCase):
    def test_match_drop_blocks_whole_flow(self):
        sim, sent, _ = make(action="drop")
        self.assertFalse(sim.process(pkt(b"hello blocked.example")))
        self.assertFalse(sim.process(pkt(b"more data", seq=1100)))           # same flow stays dropped
        self.assertFalse(sim.process(pkt(b"reply", to_server=False)))        # and the reverse direction
        self.assertTrue(sim.process(pkt(b"other flow", sport=40001)))
        self.assertEqual(sent, [])

    def test_match_rst_injects_both_ways_with_right_numbers(self):
        sim, sent, _ = make(action="rst", rst_to="both")
        self.assertFalse(sim.process(pkt(b"x blocked.example", seq=1000, ack=5000)))
        self.assertEqual(len(sent), 2)
        to_client, to_server = sent
        self.assertEqual((to_client[IP].dst, to_client[TCP].seq), (C, 5000))
        self.assertEqual((to_server[IP].dst, to_server[TCP].seq), (S, 1000))
        self.assertTrue(int(to_client[TCP].flags) & 0x04)

    def test_stateless_misses_split_sni_stateful_catches_it(self):
        a, b = b"GET blocked.", b"example HTTP/1.1"
        sim, _, _ = make(action="drop", stateful=False)
        self.assertTrue(sim.process(pkt(a)))
        self.assertTrue(sim.process(pkt(b, seq=1100)))
        sim, _, _ = make(action="drop", stateful=True)
        self.assertTrue(sim.process(pkt(a)))
        self.assertFalse(sim.process(pkt(b, seq=1100)))

    def test_inspection_depth(self):
        sim, _, _ = make(action="drop", max_pkts=2)
        self.assertTrue(sim.process(pkt(b"pad1")))
        self.assertTrue(sim.process(pkt(b"pad2", seq=1010)))
        self.assertTrue(sim.process(pkt(b"blocked.example", seq=1020)))      # 3rd packet: not inspected

    def test_threshold_triggers_on_bytes_not_content(self):
        sim, _, _ = make(action="drop", match="", threshold_kb=1)
        self.assertTrue(sim.process(pkt(b"A" * 600)))
        self.assertFalse(sim.process(pkt(b"A" * 600, seq=1600)))             # 1200 >= 1024

    def test_syn_clears_state_on_port_reuse(self):
        sim, _, _ = make(action="drop")
        self.assertFalse(sim.process(pkt(b"blocked.example")))
        self.assertTrue(sim.process(pkt(flags="S")))                         # new connection, same 5-tuple
        self.assertTrue(sim.process(pkt(b"harmless", seq=2000)))

    def test_rst_action_forgets_flow_on_fin(self):
        sim, _, _ = make(action="rst")
        sim.process(pkt(b"blocked.example"))
        self.assertEqual(len(sim.blocked), 1)
        self.assertTrue(sim.process(pkt(flags="FA", seq=1100)))
        self.assertEqual(len(sim.blocked), 0)

    def test_gc_expires_flows_and_blocked(self):
        sim, _, clock = make(action="drop", flow_ttl=10, blocked_ttl=20, gc_interval=1)
        sim.process(pkt(b"idle flow", sport=40001))
        sim.process(pkt(b"blocked.example", sport=40002))
        self.assertEqual((len(sim.flows), len(sim.blocked)), (1, 1))
        clock.t = 15
        sim.process(pkt(b"tick", sport=40003))
        self.assertEqual(len(sim.flows), 1)       # only the fresh flow is left
        self.assertEqual(len(sim.blocked), 1)     # not expired yet
        clock.t = 40
        sim.process(pkt(b"tick", sport=40003))
        self.assertEqual(len(sim.blocked), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
