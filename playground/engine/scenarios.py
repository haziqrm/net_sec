"""Starting networks."""

from __future__ import annotations

from playground.engine.state import Host, Network

GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "aa:aa:aa:aa:aa:01"
VICTIM_IP = "10.0.0.5"
VICTIM_MAC = "aa:aa:aa:aa:aa:05"
ATTACKER_IP = "10.0.0.9"
ATTACKER_MAC = "aa:aa:aa:aa:aa:09"


def simple_lan() -> Network:
    """Victim, gateway and attacker; victim and gateway know each other correctly."""
    victim = Host("victim", VICTIM_IP, VICTIM_MAC, arp_table={GATEWAY_IP: GATEWAY_MAC})
    gateway = Host("gateway", GATEWAY_IP, GATEWAY_MAC, arp_table={VICTIM_IP: VICTIM_MAC})
    attacker = Host("attacker", ATTACKER_IP, ATTACKER_MAC)
    return Network(hosts={h.name: h for h in (victim, gateway, attacker)})
