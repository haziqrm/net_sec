"""Tests for the immutable network state."""

from dataclasses import FrozenInstanceError

import pytest

from playground.engine.packets import forge_reply
from playground.engine.scenarios import GATEWAY_IP, simple_lan
from playground.engine.state import Captured


def test_starting_state():
    net = simple_lan()
    assert set(net.hosts) == {"victim", "gateway", "attacker"}
    assert net.captured == () and net.clock == 0 and net.seed == 0
    victim, gateway, attacker = net.host("victim"), net.host("gateway"), net.host("attacker")
    assert (victim.ip, victim.mac) == ("10.0.0.5", "aa:aa:aa:aa:aa:05")
    assert (gateway.ip, gateway.mac) == (GATEWAY_IP, "aa:aa:aa:aa:aa:01")
    assert (attacker.ip, attacker.mac) == ("10.0.0.9", "aa:aa:aa:aa:aa:09")
    assert victim.arp_table == {GATEWAY_IP: gateway.mac}
    assert gateway.arp_table == {victim.ip: victim.mac}
    assert attacker.arp_table == {}
    assert all(h.static_entries == {} for h in net.hosts.values())


def test_with_arp_returns_new_host_and_leaves_original():
    victim = simple_lan().host("victim")
    poisoned = victim.with_arp(GATEWAY_IP, "aa:aa:aa:aa:aa:09")
    assert poisoned is not victim
    assert poisoned.arp_table[GATEWAY_IP] == "aa:aa:aa:aa:aa:09"
    assert victim.arp_table[GATEWAY_IP] == "aa:aa:aa:aa:aa:01"
    assert poisoned.static_entries == {}


def test_with_static_returns_new_host_and_leaves_original():
    victim = simple_lan().host("victim")
    locked = victim.with_static(GATEWAY_IP, "aa:aa:aa:aa:aa:01")
    assert locked is not victim
    assert locked.static_entries == {GATEWAY_IP: "aa:aa:aa:aa:aa:01"}
    assert locked.arp_table[GATEWAY_IP] == "aa:aa:aa:aa:aa:01"
    assert victim.static_entries == {}


def test_host_is_frozen():
    victim = simple_lan().host("victim")
    with pytest.raises(FrozenInstanceError):
        victim.ip = "1.2.3.4"


def test_lookups():
    net = simple_lan()
    assert net.host("victim").ip == "10.0.0.5"
    assert net.host("nobody") is None
    assert net.host_by_ip(GATEWAY_IP).name == "gateway"
    assert net.host_by_ip("10.0.0.99") is None
    assert net.host_by_mac("aa:aa:aa:aa:aa:09").name == "attacker"
    assert net.host_by_mac("ff:ff:ff:ff:ff:ff") is None


def test_with_host_and_with_captured_leave_original():
    net = simple_lan()
    poisoned = net.host("victim").with_arp(GATEWAY_IP, "aa:aa:aa:aa:aa:09")
    net2 = net.with_host(poisoned)
    assert net2.host("victim").arp_table[GATEWAY_IP] == "aa:aa:aa:aa:aa:09"
    assert net.host("victim").arp_table[GATEWAY_IP] == "aa:aa:aa:aa:aa:01"

    item = Captured(by="attacker", src="victim", dest_ip=GATEWAY_IP, payload="hello")
    net3 = net.with_captured(item)
    assert net3.captured == (item,)
    assert net.captured == ()


def test_forge_reply_defaults_to_sender_mac():
    net = simple_lan()
    pkt = forge_reply(net.host("attacker"), net.host("victim"), GATEWAY_IP)
    assert (pkt.op, pkt.psrc, pkt.hwsrc) == (2, GATEWAY_IP, "aa:aa:aa:aa:aa:09")
    assert (pkt.pdst, pkt.hwdst) == ("10.0.0.5", "aa:aa:aa:aa:aa:05")
