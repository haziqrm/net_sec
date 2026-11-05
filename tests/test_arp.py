"""Tests for ARP behaviour, the engine and goals."""

import pytest

from playground.engine.actions import ForgeArpReply, SendTraffic, SetStaticEntry
from playground.engine.engine import apply, run
from playground.engine.events import Step
from playground.engine.goals import arp_poisoned, check_goal, traffic_captured
from playground.engine.packets import ArpPacket
from playground.engine.protocols.arp import receive_arp
from playground.engine.scenarios import ATTACKER_MAC, GATEWAY_IP, GATEWAY_MAC, simple_lan
from playground.engine.state import Captured

FORGE = ForgeArpReply(sender="attacker", target="victim", claimed_ip=GATEWAY_IP)
SEND = SendTraffic(sender="victim", dest_ip=GATEWAY_IP, payload="password=hunter2")
LOCK = SetStaticEntry(host="victim", ip=GATEWAY_IP, mac=GATEWAY_MAC)
GOAL = {"type": "traffic_captured", "attacker": "attacker", "src": "victim"}


def kinds(events):
    return [e.kind for e in events]


def test_normal_traffic_is_delivered():
    net, events = apply(simple_lan(), SEND)
    assert kinds(events) == ["delivered"]
    assert events[0].host == "gateway"
    assert net.captured == ()


def test_forged_reply_poisons_victim_without_defence():
    net, events = apply(simple_lan(), FORGE)
    assert kinds(events) == ["sent", "accepted"]
    assert net.host("victim").arp_table[GATEWAY_IP] == ATTACKER_MAC
    assert arp_poisoned(net, "victim", GATEWAY_IP, "attacker")


def test_poisoned_traffic_is_intercepted_and_captured():
    net, events = run(simple_lan(), [FORGE, SEND])
    assert kinds(events)[-1] == "intercepted"
    assert net.captured == (
        Captured(by="attacker", src="victim", dest_ip=GATEWAY_IP, payload="password=hunter2"),
    )
    assert traffic_captured(net, "attacker", src="victim")


def test_static_entry_rejects_forged_reply():
    net, events = run(simple_lan(), [LOCK, FORGE])
    assert kinds(events) == ["defence", "sent", "rejected"]
    assert "locked" in events[-1].text
    assert net.host("victim").arp_table[GATEWAY_IP] == GATEWAY_MAC
    assert not arp_poisoned(net, "victim", GATEWAY_IP, "attacker")


def test_rejection_trace_checks_in_order():
    _, events = run(simple_lan(), [LOCK, FORGE])
    assert events[-1].trace == (
        Step("packet is an ARP reply (op=2)", True),
        Step(f"{GATEWAY_IP} has a static (locked) entry", True),
        Step(f"claimed MAC {ATTACKER_MAC} equals locked MAC {GATEWAY_MAC}", False),
        Step("decision", "REJECT"),
    )


def test_non_reply_is_ignored():
    net = simple_lan()
    request = ArpPacket(op=1, psrc=GATEWAY_IP, hwsrc=ATTACKER_MAC, pdst="10.0.0.5", hwdst="")
    new_net, events = receive_arp(net, "victim", request)
    assert kinds(events) == ["ignored"]
    assert new_net == net


def test_defended_victim_still_reaches_gateway():
    net, events = run(simple_lan(), [LOCK, FORGE, SEND])
    assert kinds(events)[-1] == "delivered"
    assert events[-1].host == "gateway"
    assert net.captured == ()


def test_apply_never_mutates_state():
    start = simple_lan()
    snapshot = simple_lan()
    for action in (FORGE, SEND, LOCK):
        apply(start, action)
    assert start == snapshot


def test_same_actions_give_equal_result():
    assert run(simple_lan(), [LOCK, FORGE, SEND]) == run(simple_lan(), [LOCK, FORGE, SEND])
    assert run(simple_lan(), [FORGE, SEND]) == run(simple_lan(), [FORGE, SEND])


def test_unknown_action_raises_type_error():
    with pytest.raises(TypeError):
        apply(simple_lan(), object())


def test_golden_attack_succeeds_and_defence_blocks_it():
    attacked, _ = run(simple_lan(), [FORGE, SEND])
    assert check_goal(attacked, GOAL)
    defended, _ = run(simple_lan(), [LOCK, FORGE, SEND])
    assert not check_goal(defended, GOAL)
