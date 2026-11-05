"""ARP behaviour: the weakness and the defences."""

from __future__ import annotations

from playground.engine.events import Event, Step
from playground.engine.packets import ARP_REPLY, ArpPacket
from playground.engine.state import Captured, Host, Network


def require_host(net: Network, name: str) -> Host:
    """Return the named host, or raise ValueError if it is not on the network."""
    host = net.host(name)
    if host is None:
        raise ValueError(f"no host named {name!r} on this network")
    return host


def receive_arp(net: Network, host_name: str, pkt: ArpPacket) -> tuple[Network, tuple[Event, ...]]:
    """Have ``host_name`` process ``pkt``, updating its ARP table unless an entry is locked."""
    host = require_host(net, host_name)
    is_reply = pkt.op == ARP_REPLY
    trace: tuple[Step, ...] = (Step("packet is an ARP reply (op=2)", is_reply),)
    if not is_reply:
        trace += (Step("decision", "IGNORE"),)
        event = Event("ignored", f"{host_name} ignores ARP packet with op={pkt.op}", host_name, trace)
        return net, (event,)

    locked = host.static_entries.get(pkt.psrc)
    trace += (Step(f"{pkt.psrc} has a static (locked) entry", locked is not None),)
    if locked is not None:
        matches = pkt.hwsrc == locked
        trace += (Step(f"claimed MAC {pkt.hwsrc} equals locked MAC {locked}", matches),)
        if not matches:
            trace += (Step("decision", "REJECT"),)
            text = (
                f"{host_name} rejects reply: {pkt.psrc} is locked to {locked}, "
                f"refusing {pkt.hwsrc}"
            )
            return net, (Event("rejected", text, host_name, trace),)

    trace += (Step("decision", "ACCEPT: update ARP table"),)
    new_net = net.with_host(host.with_arp(pkt.psrc, pkt.hwsrc))
    text = f"{host_name} accepts reply: {pkt.psrc} is now at {pkt.hwsrc}"
    return new_net, (Event("accepted", text, host_name, trace),)


def deliver(
    net: Network, sender_name: str, dest_ip: str, payload: str
) -> tuple[Network, tuple[Event, ...]]:
    """Send ``payload`` to ``dest_ip`` using the sender's ARP table to pick the MAC."""
    sender = require_host(net, sender_name)
    mac = sender.arp_table.get(dest_ip)
    trace: tuple[Step, ...] = (Step(f"{sender_name} has an ARP entry for {dest_ip}", mac is not None),)
    if mac is None:
        text = f"{sender_name} has no ARP entry for {dest_ip}; nothing sent"
        return net, (Event("no_entry", text, sender_name, trace),)

    receiver = net.host_by_mac(mac)
    trace += (Step(f"MAC {sender_name} uses for {dest_ip}", mac),)
    trace += (Step(f"MAC {mac} belongs to a host", receiver.name if receiver else False),)
    if receiver is None:
        text = f"frame from {sender_name} to {mac} reached no host; dropped"
        return net, (Event("dropped", text, sender_name, trace),)

    is_owner = receiver.ip == dest_ip
    trace += (Step(f"{receiver.name} owns {dest_ip}", is_owner),)
    if is_owner:
        text = f"{sender_name} -> {receiver.name}: {payload!r} delivered"
        return net, (Event("delivered", text, receiver.name, trace),)

    captured = Captured(by=receiver.name, src=sender_name, dest_ip=dest_ip, payload=payload)
    text = f"{receiver.name} intercepted {payload!r} from {sender_name} meant for {dest_ip}"
    return net.with_captured(captured), (Event("intercepted", text, receiver.name, trace),)
