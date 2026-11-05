"""apply(state, action) -> (new_state, events)."""

from __future__ import annotations

from typing import Iterable

from playground.engine.actions import Action, ForgeArpReply, SendTraffic, SetStaticEntry
from playground.engine.events import Event
from playground.engine.packets import forge_reply
from playground.engine.protocols.arp import deliver, receive_arp, require_host
from playground.engine.state import Network


def apply(net: Network, action: Action) -> tuple[Network, tuple[Event, ...]]:
    """Apply one action, returning the new network and the events it caused."""
    if isinstance(action, ForgeArpReply):
        sender = require_host(net, action.sender)
        target = require_host(net, action.target)
        pkt = forge_reply(sender, target, action.claimed_ip, action.claimed_mac)
        sent = Event(
            "sent",
            f"{sender.name} sends ARP reply to {target.name}: {pkt.psrc} is at {pkt.hwsrc}",
            sender.name,
        )
        new_net, events = receive_arp(net, target.name, pkt)
        return new_net, (sent, *events)

    if isinstance(action, SendTraffic):
        return deliver(net, action.sender, action.dest_ip, action.payload)

    if isinstance(action, SetStaticEntry):
        host = require_host(net, action.host)
        defence = Event(
            "defence",
            f"{host.name} locks ARP entry {action.ip} -> {action.mac}",
            host.name,
        )
        return net.with_host(host.with_static(action.ip, action.mac)), (defence,)

    raise TypeError(f"unknown action: {action!r}")


def run(net: Network, actions: Iterable[Action]) -> tuple[Network, tuple[Event, ...]]:
    """Apply actions in order, returning the final network and all events."""
    events: tuple[Event, ...] = ()
    for action in actions:
        net, new_events = apply(net, action)
        events += new_events
    return net, events
