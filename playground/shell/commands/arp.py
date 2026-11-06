"""ARP commands: arp -a, arpspoof, wait, captured, explain."""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import TYPE_CHECKING, List, Sequence, Tuple

from playground.engine.actions import ForgeArpReply
from playground.engine.engine import apply
from playground.engine.events import Event, Step
from playground.engine.state import Host, Network
from playground.shell.registry import Command, UsageError, register

if TYPE_CHECKING:
    from playground.shell.session import Session


def format_event(event: Event) -> str:
    """One line for an event, e.g. ``[rejected] victim rejects reply: ...``."""
    return f"[{event.kind}] {event.text}"


def format_step(number: int, step: Step) -> str:
    """One numbered trace line; booleans read as yes/no."""
    result = step.result if isinstance(step.result, str) else ("yes" if step.result else "no")
    return f"{number}. {step.check}: {result}"


def find_host(session: Session, name: str) -> Host:
    """Return the named host or raise a UsageError with a friendly message."""
    host = session.network.host(name)
    if host is None:
        raise UsageError(f"unknown host: {name}. Type hosts to list them")
    return host


def check_ip(text: str) -> str:
    """Return ``text`` if it is a valid IPv4 address, else raise UsageError."""
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        raise UsageError(f"not a valid IPv4 address: {text}") from None
    return text


def with_events(
    session: Session, network: Network, events: Sequence[Event]
) -> Tuple[Session, List[str]]:
    """Store the new network and events on the session and print the event lines."""
    new = replace(session, network=network, last_events=tuple(events))
    return new, [format_event(e) for e in events]


def run_arp(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """Show a host's ARP table (the attacker's by default)."""
    if not args or args[0] != "-a" or len(args) > 2:
        raise UsageError
    host = find_host(session, args[1] if len(args) == 2 else session.attacker)
    lines = [f"ARP table of {host.name}:"]
    for ip, mac in sorted(host.arp_table.items()):
        locked = " (static)" if host.static_entries.get(ip) == mac else ""
        lines.append(f"  {ip} at {mac}{locked}")
    if not host.arp_table:
        lines.append("  (empty)")
    return session, lines


def run_arpspoof(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """Forge an ARP reply telling ``target`` that ``ip`` is at the attacker's MAC."""
    if len(args) != 2:
        raise UsageError
    target = find_host(session, args[0])
    ip = check_ip(args[1])
    action = ForgeArpReply(sender=session.attacker, target=target.name, claimed_ip=ip)
    network, events = apply(session.network, action)
    return with_events(session, network, events)


def run_wait(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """Let time pass: apply the next scheduled action, if any."""
    if args:
        raise UsageError
    if not session.scheduled:
        return session, ["nothing happens"]
    action, rest = session.scheduled[0], session.scheduled[1:]
    network, events = apply(session.network, action)
    return with_events(replace(session, scheduled=rest), network, events)


def run_captured(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """List traffic the attacker has intercepted."""
    if args:
        raise UsageError
    mine = [c for c in session.network.captured if c.by == session.attacker]
    if not mine:
        return session, ["nothing captured yet"]
    return session, [f"from {c.src} to {c.dest_ip}: {c.payload}" for c in mine]


def run_explain(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """Show the checks behind the last event, as numbered steps."""
    if args:
        raise UsageError
    if not session.last_events:
        return session, ["nothing to explain yet: try arpspoof or wait first"]
    event = session.last_events[-1]
    lines = [f"Why: {event.text}"]
    lines += [format_step(i, step) for i, step in enumerate(event.trace, start=1)]
    if not event.trace:
        lines.append("(no checks recorded for this event)")
    return session, lines


register(Command("arp", "arp -a [host]", "Show an ARP table (yours, or another host's).", run_arp))
register(Command(
    "arpspoof", "arpspoof <target> <ip>",
    "Tell <target> that <ip> is at your MAC (forged ARP reply).", run_arpspoof,
))
register(Command("wait", "wait", "Let time pass so the next thing on the network happens.", run_wait))
register(Command("captured", "captured", "List traffic you have intercepted.", run_captured))
register(Command("explain", "explain", "Show the checks behind the last event.", run_explain))
