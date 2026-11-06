"""ARP Level 1 commands: ip addr, arp-scan, arpspoof, wait, tcpdump, show-arp, explain.

Output is plain and short. ``show-arp`` and ``explain`` show things a real
attacker could not see, so they start with "[teaching view]".
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import TYPE_CHECKING, Dict, List, Tuple

from playground.engine.actions import ForgeArpReply
from playground.engine.engine import apply
from playground.engine.events import Step
from playground.engine.protocols.arp import require_host
from playground.engine.state import Host, Network
from playground.shell.registry import Command, CommandError, UsageError, register

if TYPE_CHECKING:
    from playground.shell.session import Session

TEACHING = "[teaching view]"
SIM = "[sim]"
MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

Output = Tuple["Session", List[str]]


# ----- helpers -------------------------------------------------------------

def ip_key(ip: str) -> Tuple[int, ...]:
    """Sort key so 10.0.0.10 comes after 10.0.0.9."""
    return tuple(int(part) if part.isdigit() else 0 for part in ip.split("."))


def host_at(net: Network, ip: str) -> Host:
    """The host that owns ``ip``, or a CommandError."""
    host = net.host_by_ip(ip)
    if host is None:
        raise CommandError(f"no host with address {ip}")
    return host


def parse_spoof_args(args: List[str]) -> Tuple[str, str, str]:
    """Return (target_ip, mac, host_ip) from ``-t <ip> --mac <mac> <ip>``, in any order."""
    options: Dict[str, str] = {}
    positional: List[str] = []
    words = iter(args)
    for word in words:
        if word in ("-t", "--mac"):
            value = next(words, None)
            if value is None or word in options:
                raise UsageError
            options[word] = value
        else:
            positional.append(word)
    if set(options) != {"-t", "--mac"} or len(positional) != 1:
        raise UsageError
    return options["-t"], options["--mac"], positional[0]


def yes_no(step: Step) -> str:
    """A trace result as text: booleans read as yes / no."""
    if isinstance(step.result, str):
        return step.result
    return "yes" if step.result else "no"


# ----- commands ------------------------------------------------------------

def run_ip(session: Session, args: List[str]) -> Output:
    """``ip addr``: your own IP and MAC."""
    if args != ["addr"]:
        raise UsageError
    me = require_host(session.network, session.attacker)
    return session, [f"eth0  ip {me.ip}  mac {me.mac}"]


def run_arp_scan(session: Session, args: List[str]) -> Output:
    """``arp-scan -l``: every other host on the local network. Changes nothing."""
    if args != ["-l"]:
        raise UsageError
    others = sorted(
        (h for h in session.network.hosts.values() if h.name != session.attacker),
        key=lambda h: ip_key(h.ip),
    )
    return session, [f"{h.ip}  {h.mac}" for h in others] + [f"{len(others)} hosts found"]


def run_arpspoof(session: Session, args: List[str]) -> Output:
    """``arpspoof -t <target-ip> --mac <mac> <host-ip>``: send one forged ARP reply."""
    target_ip, mac, host_ip = parse_spoof_args(args)
    net = session.network
    target, impersonated = host_at(net, target_ip), host_at(net, host_ip)
    mac = mac.lower()
    if not MAC_PATTERN.match(mac):
        raise CommandError(f"invalid mac address {mac}")
    action = ForgeArpReply(
        sender=session.attacker, target=target.name, claimed_ip=impersonated.ip, claimed_mac=mac
    )
    new_net, events = apply(net, action)
    results = [f"{SIM} {e.text}" for e in events if e.kind != "sent"]
    new = replace(session, network=new_net, last_events=events)
    return new, [f"sent: {impersonated.ip} is at {mac}", *results]


def run_wait(session: Session, args: List[str]) -> Output:
    """Let time pass: apply the next scheduled action, if any."""
    if args:
        raise UsageError
    if not session.scheduled:
        return session, ["nothing happens"]
    action, rest = session.scheduled[0], session.scheduled[1:]
    new_net, events = apply(session.network, action)
    new = replace(session, network=new_net, scheduled=rest, last_events=events)
    return new, [f"{SIM} {e.text}" for e in events]


def run_tcpdump(session: Session, args: List[str]) -> Output:
    """``tcpdump``: traffic you received that was meant for someone else."""
    if args:
        raise UsageError
    net = session.network
    mine = [c for c in net.captured if c.by == session.attacker]
    if not mine:
        return session, ["no packets captured"]
    lines = []
    for c in mine:
        src = net.host(c.src)
        lines.append(f"{src.ip if src else c.src} -> {c.dest_ip}: {c.payload}")
    return session, lines


def run_show_arp(session: Session, args: List[str]) -> Output:
    """Any host's ARP table. A real attacker could not see this."""
    if len(args) != 1:
        raise UsageError
    host = session.network.host(args[0])
    if host is None:
        raise CommandError(f"no host named {args[0]}")
    lines = [TEACHING]
    for ip in sorted(host.arp_table, key=ip_key):
        mac = host.arp_table[ip]
        locked = " (locked)" if host.static_entries.get(ip) == mac else ""
        lines.append(f"{ip} -> {mac}{locked}")
    if not host.arp_table:
        lines.append("(empty)")
    return session, lines


def run_explain(session: Session, args: List[str]) -> Output:
    """The checks behind the last engine event, as numbered steps."""
    if args:
        raise UsageError
    if not session.last_events:
        return session, ["nothing to explain yet"]
    event = session.last_events[-1]
    lines = [TEACHING, event.text]
    lines += [f"{i}. {step.check}: {yes_no(step)}" for i, step in enumerate(event.trace, start=1)]
    return session, lines


register(Command("ip", "ip addr", "Show your IP and MAC address.", run_ip))
register(Command("arp-scan", "arp-scan -l", "Find the other hosts on the network.", run_arp_scan))
register(Command(
    "arpspoof", "arpspoof -t <target-ip> --mac <mac> <host-ip>",
    "Tell <target-ip> that <host-ip> is at <mac>.", run_arpspoof,
))
register(Command("wait", "wait", "Let time pass (the victim logs in).", run_wait))
register(Command("tcpdump", "tcpdump", "Show traffic you have intercepted.", run_tcpdump))
register(Command(
    "show-arp", "show-arp <host-name>", f"{TEACHING} Show a host's ARP table.", run_show_arp,
))
register(Command(
    "explain", "explain", f"{TEACHING} Show the checks behind the last event.", run_explain,
))
