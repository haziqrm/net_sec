"""ARP Level 1 commands.

Real tools (ip, arp, arp-scan, arpspoof, tcpdump) print output in the style of
their Linux counterparts. ``wait``, ``show-arp`` and ``explain`` exist only to
teach; the last two are marked "[teaching view]".
"""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import TYPE_CHECKING, List, Tuple

from playground.engine.actions import ForgeArpReply
from playground.engine.engine import apply
from playground.engine.events import Step
from playground.engine.protocols.arp import require_host
from playground.engine.state import Host, Network
from playground.shell.registry import Command, CommandError, UsageError, register

if TYPE_CHECKING:
    from playground.shell.session import Session

IFACE = "eth0"
PREFIX_LEN = 24  # the simulated LAN is treated as a /24
TEACHING = "[teaching view]"
SIM = "[sim]"

Output = Tuple["Session", List[str]]


# ----- helpers -------------------------------------------------------------

def ip_key(ip: str) -> Tuple[int, ...]:
    """Sort key so 10.0.0.10 comes after 10.0.0.9."""
    return tuple(int(part) if part.isdigit() else 0 for part in ip.split("."))


def arp_entries(host: Host) -> List[str]:
    """``host``'s ARP table in ``arp -a`` format; locked entries are marked PERM."""
    lines = []
    for ip in sorted(host.arp_table, key=ip_key):
        mac = host.arp_table[ip]
        perm = " PERM" if host.static_entries.get(ip) == mac else ""
        lines.append(f"? ({ip}) at {mac} [ether]{perm} on {IFACE}")
    return lines


def host_at(net: Network, ip: str) -> Host:
    """The host that owns ``ip``, or a CommandError with a short, real-looking message."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise CommandError(f"invalid address: {ip}") from None
    host = net.host_by_ip(ip)
    if host is None:
        raise CommandError(f"no host with address {ip}")
    return host


def yes_no(step: Step) -> str:
    """A trace result as text: booleans read as yes / NO."""
    if isinstance(step.result, str):
        return step.result
    return "yes" if step.result else "NO"


# ----- real tools ----------------------------------------------------------

def run_ip(session: Session, args: List[str]) -> Output:
    """``ip addr``: the attacker's interfaces."""
    if args not in (["addr"], ["a"], ["address"], ["addr", "show"]):
        raise UsageError
    me = require_host(session.network, session.attacker)
    iface = ipaddress.IPv4Interface(f"{me.ip}/{PREFIX_LEN}")
    return session, [
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000",
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
        "    inet 127.0.0.1/8 scope host lo",
        "       valid_lft forever preferred_lft forever",
        f"2: {IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP "
        "group default qlen 1000",
        f"    link/ether {me.mac} brd ff:ff:ff:ff:ff:ff",
        f"    inet {iface.with_prefixlen} brd {iface.network.broadcast_address} scope global {IFACE}",
        "       valid_lft forever preferred_lft forever",
    ]


def run_arp(session: Session, args: List[str]) -> Output:
    """``arp -a``: the attacker's own ARP cache (empty output if there is nothing)."""
    if args != ["-a"]:
        raise UsageError
    return session, arp_entries(require_host(session.network, session.attacker))


def run_arp_scan(session: Session, args: List[str]) -> Output:
    """``arp-scan -l``: every other host on the LAN. Read-only."""
    if args not in (["-l"], ["--localnet"]):
        raise UsageError
    me = require_host(session.network, session.attacker)
    others = sorted(
        (h for h in session.network.hosts.values() if h.name != me.name), key=lambda h: ip_key(h.ip)
    )
    size = ipaddress.IPv4Interface(f"{me.ip}/{PREFIX_LEN}").network.num_addresses
    lines = [
        f"Interface: {IFACE}, type: EN10MB, MAC: {me.mac}, IPv4: {me.ip}",
        f"Starting arp-scan with {size} hosts",
    ]
    lines += [f"{h.ip}\t{h.mac}\t(Unknown)" for h in others]
    lines += ["", f"Ending arp-scan: {size} hosts scanned. {len(others)} responded"]
    return session, lines


def run_arpspoof(session: Session, args: List[str]) -> Output:
    """``arpspoof -t <target-ip> <host-ip>``: send one forged ARP reply to the target."""
    if len(args) != 3 or args[0] != "-t":
        raise UsageError
    net = session.network
    target, impersonated = host_at(net, args[1]), host_at(net, args[2])
    me = require_host(net, session.attacker)
    action = ForgeArpReply(sender=me.name, target=target.name, claimed_ip=impersonated.ip)
    new_net, events = apply(net, action)
    wire = f"{me.mac} {target.mac} 0806 42: arp reply {impersonated.ip} is-at {me.mac}"
    results = [f"{SIM} {e.text}" for e in events if e.kind != "sent"]
    return replace(session, network=new_net, last_events=events), [wire, *results]


def run_tcpdump(session: Session, args: List[str]) -> Output:
    """``tcpdump``: traffic the attacker received that was meant for someone else."""
    if args not in ([], ["-i", IFACE]):
        raise UsageError
    net = session.network
    mine = [c for c in net.captured if c.by == session.attacker]
    if not mine:
        return session, [f"listening on {IFACE}, no packets captured yet"]
    lines = [f"listening on {IFACE}, link-type EN10MB (Ethernet), snapshot length 262144 bytes"]
    for c in mine:
        src = net.host(c.src)
        lines.append(f"IP {src.ip if src else c.src} > {c.dest_ip}: {c.payload}")
    return session, lines


# ----- simulation and teaching views ---------------------------------------

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


def run_show_arp(session: Session, args: List[str]) -> Output:
    """Any host's ARP table. A real attacker could not see this."""
    if len(args) != 1:
        raise UsageError
    host = session.network.host(args[0])
    if host is None:
        raise CommandError(f"no host named {args[0]}")
    lines = [f"{TEACHING} ARP table of {host.name} (a real attacker cannot see this):"]
    lines += [f"  {line}" for line in arp_entries(host)] or ["  (empty)"]
    return session, lines


def run_explain(session: Session, args: List[str]) -> Output:
    """The checks behind the last engine event, as numbered steps."""
    if args:
        raise UsageError
    if not session.last_events:
        return session, [f"{TEACHING} nothing to explain yet: try arpspoof or wait first"]
    event = session.last_events[-1]
    lines = [f"{TEACHING} Why: {event.text}"]
    lines += [f"{i}. {step.check}: {yes_no(step)}" for i, step in enumerate(event.trace, start=1)]
    return session, lines


register(Command("ip", "ip addr", "Show your network interfaces.", run_ip))
register(Command("arp", "arp -a", "Show your ARP cache.", run_arp))
register(Command(
    "arp-scan", "arp-scan -l", "Discover hosts on the local network.", run_arp_scan,
))
register(Command(
    "arpspoof", "arpspoof -t target host",
    "Send one forged ARP reply telling target that host's IP is at your MAC.", run_arpspoof,
))
register(Command("tcpdump", "tcpdump [-i eth0]", "Show traffic you have received.", run_tcpdump))
register(Command(
    "wait", "wait", "[sim] Let time pass so the next thing on the network happens.", run_wait,
))
register(Command(
    "show-arp", "show-arp <host-name>", f"{TEACHING} Show any host's ARP table.", run_show_arp,
))
register(Command(
    "explain", "explain", f"{TEACHING} Show the checks behind the last event.", run_explain,
))
