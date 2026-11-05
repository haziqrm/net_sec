"""Goals as conditions on network state."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from playground.engine.state import Network


def arp_poisoned(net: Network, victim: str, ip: str, attacker: str) -> bool:
    """True if ``victim`` maps ``ip`` to the attacker's MAC."""
    v, a = net.host(victim), net.host(attacker)
    return v is not None and a is not None and v.arp_table.get(ip) == a.mac


def traffic_captured(net: Network, attacker: str, src: Optional[str] = None) -> bool:
    """True if ``attacker`` has captured any traffic (from ``src``, if given)."""
    return any(c.by == attacker and (src is None or c.src == src) for c in net.captured)


GOALS: Mapping[str, Callable[..., bool]] = {
    "arp_poisoned": arp_poisoned,
    "traffic_captured": traffic_captured,
}


def check_goal(net: Network, spec: Mapping[str, Any]) -> bool:
    """Evaluate a goal spec such as ``{"type": "traffic_captured", "attacker": "attacker"}``."""
    kind = spec.get("type")
    if kind not in GOALS:
        raise ValueError(f"unknown goal type: {kind!r}")
    params = {k: v for k, v in spec.items() if k != "type"}
    return GOALS[kind](net, **params)
