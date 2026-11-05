"""Everything a student can do, as plain data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union


@dataclass(frozen=True)
class ForgeArpReply:
    """Send a forged ARP reply claiming ``claimed_ip`` is at ``claimed_mac``."""

    sender: str
    target: str
    claimed_ip: str
    claimed_mac: Optional[str] = None


@dataclass(frozen=True)
class SendTraffic:
    """Send a payload from ``sender`` to ``dest_ip``."""

    sender: str
    dest_ip: str
    payload: str


@dataclass(frozen=True)
class SetStaticEntry:
    """Lock an ``ip -> mac`` entry in ``host``'s ARP table (the defence)."""

    host: str
    ip: str
    mac: str


Action = Union[ForgeArpReply, SendTraffic, SetStaticEntry]
