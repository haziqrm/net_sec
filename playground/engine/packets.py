"""Packet objects such as ArpPacket."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from playground.engine.state import Host

ARP_REQUEST = 1
ARP_REPLY = 2


@dataclass(frozen=True)
class ArpPacket:
    """An ARP packet (op 1 = request, 2 = reply), held purely as data."""

    op: int
    psrc: str
    hwsrc: str
    pdst: str
    hwdst: str

    def to_scapy(self) -> Any:
        """Build an equivalent scapy ARP object for display only (needs scapy)."""
        from scapy.layers.l2 import ARP  # lazy: scapy is optional

        return ARP(op=self.op, psrc=self.psrc, hwsrc=self.hwsrc, pdst=self.pdst, hwdst=self.hwdst)


def forge_reply(
    sender: Host, target: Host, claimed_ip: str, claimed_mac: Optional[str] = None
) -> ArpPacket:
    """Build an ARP reply telling ``target`` that ``claimed_ip`` is at ``claimed_mac``.

    ``claimed_mac`` defaults to the sender's own MAC (the classic spoof).
    """
    return ArpPacket(
        op=ARP_REPLY,
        psrc=claimed_ip,
        hwsrc=claimed_mac if claimed_mac is not None else sender.mac,
        pdst=target.ip,
        hwdst=target.mac,
    )
