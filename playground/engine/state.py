"""Immutable network state: Host, Captured, Network."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping, Optional


@dataclass(frozen=True)
class Host:
    """A machine on the simulated LAN with its own ARP cache."""

    name: str
    ip: str
    mac: str
    arp_table: Mapping[str, str] = field(default_factory=dict)
    static_entries: Mapping[str, str] = field(default_factory=dict)

    def with_arp(self, ip: str, mac: str) -> Host:
        """Return a copy with ``ip -> mac`` set in the ARP table."""
        return replace(self, arp_table={**self.arp_table, ip: mac})

    def with_static(self, ip: str, mac: str) -> Host:
        """Return a copy with a locked ``ip -> mac`` entry (static and in the table)."""
        return replace(
            self,
            arp_table={**self.arp_table, ip: mac},
            static_entries={**self.static_entries, ip: mac},
        )


@dataclass(frozen=True)
class Captured:
    """Traffic that ended up at a host it was not meant for."""

    by: str
    src: str
    dest_ip: str
    payload: str


@dataclass(frozen=True)
class Network:
    """The whole simulated network at one moment in time."""

    hosts: Mapping[str, Host]
    captured: tuple[Captured, ...] = ()
    clock: int = 0
    seed: int = 0

    def host(self, name: str) -> Optional[Host]:
        """Look up a host by name."""
        return self.hosts.get(name)

    def host_by_ip(self, ip: str) -> Optional[Host]:
        """Look up a host by its IP address."""
        return next((h for h in self.hosts.values() if h.ip == ip), None)

    def host_by_mac(self, mac: str) -> Optional[Host]:
        """Look up a host by its MAC address."""
        return next((h for h in self.hosts.values() if h.mac == mac), None)

    def with_host(self, host: Host) -> Network:
        """Return a copy with ``host`` added or replaced (keyed by name)."""
        return replace(self, hosts={**self.hosts, host.name: host})

    def with_captured(self, item: Captured) -> Network:
        """Return a copy with ``item`` appended to the captured log."""
        return replace(self, captured=(*self.captured, item))
