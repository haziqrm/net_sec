"""Tests for the ARP Level 1 shell commands and the terminal loop."""

import pytest

from playground.engine.scenarios import (
    ATTACKER_IP, ATTACKER_MAC, GATEWAY_IP, GATEWAY_MAC, VICTIM_IP, VICTIM_MAC,
)
from playground.shell.cli import LOGIN_PAYLOAD, PROMPT, build_session, repl
from playground.shell.registry import EXIT_MARKER

SPOOF = f"arpspoof -t {VICTIM_IP} {GATEWAY_IP}"


def test_ip_addr_shows_attacker_interface():
    out = build_session().execute("ip addr")
    assert any(line.startswith("2: eth0:") for line in out)
    assert f"    link/ether {ATTACKER_MAC} brd ff:ff:ff:ff:ff:ff" in out
    assert f"    inet {ATTACKER_IP}/24 brd 10.0.0.255 scope global eth0" in out


def test_arp_a_shows_own_cache_in_real_format():
    s = build_session()
    assert s.execute("arp -a") == []  # the attacker has learned nothing yet
    s.attacker = "victim"  # look through the victim's eyes to check the format
    assert s.execute("arp -a") == [f"? ({GATEWAY_IP}) at {GATEWAY_MAC} [ether] on eth0"]


def test_arp_scan_lists_other_hosts_and_changes_nothing():
    s = build_session()
    before = s.network
    out = s.execute("arp-scan -l")
    assert s.execute("arp-scan --localnet") == out
    text = "\n".join(out)
    assert f"{GATEWAY_IP}\t{GATEWAY_MAC}" in text
    assert f"{VICTIM_IP}\t{VICTIM_MAC}" in text
    assert f"{ATTACKER_IP}\t" not in text
    assert out[-1].endswith("2 responded")
    assert s.network is before


def test_arpspoof_poisons_victim():
    s = build_session()
    out = s.execute(SPOOF)
    assert out[0] == f"{ATTACKER_MAC} {VICTIM_MAC} 0806 42: arp reply {GATEWAY_IP} is-at {ATTACKER_MAC}"
    assert out[1].startswith("[sim] victim accepts reply")
    assert len(out) == 2
    assert f"  ? ({GATEWAY_IP}) at {ATTACKER_MAC} [ether] on eth0" in s.execute("show-arp victim")


def test_attack_then_wait_then_tcpdump_shows_login():
    s = build_session()
    assert s.execute("tcpdump") == ["listening on eth0, no packets captured yet"]
    s.execute(SPOOF)
    assert s.execute("wait")[0].startswith("[sim] attacker intercepted")
    assert f"IP {VICTIM_IP} > {GATEWAY_IP}: {LOGIN_PAYLOAD}" in s.execute("tcpdump")


def test_wait_runs_each_scheduled_action_once():
    s = build_session()
    assert s.execute("wait")[0].startswith("[sim] victim -> gateway")
    assert s.execute("wait") == ["nothing happens"]


def test_defence_rejects_spoof_and_explain_shows_reject():
    s = build_session(defence=True)
    out = s.execute(SPOOF)
    assert out[1].startswith("[sim] victim rejects reply")

    s.execute("arp-scan -l")  # a read-only command must not hide the last event
    explain = s.execute("explain")
    assert explain[0].startswith("[teaching view] Why: victim rejects reply")
    assert explain[1:] == [
        "1. packet is an ARP reply (op=2): yes",
        f"2. {GATEWAY_IP} has a static (locked) entry: yes",
        f"3. claimed MAC {ATTACKER_MAC} equals locked MAC {GATEWAY_MAC}: NO",
        "4. decision: REJECT",
    ]

    assert s.execute("wait")[0].startswith("[sim] victim -> gateway")
    assert s.execute("tcpdump") == ["listening on eth0, no packets captured yet"]


def test_locked_entries_show_as_perm():
    out = build_session(defence=True).execute("show-arp victim")
    assert out[0].startswith("[teaching view]")
    assert f"  ? ({GATEWAY_IP}) at {GATEWAY_MAC} [ether] PERM on eth0" in out


def test_explain_before_any_event():
    assert "nothing to explain yet" in build_session().execute("explain")[0]


@pytest.mark.parametrize(
    "line, expected",
    [
        ("arpspoof -t 10.0.0.77 10.0.0.1", "arpspoof: no host with address 10.0.0.77"),
        ("arpspoof -t 10.0.0.5 10.0.0.77", "arpspoof: no host with address 10.0.0.77"),
        ("arpspoof -t 10.0.0.5 not-an-ip", "arpspoof: invalid address: not-an-ip"),
        ("arpspoof -t 10.0.0.5", "arpspoof: usage: arpspoof -t target host"),
        ("arpspoof 10.0.0.5 10.0.0.1", "arpspoof: usage: arpspoof -t target host"),
        ("arpspoof", "arpspoof: usage: arpspoof -t target host"),
        ("arp", "arp: usage: arp -a"),
        ("arp-scan", "arp-scan: usage: arp-scan -l"),
        ("ip", "ip: usage: ip addr"),
        ("show-arp", "show-arp: usage: show-arp <host-name>"),
        ("show-arp bob", "show-arp: no host named bob"),
        ("tcpdump -i wlan0", "tcpdump: usage: tcpdump [-i eth0]"),
        ("wait now", "wait: usage: wait"),
        ("explain this", "explain: usage: explain"),
        ("nmap -sn 10.0.0.0/24", "unknown command: nmap. Type help"),
    ],
)
def test_bad_input_gives_a_message_and_does_not_raise(line, expected):
    s = build_session()
    assert s.execute(line) == [expected]
    assert s.network == build_session().network  # nothing changed


def test_level_can_restrict_commands():
    s = build_session()
    s.allowed = frozenset({"arp-scan", "arpspoof"})
    assert s.execute("show-arp victim") == ["show-arp: not available in this level"]
    assert s.execute(SPOOF)[1].startswith("[sim]")


def test_repl_runs_lines_and_stops_on_exit():
    lines = iter(["arp-scan -l", SPOOF, "exit", "never reached"])
    prompts, written = [], []

    def read(prompt):
        prompts.append(prompt)
        return next(lines)

    final = repl(build_session(), read=read, write=written.append)
    assert final.history == ("arp-scan -l", SPOOF, "exit")
    assert set(prompts) == {PROMPT} and PROMPT == "attacker# "
    assert any(w.startswith("[sim] victim accepts") for w in written)
    assert EXIT_MARKER not in written


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_repl_stops_on_ctrl_d_and_ctrl_c(error):
    def read(prompt):
        raise error

    written = []
    repl(build_session(), read=read, write=written.append)
    assert written == [""]
