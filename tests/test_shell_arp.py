"""Tests for the ARP Level 1 shell commands and the terminal loop."""

import pytest

from playground.engine.scenarios import (
    ATTACKER_IP, ATTACKER_MAC, GATEWAY_IP, GATEWAY_MAC, VICTIM_IP, VICTIM_MAC,
)
from playground.shell.cli import LOGIN_PAYLOAD, PROMPT, build_session, repl
from playground.shell.registry import EXIT_MARKER

SPOOF = f"arpspoof -t {VICTIM_IP} --mac {ATTACKER_MAC} {GATEWAY_IP}"
USAGE = "usage: arpspoof -t <target-ip> --mac <mac> <host-ip>"


def test_ip_addr_shows_attacker_ip_and_mac():
    assert build_session().execute("ip addr") == [f"eth0  ip {ATTACKER_IP}  mac {ATTACKER_MAC}"]


def test_arp_scan_lists_other_hosts_and_changes_nothing():
    s = build_session()
    before = s.network
    assert s.execute("arp-scan -l") == [
        f"{GATEWAY_IP}  {GATEWAY_MAC}",
        f"{VICTIM_IP}  {VICTIM_MAC}",
        "2 hosts found",
    ]
    assert s.network is before


def test_arpspoof_with_attacker_mac_poisons_victim():
    s = build_session()
    out = s.execute(SPOOF)
    assert out == [
        f"sent: {GATEWAY_IP} is at {ATTACKER_MAC}",
        f"[sim] victim accepts reply: {GATEWAY_IP} is now at {ATTACKER_MAC}",
    ]
    assert s.execute("show-arp victim") == ["[teaching view]", f"{GATEWAY_IP} -> {ATTACKER_MAC}"]


def test_arpspoof_with_gateway_mac_leaves_table_correct():
    s = build_session()
    s.execute(f"arpspoof -t {VICTIM_IP} --mac {GATEWAY_MAC} {GATEWAY_IP}")
    assert s.execute("show-arp victim") == ["[teaching view]", f"{GATEWAY_IP} -> {GATEWAY_MAC}"]
    s.execute("wait")
    assert s.execute("tcpdump") == ["no packets captured"]


def test_arpspoof_accepts_options_in_any_order_and_upper_case_mac():
    s = build_session()
    out = s.execute(f"arpspoof --mac {ATTACKER_MAC.upper()} {GATEWAY_IP} -t {VICTIM_IP}")
    assert out[0] == f"sent: {GATEWAY_IP} is at {ATTACKER_MAC}"


def test_attack_then_wait_then_tcpdump_shows_login():
    s = build_session()
    assert s.execute("tcpdump") == ["no packets captured"]
    s.execute(SPOOF)
    assert s.execute("wait")[0].startswith("[sim] attacker intercepted")
    assert s.execute("tcpdump") == [f"{VICTIM_IP} -> {GATEWAY_IP}: {LOGIN_PAYLOAD}"]


def test_wait_runs_each_scheduled_action_once():
    s = build_session()
    assert s.execute("wait")[0].startswith("[sim] victim -> gateway")
    assert s.execute("wait") == ["nothing happens"]


def test_defence_rejects_spoof_and_explain_ends_with_reject():
    s = build_session(defence=True)
    assert s.execute("show-arp victim") == ["[teaching view]", f"{GATEWAY_IP} -> {GATEWAY_MAC} (locked)"]
    assert s.execute(SPOOF)[1].startswith("[sim] victim rejects reply")

    s.execute("arp-scan -l")  # a command without events must not hide the last one
    explain = s.execute("explain")
    assert explain[0] == "[teaching view]"
    assert explain[1].startswith("victim rejects reply")
    assert explain[2:] == [
        "1. packet is an ARP reply (op=2): yes",
        f"2. {GATEWAY_IP} has a static (locked) entry: yes",
        f"3. claimed MAC {ATTACKER_MAC} equals locked MAC {GATEWAY_MAC}: no",
        "4. decision: REJECT",
    ]

    assert s.execute("wait")[0].startswith("[sim] victim -> gateway")
    assert s.execute("tcpdump") == ["no packets captured"]


def test_show_arp_empty_table():
    assert build_session().execute("show-arp attacker") == ["[teaching view]", "(empty)"]


def test_explain_before_any_event():
    assert build_session().execute("explain") == ["nothing to explain yet"]


@pytest.mark.parametrize(
    "line, expected",
    [
        ("arpspoof", USAGE),
        (f"arpspoof -t {VICTIM_IP} {GATEWAY_IP}", USAGE),
        (f"arpspoof -t {VICTIM_IP} --mac {ATTACKER_MAC}", USAGE),
        (f"arpspoof --mac {ATTACKER_MAC} {GATEWAY_IP}", USAGE),
        (f"arpspoof -t {VICTIM_IP} --mac", USAGE),
        (f"{SPOOF} extra", USAGE),
        (f"arpspoof -t 10.0.0.77 --mac {ATTACKER_MAC} {GATEWAY_IP}", "no host with address 10.0.0.77"),
        (f"arpspoof -t {VICTIM_IP} --mac {ATTACKER_MAC} 10.0.0.77", "no host with address 10.0.0.77"),
        (f"arpspoof -t {VICTIM_IP} --mac nonsense {GATEWAY_IP}", "invalid mac address nonsense"),
        ("ip", "usage: ip addr"),
        ("arp-scan", "usage: arp-scan -l"),
        ("show-arp", "usage: show-arp <host-name>"),
        ("show-arp bob", "no host named bob"),
        ("tcpdump -i eth0", "usage: tcpdump"),
        ("wait now", "usage: wait"),
        ("explain this", "usage: explain"),
        ("arp -a", "unknown command: arp. Type help"),
        ("nmap -sn 10.0.0.0/24", "unknown command: nmap. Type help"),
    ],
)
def test_bad_input_prints_one_line_and_does_not_raise(line, expected):
    s = build_session()
    assert s.execute(line) == [expected]
    assert s.network == build_session().network  # nothing changed


def test_level_can_restrict_commands():
    s = build_session()
    s.allowed = frozenset({"arp-scan", "arpspoof"})
    assert s.execute("show-arp victim") == ["show-arp: not available in this level"]
    assert s.execute(SPOOF)[0].startswith("sent:")


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
