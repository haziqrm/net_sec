"""Tests for the ARP shell commands and the terminal loop."""

import pytest

from playground.engine.scenarios import ATTACKER_MAC, GATEWAY_IP, GATEWAY_MAC
from playground.shell.cli import LOGIN_PAYLOAD, build_session, repl


def run_lines(session, *lines):
    """Execute each line and return the output of the last one."""
    out = []
    for line in lines:
        out = session.execute(line)
    return out


def test_arp_a_defaults_to_attacker_table():
    out = build_session().execute("arp -a")
    assert out == ["ARP table of attacker:", "  (empty)"]


def test_arpspoof_changes_victim_entry():
    s = build_session()
    before = s.execute("arp -a victim")
    assert f"  {GATEWAY_IP} at {GATEWAY_MAC}" in before

    out = s.execute(f"arpspoof victim {GATEWAY_IP}")
    assert [line.split("]")[0] for line in out] == ["[sent", "[accepted"]

    after = s.execute("arp -a victim")
    assert f"  {GATEWAY_IP} at {ATTACKER_MAC}" in after


def test_attack_captures_login():
    s = build_session()
    s.execute(f"arpspoof victim {GATEWAY_IP}")
    wait_out = s.execute("wait")
    assert wait_out[0].startswith("[intercepted]")
    assert s.execute("captured") == [f"from victim to {GATEWAY_IP}: {LOGIN_PAYLOAD}"]


def test_wait_runs_each_scheduled_action_once():
    s = build_session()
    assert s.execute("wait")[0].startswith("[delivered]")
    assert s.execute("wait") == ["nothing happens"]


def test_captured_starts_empty():
    assert build_session().execute("captured") == ["nothing captured yet"]


def test_defence_rejects_spoof_and_explain_shows_reject():
    s = build_session(defence=True)
    assert f"  {GATEWAY_IP} at {GATEWAY_MAC} (static)" in s.execute("arp -a victim")

    out = s.execute(f"arpspoof victim {GATEWAY_IP}")
    assert out[-1].startswith("[rejected]")

    s.execute("arp -a")  # a command without events must not hide the last ones
    explain = s.execute("explain")
    assert explain[0].startswith("Why: victim rejects reply")
    assert explain[1:] == [
        "1. packet is an ARP reply (op=2): yes",
        f"2. {GATEWAY_IP} has a static (locked) entry: yes",
        f"3. claimed MAC {ATTACKER_MAC} equals locked MAC {GATEWAY_MAC}: no",
        "4. decision: REJECT",
    ]

    assert s.execute("wait")[0].startswith("[delivered]")
    assert s.execute("captured") == ["nothing captured yet"]


def test_explain_before_any_event():
    assert build_session().execute("explain")[0].startswith("nothing to explain yet")


@pytest.mark.parametrize(
    "line, reason",
    [
        ("arpspoof bob 10.0.0.1", "unknown host: bob"),
        ("arpspoof victim 10.0.0.999", "not a valid IPv4 address"),
        ("arpspoof victim not-an-ip", "not a valid IPv4 address"),
        ("arpspoof victim", None),
        ("arpspoof", None),
        ("arp -a bob", "unknown host: bob"),
        ("arp", None),
        ("arp -x", None),
        ("wait now", None),
        ("captured all", None),
        ("explain this", None),
    ],
)
def test_bad_arguments_return_usage(line, reason):
    s = build_session()
    out = s.execute(line)
    assert out[-1].startswith("usage: ")
    if reason:
        assert out[0].startswith(reason)
    assert s.network == build_session().network  # nothing changed


def test_repl_runs_lines_and_stops_on_exit():
    lines = iter(["hosts", f"arpspoof victim {GATEWAY_IP}", "exit", "never reached"])
    written = []
    final = repl(build_session(), read=lambda prompt: next(lines), write=written.append)
    assert final.history == ("hosts", f"arpspoof victim {GATEWAY_IP}", "exit")
    assert any(w.startswith("[accepted]") for w in written)
    assert "<<exit>>" not in written


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_repl_stops_on_ctrl_d_and_ctrl_c(error):
    def read(prompt):
        raise error

    written = []
    repl(build_session(), read=read, write=written.append)
    assert written == [""]
