"""Tests for the shell session, registry and core commands."""

from playground.engine.scenarios import simple_lan
from playground.shell.registry import COMMANDS, EXIT_MARKER, Command
from playground.shell.session import Session


def new_session():
    return Session(simple_lan())


def test_empty_line_returns_nothing():
    s = new_session()
    assert s.execute("") == []
    assert s.execute("   ") == []
    assert s.history == ()


def test_unknown_command_message():
    s = new_session()
    assert s.execute("nmap 10.0.0.1") == ["unknown command: nmap. Type help"]
    assert s.history == ("nmap 10.0.0.1",)


def test_help_lists_every_command():
    out = "\n".join(new_session().execute("help"))
    for name in ("help", "hosts", "exit"):
        assert name in out
    assert COMMANDS["hosts"].help_text in out


def test_help_for_one_command_shows_usage():
    out = new_session().execute("help hosts")
    assert out[0] == "usage: hosts"


def test_hosts_lists_names_ips_and_macs():
    out = new_session().execute("hosts")
    text = "\n".join(out)
    for host in simple_lan().hosts.values():
        assert host.name in text and host.ip in text and host.mac in text
    assert len(out) == 1 + len(simple_lan().hosts)
    assert "(you)" in next(line for line in out if line.startswith("attacker"))


def test_bad_arguments_return_usage_and_do_not_raise():
    s = new_session()
    assert s.execute("hosts extra") == ["usage: hosts"]
    assert s.execute("help a b") == ["usage: help [command]"]
    assert s.execute("exit now") == ["usage: exit"]


def test_unclosed_quote_does_not_raise():
    out = new_session().execute('help "hosts')
    assert len(out) == 1 and out[0].startswith("could not parse line")


def test_quoted_arguments_parse_correctly(monkeypatch):
    def echo(session, args):
        return session, [repr(args)]

    monkeypatch.setitem(COMMANDS, "echo", Command("echo", "echo [words...]", "Echo.", echo))
    out = new_session().execute("echo \"hello world\" 'a b' plain")
    assert out == [repr(["hello world", "a b", "plain"])]


def test_quoted_argument_stays_one_word_for_help():
    assert new_session().execute('help "no such"') == ["unknown command: no such. Type help"]


def test_exit_returns_marker():
    assert new_session().execute("exit") == [EXIT_MARKER]


def test_step_does_not_mutate_session():
    s = new_session()
    new, _ = s.step("hosts")
    assert s.history == ()
    assert new.history == ("hosts",)
    assert new.network is s.network
