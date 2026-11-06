"""Tests for the shell session, registry and core commands."""

from playground.engine.scenarios import simple_lan
from playground.shell.registry import COMMANDS, EXIT_MARKER, Command
from playground.shell.session import Session


def new_session(**kwargs):
    return Session(simple_lan(), **kwargs)


def test_empty_line_returns_nothing():
    s = new_session()
    assert s.execute("") == []
    assert s.execute("   ") == []
    assert s.history == ()


def test_unknown_command_message():
    s = new_session()
    assert s.execute("nmap 10.0.0.1") == ["unknown command: nmap. Type help"]
    assert s.history == ("nmap 10.0.0.1",)


def test_hosts_command_is_gone():
    assert "hosts" not in COMMANDS
    assert new_session().execute("hosts") == ["unknown command: hosts. Type help"]


def test_help_lists_every_command():
    out = "\n".join(new_session().execute("help"))
    for name in COMMANDS:
        assert name in out
    assert COMMANDS["exit"].help_text in out


def test_help_for_one_command_shows_usage():
    assert new_session().execute("help exit")[0] == "usage: exit"


def test_bad_arguments_return_usage_and_do_not_raise():
    s = new_session()
    assert s.execute("exit now") == ["exit: usage: exit"]
    assert s.execute("help a b") == ["help: usage: help [command]"]


def test_unclosed_quote_does_not_raise():
    out = new_session().execute('help "exit')
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


def test_allowed_restricts_commands_and_help():
    s = new_session(allowed=frozenset({"ip"}))
    assert s.execute("arpspoof -t 10.0.0.5 10.0.0.1") == ["arpspoof: not available in this level"]
    assert s.execute("help arp-scan") == ["arp-scan: not available in this level"]
    listed = "\n".join(s.execute("help"))
    assert "  ip " in listed and "arp-scan" not in listed
    assert s.execute("exit") == [EXIT_MARKER]  # help and exit are always available
    assert s.network == simple_lan()


def test_step_does_not_mutate_session():
    s = new_session()
    new, _ = s.step("help")
    assert s.history == ()
    assert new.history == ("help",)
    assert new.network is s.network
