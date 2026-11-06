"""Terminal loop for the simulated shell, and the starting session it uses."""

from __future__ import annotations

from typing import Callable, List

from playground.engine.actions import SendTraffic, SetStaticEntry
from playground.engine.engine import apply
from playground.engine.scenarios import GATEWAY_IP, GATEWAY_MAC, simple_lan
from playground.shell.registry import EXIT_MARKER
from playground.shell.session import Session

PROMPT = "attacker# "
LOGIN_PAYLOAD = "POST /login user=alice"


def build_session(defence: bool = False) -> Session:
    """simple_lan() with the victim's login scheduled; optionally lock the gateway entry first."""
    network = simple_lan()
    if defence:
        network, _ = apply(network, SetStaticEntry(host="victim", ip=GATEWAY_IP, mac=GATEWAY_MAC))
    scheduled = (SendTraffic(sender="victim", dest_ip=GATEWAY_IP, payload=LOGIN_PAYLOAD),)
    return Session(network, scheduled=scheduled)


def banner(defence: bool) -> List[str]:
    """Lines shown when the shell starts."""
    lines = ["This is a simulation: nothing touches your real network. Type help for commands."]
    if defence:
        lines.append("Defence on: the victim has a locked ARP entry for the gateway.")
    return lines


def repl(
    session: Session,
    read: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
) -> Session:
    """Read lines, run them, print output; stop on exit, end of input or Ctrl-C."""
    while True:
        try:
            line = read(PROMPT)
        except (EOFError, KeyboardInterrupt):
            write("")
            return session
        output = session.execute(line)
        for out in output:
            if out != EXIT_MARKER:
                write(out)
        if EXIT_MARKER in output:
            return session
