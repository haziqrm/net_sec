"""Shell session: holds the simulated network and turns typed lines into output."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, fields, replace
from typing import List, Tuple

import playground.shell.commands  # noqa: F401  (registers the commands)
from playground.engine.actions import Action
from playground.engine.events import Event
from playground.engine.state import Network
from playground.shell.registry import COMMANDS, UsageError


@dataclass
class Session:
    """The student's shell: current network, who they are, and what has happened.

    Every field holds an immutable value. Commands never change a session; they
    return a new one built with ``dataclasses.replace``. ``step`` is pure;
    ``execute`` is the one place that adopts the new values, for the CLI loop.
    """

    network: Network
    attacker: str = "attacker"
    scheduled: Tuple[Action, ...] = ()
    history: Tuple[str, ...] = ()
    last_events: Tuple[Event, ...] = ()

    def step(self, line: str) -> Tuple[Session, List[str]]:
        """Run one typed line and return the new session and output, without mutating."""
        try:
            words = shlex.split(line)
        except ValueError as exc:  # e.g. an unclosed quote
            return replace(self, history=(*self.history, line)), [f"could not parse line: {exc}"]
        if not words:
            return self, []

        base = replace(self, history=(*self.history, line), last_events=())
        name, args = words[0], words[1:]
        command = COMMANDS.get(name)
        if command is None:
            return base, [f"unknown command: {name}. Type help"]
        try:
            return command.run(base, args)
        except UsageError:
            return base, [f"usage: {command.usage}"]
        except ValueError as exc:  # engine rejects bad input, e.g. an unknown host
            return base, [f"error: {exc}"]

    def execute(self, line: str) -> List[str]:
        """Run one typed line, adopt the resulting session, and return output lines."""
        new, output = self.step(line)
        for f in fields(self):
            setattr(self, f.name, getattr(new, f.name))
        return output
