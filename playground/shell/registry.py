"""Command registry: each shell command as data plus a pure run function."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Tuple

if TYPE_CHECKING:
    from playground.shell.session import Session

# Output line a command returns to ask the CLI loop to stop.
EXIT_MARKER = "<<exit>>"

RunFn = Callable[["Session", List[str]], Tuple["Session", List[str]]]


class UsageError(Exception):
    """Raised by a command when its arguments are wrong; the shell shows its usage.

    An optional message (e.g. "unknown host: bob") is shown before the usage line.
    """


@dataclass(frozen=True)
class Command:
    """A shell command: its name, usage line, one-line help and run function."""

    name: str
    usage: str
    help_text: str
    run: RunFn


COMMANDS: Dict[str, Command] = {}


def register(command: Command) -> Command:
    """Add ``command`` to the registry (replacing any with the same name) and return it."""
    COMMANDS[command.name] = command
    return command
