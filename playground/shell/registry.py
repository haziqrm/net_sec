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
    """Raised when a command's arguments are wrong; shown as ``usage: <usage>``."""


class CommandError(Exception):
    """Raised for a specific problem; its message is shown as one line."""


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
