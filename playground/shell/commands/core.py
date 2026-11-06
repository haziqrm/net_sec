"""Core commands: help, exit."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple

from playground.shell.registry import COMMANDS, EXIT_MARKER, Command, UsageError, register

if TYPE_CHECKING:
    from playground.shell.session import Session


def run_help(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """List the commands available in this level, or show one command's usage."""
    if len(args) > 1:
        raise UsageError
    if args:
        name = args[0]
        command = COMMANDS.get(name)
        if command is None:
            return session, [f"unknown command: {name}. Type help"]
        if not session.is_allowed(name):
            return session, [f"{name}: not available in this level"]
        return session, [f"usage: {command.usage}", f"  {command.help_text}"]
    names = [name for name in sorted(COMMANDS) if session.is_allowed(name)]
    width = max(len(name) for name in names)
    lines = ["Commands:"]
    lines += [f"  {name.ljust(width)}  {COMMANDS[name].help_text}" for name in names]
    lines.append("Type 'help <command>' for usage.")
    return session, lines


def run_exit(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """Ask the CLI loop to stop by returning the exit marker."""
    if args:
        raise UsageError
    return session, [EXIT_MARKER]


register(Command("help", "help [command]", "List commands, or show how to use one.", run_help))
register(Command("exit", "exit", "Leave the shell.", run_exit))
