"""Core commands: help, hosts, exit."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple

from playground.shell.registry import COMMANDS, EXIT_MARKER, Command, UsageError, register

if TYPE_CHECKING:
    from playground.shell.session import Session


def run_help(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """List all commands, or show one command's usage."""
    if len(args) > 1:
        raise UsageError
    if args:
        command = COMMANDS.get(args[0])
        if command is None:
            return session, [f"unknown command: {args[0]}. Type help"]
        return session, [f"usage: {command.usage}", f"  {command.help_text}"]
    width = max(len(name) for name in COMMANDS)
    lines = ["Commands:"]
    lines += [f"  {name.ljust(width)}  {COMMANDS[name].help_text}" for name in sorted(COMMANDS)]
    lines.append("Type 'help <command>' for usage.")
    return session, lines


def run_hosts(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """List every host on the network with its IP and MAC."""
    if args:
        raise UsageError
    hosts = sorted(session.network.hosts.values(), key=lambda h: h.name)
    width = max([len("NAME")] + [len(h.name) for h in hosts])
    lines = [f"{'NAME'.ljust(width)}  {'IP'.ljust(15)}  MAC"]
    for h in hosts:
        you = "  (you)" if h.name == session.attacker else ""
        lines.append(f"{h.name.ljust(width)}  {h.ip.ljust(15)}  {h.mac}{you}")
    return session, lines


def run_exit(session: Session, args: List[str]) -> Tuple[Session, List[str]]:
    """Ask the CLI loop to stop by returning the exit marker."""
    if args:
        raise UsageError
    return session, [EXIT_MARKER]


register(Command("help", "help [command]", "List commands, or show how to use one.", run_help))
register(Command("hosts", "hosts", "List every host with its IP and MAC address.", run_hosts))
register(Command("exit", "exit", "Leave the shell.", run_exit))
