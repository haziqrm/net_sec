"""Guards the promise that the shell never touches the real system.

Every .py file under playground/shell is parsed (not imported) and checked for
imports or uses of subprocess, os.system, socket, ctypes and open().
"""

import ast
from pathlib import Path
from typing import List

SHELL_DIR = Path(__file__).resolve().parents[1] / "playground" / "shell"
BANNED_MODULES = {"subprocess", "socket", "ctypes"}


def violations(source: str) -> List[str]:
    """Return a description of every banned import or call in ``source``."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in BANNED_MODULES:
                    found.append(f"line {node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in BANNED_MODULES:
                found.append(f"line {node.lineno}: from {node.module} import ...")
            if module == "os" and any(a.name == "system" for a in node.names):
                found.append(f"line {node.lineno}: from os import system")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "system":
                found.append(f"line {node.lineno}: os.system")
            if isinstance(node.value, ast.Name) and node.value.id in BANNED_MODULES:
                found.append(f"line {node.lineno}: {node.value.id}.{node.attr}")
        elif isinstance(node, ast.Name) and node.id == "open":
            found.append(f"line {node.lineno}: open")
    return found


def shell_files() -> List[Path]:
    return sorted(SHELL_DIR.rglob("*.py"))


def test_scanner_finds_shell_files():
    names = {p.name for p in shell_files()}
    assert {"session.py", "registry.py", "core.py"} <= names


def test_scanner_catches_each_banned_use():
    bad = [
        "import subprocess",
        "import socket",
        "import ctypes.util",
        "from subprocess import run",
        "from os import system",
        "import os\nos.system('ls')",
        "open('x')",
        "f = open",
    ]
    for source in bad:
        assert violations(source), source
    assert violations("import shlex\nfrom os import path") == []


def test_shell_never_touches_the_real_system():
    problems = {
        str(path.relative_to(SHELL_DIR)): found
        for path in shell_files()
        if (found := violations(path.read_text(encoding="utf-8")))
    }
    assert problems == {}
