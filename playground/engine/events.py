"""Events and the trace of checks behind each one."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union


@dataclass(frozen=True)
class Step:
    """One check the engine made, and its outcome."""

    check: str
    result: Union[bool, str]


@dataclass(frozen=True)
class Event:
    """Something that happened, with the checks that led to it."""

    kind: str
    text: str
    host: Optional[str] = None
    trace: tuple[Step, ...] = ()
