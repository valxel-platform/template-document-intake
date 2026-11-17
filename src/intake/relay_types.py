"""An event on its way to Kafka (outbox rows)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Outgoing:
    topic: str
    key: str
    value: dict[str, Any]
    headers: dict[str, str]


@dataclass(frozen=True)
class Queued:
    id: int
    topic: str
    key: str
    value: dict[str, Any]
    headers: dict[str, str]
