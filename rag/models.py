from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RAGResult:
    id: str
    name: str
    description: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)
