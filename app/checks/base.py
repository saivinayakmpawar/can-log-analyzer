"""Check plugin interface.

A check receives every frame that matches a DBC message (decoded when decoding
succeeded) and may emit findings and/or contribute result sections. To add a new
diagnostic, subclass :class:`Check`, implement ``on_frame``/``finish`` and add it
to the list built in ``app.analyzer.build_checks``. The core loop does not change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..findings import FindingSink

Key = tuple[int, bool]  # (frame id, is_extended)


@dataclass
class Frame:
    idx: int
    t: float
    key: Key
    msg: Any  # cantools Message
    data: bytes
    values: dict[str, float] | None  # None when decoding failed


@dataclass
class FinishContext:
    last_t: float
    total_frames: int
    db: Any
    sections: dict[str, Any] = field(default_factory=dict)


class Check:
    name = "check"

    def on_frame(self, frame: Frame, sink: FindingSink) -> None:  # pragma: no cover - interface
        pass

    def finish(self, ctx: FinishContext, sink: FindingSink) -> None:  # pragma: no cover - interface
        pass
