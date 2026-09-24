"""Append-only, provenance-preserving evidence ledger."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from aegis.evidence.models import Evidence


class EvidenceConflictError(ValueError):
    """Raised when an analyzer tries to reuse an evidence ID with new content."""


class EvidenceLedger:
    """A small append-only ledger.

    Evidence is immutable and can be added, never silently replaced or removed.
    This explicitly prevents downstream components from erasing deterministic
    observations such as prompt-manipulation evidence.
    """

    def __init__(self, evidence: Iterable[Evidence] = ()) -> None:
        self._items: list[Evidence] = []
        self._by_id: dict[str, Evidence] = {}
        self.extend(evidence)

    def add(self, item: Evidence) -> Evidence:
        existing = self._by_id.get(item.id)
        if existing is not None:
            if existing != item:
                raise EvidenceConflictError(
                    f"Evidence ID {item.id!r} already exists and cannot be overwritten."
                )
            return existing
        self._items.append(item)
        self._by_id[item.id] = item
        return item

    def extend(self, evidence: Iterable[Evidence]) -> None:
        for item in evidence:
            self.add(item)

    def replace(self, item: Evidence) -> None:
        """Always reject replacement; preserved evidence must remain reviewable."""

        raise EvidenceConflictError(
            "EvidenceLedger is append-only; replacement would erase provenance."
        )

    @property
    def items(self) -> tuple[Evidence, ...]:
        """Return an immutable ordered snapshot of all retained evidence."""

        return tuple(self._items)

    def __iter__(self) -> Iterator[Evidence]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def get(self, evidence_id: str) -> Evidence | None:
        return self._by_id.get(evidence_id)
