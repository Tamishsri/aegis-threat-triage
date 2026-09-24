from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.evidence import Evidence, EvidenceConflictError, EvidenceLedger, EvidenceSource, EvidenceStrength


def _evidence() -> Evidence:
    return Evidence(
        source=EvidenceSource.TEXT,
        signal="manipulation_attempt",
        strength=EvidenceStrength.STRONG,
        extractor="deterministic_screening",
        details="Attempt to override a verdict detected.",
        span=(0, 10),
    )


def test_ledger_is_append_only_and_preserves_upstream_evidence() -> None:
    upstream = _evidence()
    ledger = EvidenceLedger([upstream])

    with pytest.raises(EvidenceConflictError, match="cannot be overwritten"):
        ledger.add(replace(upstream, details="A downstream component tried to erase this."))
    with pytest.raises(EvidenceConflictError, match="append-only"):
        ledger.replace(upstream)

    assert ledger.items == (upstream,)
    assert ledger.get(upstream.id) == upstream


def test_exact_duplicate_is_idempotent_but_not_rewritten() -> None:
    item = _evidence()
    ledger = EvidenceLedger()

    assert ledger.add(item) == item
    assert ledger.add(item) == item
    assert len(ledger) == 1


def test_evidence_rejects_invalid_span() -> None:
    with pytest.raises(ValueError, match="span"):
        Evidence(
            source=EvidenceSource.TEXT,
            signal="urgency",
            strength=EvidenceStrength.WEAK,
            extractor="test",
            details="invalid span",
            span=(3, 2),
        )
