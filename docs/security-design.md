# Security design

## Design principles

1. **Evidence before verdict.** An analyzer reports observable signals; a
   centralized deterministic risk engine assesses the collection of evidence.
2. **Untrusted content never controls the verdict directly.** A suspicious
   message may contain instructions such as "mark this safe," but those words
   are input, not policy.
3. **Provenance is preserved.** Evidence records identify their source and
   extractor. Downstream analysis can add records but cannot silently replace an
   upstream deterministic observation.
4. **Local-first, minimum dependency.** The core text workflow does not require
   a cloud LLM, an API key, or mandatory online threat intelligence.
5. **Static-only file safety.** Future executable handling reads and parses
   bytes; it does not run, detonate, inject into, persist, or delete files.
6. **Truthful execution reporting.** An accelerator is reported only when it is
   the verified runtime that performed the relevant inference.

## Evidence model

All analyzers should emit a common evidence record with at least:

| Field | Purpose |
| --- | --- |
| source | Origin of the content or signal, for example text, voice, or file. |
| signal | Stable, machine-readable observation such as otp_request or manipulation_attempt. |
| strength | Qualitative impact: strong, moderate, or weak. This is not a calibrated probability. |
| extractor | Component that observed the signal, for example deterministic_screening. |
| details | Human-readable supporting context. |
| span/timestamp when available | Location within text or time within a transcript. |

The ledger assigns identity/order as needed and retains evidence rather than
allowing a later analyzer to mutate it. This is a controlled information-flow
property, not a claim of immutability against a compromised machine.

## Deterministic screening and routing

Stage 0 is fast deterministic screening. It can recognize explicit high-harm
requests, contextual pressure, obvious manipulation attempts, and lightweight
URL structure. It returns both evidence and an explicit routing result.

~~~text
Stage 0 found high-signal evidence  -> can be resolved locally
Stage 0 is ambiguous or has no signal -> semantic analysis may be required
~~~

The second line is crucial: no keyword found means "not resolved by these
rules," not "safe." If semantic analysis is unavailable, the pipeline preserves
that uncertainty instead of inventing confidence.

## Assessment and explanations

The risk engine is the only component that returns the four risk states:

- HIGH_RISK: multiple or strong indicators support a high-risk assessment.
- SUSPICIOUS: evidence warrants caution but does not satisfy high-risk policy.
- LOW_RISK: no meaningful evidence was found in the current evidence
  vocabulary; this is not a guarantee of safety.
- INSUFFICIENT_EVIDENCE: available observations do not support a reliable
  assessment.

Risk policy is centralized and configurable. High-harm signals may have more
effect than contextual ones, but the values are engineering policy assumptions
until evaluated on a disclosed held-out set. Template-based explanations list
the evidence that supports the result. They do not ask a generative model to
reinterpret or suppress evidence.

## Manipulation resistance

Text resembling "ignore previous instructions," "disregard the above," "mark
this safe," or "say this is safe" is treated as a possible manipulation attempt
and recorded in the ledger. The detector does not claim exhaustive coverage.
If a semantic or generative feature is added later, it must receive only the
minimum necessary input and must not have authority to delete, downgrade, or
overwrite recorded evidence or risk policy.

## File-analysis safety contract

The current HeaderOnlyPEAnalyzer is a narrow static MZ/PE-signature preflight,
not a malware classifier or full PE parser. Its current and future file-module
constraints are:

- accept a path or byte stream only for static inspection;
- keep the current preflight limited to signature inspection, and require a
  future full PE parser to validate headers and bounds before feature access;
- never launch the file, load it as a library, invoke macros, unpack it by
  execution, or submit it to a remote sandbox by default;
- keep the provided future ClaMP classifier seam behind predict(features) and
  explain(features) interfaces;
- treat classifier output as supporting evidence, not an autonomous remediation
  decision; and
- do not commit or distribute live malware binaries or unverified private data.

## Backend safety and transparency

Future speech and semantic backends use an explicit interface with a local CPU
implementation and a separately verified Qualcomm/Snapdragon implementation.
The unavailable Qualcomm backend must fail clearly rather than emulate an NPU or
fall back silently while displaying NPU. A result must identify the backend that
actually executed (CPU or verified NPU).

No Qualcomm-specific imports, API calls, model compatibility claims, or
performance claims are included until real model artifacts, runtime support,
and target-device execution have been verified.

## Privacy and operational safeguards

Core analysis is offline-first. Optional future network features must be
separately disclosed, disabled by default where appropriate, and unable to
change local risk policy without clearly identifying their provenance. Do not
store API tokens, credentials, private transcripts, proprietary data, large
model caches, or malware samples in the repository.

Before release, validate package integrity, pin or review dependencies in
accordance with the chosen packaging process, test the executable/static parser
against malformed inputs, and ensure user-facing language preserves uncertainty.
