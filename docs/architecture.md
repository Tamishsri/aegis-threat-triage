# AEGIS architecture

## Purpose and boundary

AEGIS is a local, evidence-first application for **pre-action** threat triage.
It helps a person inspect suspicious content before they disclose a credential,
share an OTP, send money, follow an instruction, or open a file. It is not an
antivirus product, EDR, firewall, malware sandbox, or automated-remediation
tool.

The first working path is text triage. Voice, semantic inference, static
executable analysis, and Snapdragon acceleration are deliberately isolated so
they can be added without changing the decision model.

## Decision flow

~~~text
untrusted input
    |
    v
input-specific handler
    |
    v
Stage 0: deterministic screening -----------+
    |                                        |
    | resolved / needs semantic context      | evidence items
    v                                        v
Stage 1: local semantic analysis (optional; planned) --> Evidence Ledger
                                                           |
                                                           v
                                                centralized Risk Engine
                                                           |
                                                           v
                                              template explanation + action
~~~

The decision engine consumes structured evidence, not raw untrusted prose and
not a generative-model verdict. A later semantic model may add evidence, but it
cannot silently erase evidence already recorded by deterministic screening.

## Implemented first-pass path

The text path is implemented as a small, dependency-light package:

| Concern | Primary location | Current responsibility |
| --- | --- | --- |
| CLI entry point | src/aegis/__main__.py | Accept text and render a local result. |
| Orchestration | src/aegis/pipeline.py | Runs Stage 0, records evidence, evaluates risk, and builds the response. |
| Stage 0 | src/aegis/screening/deterministic.py | Detects explicit social-engineering and manipulation signals. |
| Evidence | src/aegis/evidence/ledger.py | Stores common, provenance-preserving evidence records. |
| Assessment | src/aegis/risk_engine/engine.py | Applies centralized, deterministic policy to evidence. |

The exact public data structures are defined in code and are the source of
truth. The important architectural contracts are:

- An evidence item includes a source, signal, strength, extractor, and details;
  a text span is retained when available.
- Strength is qualitative (strong, moderate, or weak), rather than an
  uncalibrated numeric confidence.
- Stage 0 reports whether it resolved the input. An absence of matching rules
  does **not** mean the content is safe.
- The pipeline exposes stage_0_resolved and stage_1_invoked so routing can
  later be measured rather than assumed.
- The risk engine has exactly four outcomes: LOW_RISK, SUSPICIOUS, HIGH_RISK,
  and INSUFFICIENT_EVIDENCE.

LOW_RISK means no meaningful evidence was found in AEGIS's current evidence
vocabulary. It never means guaranteed safe.

## Evidence and assessment separation

Stage 0 produces observations such as an OTP request, credential request,
payment request, urgency, account-threat language, impersonation, suspicious
instructions, manipulation attempts, and lightweight URL anomalies. These are
observations, not a verdict. The ledger preserves their origin before the risk
engine applies the assessment policy.

The initial risk weights are transparent engineering assumptions, not learned
or calibrated probabilities. High-harm requests (credentials, OTPs, and
payments) can outweigh contextual signals such as urgency because accepting
them can directly enable account takeover or fraud. The policy belongs in one
central configuration rather than being duplicated among detectors.

Explanations are template-based and cite the evidence that drove the result.
This keeps the explanation consistent with the assessment and avoids presenting
a fluent generated answer as a security authority.

## Inputs and status

| Input | Current status | Design boundary |
| --- | --- | --- |
| Text / message | **IMPLEMENTED** | Deterministic Stage 0, ledger, transparent risk result, template explanation. |
| Voice recording | **PROTOTYPE / UNAVAILABLE BY DEFAULT** | SpeechRecognizer and VoiceTriagePipeline contracts exist, including a caller-supplied local adapter, but no speech model is bundled or configured. Whisper transcription remains a fixed input cost. |
| Semantic analysis | **PROTOTYPE / UNAVAILABLE BY DEFAULT** | The Stage 1 SemanticAnalyzer contract exists, but no verified local semantic model is installed. A future model emits evidence only; it never owns the verdict. |
| Executable file | **PROTOTYPE** | HeaderOnlyPEAnalyzer performs a static MZ/PE-signature preflight and a MalwareClassifier interface exists. There is no bundled classifier or file-analysis CLI flow. Submitted files must never execute. |
| Snapdragon backend | **UNAVAILABLE** | Future verified target-device/model/runtime integration only; no Qualcomm API or NPU execution is claimed today. |

## Execution placement

The architecture is designed so that CPU and accelerator responsibilities stay
honest and visible:

| CPU / local application | Future verified Snapdragon NPU candidate |
| --- | --- |
| Current: UI and CLI, orchestration, deterministic screening, URL inspection, evidence ledger, risk engine, explanation templates, and header-only PE preflight. Future full PE parsing, static feature extraction, and the supporting malware classifier remain CPU responsibilities. | Speech recognition and compact semantic inference |

The UI and result payload must expose the actual backend. A CPU run says
AI acceleration: CPU; it must never display NPU merely because an NPU-capable
machine is present. Until a specific model, runtime, artifact, and target device
have been verified end-to-end, the Snapdragon backend remains unavailable.

## Extension rules

Future adapters should obey the existing data boundary rather than bypass it:

1. An input adapter produces a transcript, static features, or other
   input-specific observation.
2. An analyzer emits common evidence records with provenance.
3. The ledger appends and preserves those records.
4. The centralized risk engine makes the assessment.
5. The explanation layer renders that assessment and its supporting evidence.

This makes a future CPU implementation and an NPU implementation interchangeable
at the inference boundary while keeping security policy auditable and stable.
