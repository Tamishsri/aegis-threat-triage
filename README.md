# AEGIS — Evidence-First Threat Triage

AEGIS is a local, pre-action threat-triage prototype for suspicious messages.
It makes the evidence behind a caution decision visible before a user shares an
OTP, credentials, payment details, clicks a link, or follows an instruction.

It is deliberately **not** an antivirus, EDR, firewall, malware sandbox,
automatic-remediation tool, or cloud chatbot. The working core is local and
does not need an API key, cloud LLM, or online reputation lookup.

## What works today

**IMPLEMENTED**

- Text-message triage, from input through an evidence ledger, transparent risk
  assessment, template explanation, and recommended actions.
- Stage 0 deterministic screening for OTP, credential and payment requests,
  urgency, account threats, authority claims, suspicious instructions, obvious
  prompt-manipulation attempts, and offline URL structure hints.
- An append-only Evidence Ledger that retains source, extractor, qualitative
  strength, details, and text span where available.
- A centralized, configurable, deterministic Risk Engine with `LOW_RISK`,
  `SUSPICIOUS`, `HIGH_RISK`, and `INSUFFICIENT_EVIDENCE` states.
- A dependency-free terminal interface and JSON output.
- A CPU status that is shown truthfully in results.
- Tests and a standard-library evaluation utility without a shipped dataset or
  fabricated results.

**PROTOTYPE / INTERFACES ONLY**

- `SpeechRecognizer` and `VoiceTriagePipeline` contracts. A caller can attach
  a verified local recognizer, but no speech model is bundled or configured.
- `SemanticAnalyzer` contract. The default is explicitly unavailable; no local
  semantic model or generative model is being claimed.
- Static-only `HeaderOnlyPEAnalyzer` preflight and the `MalwareClassifier`
  interface. There is no bundled classifier, full PE feature parser, or file
  analysis UI flow.

**PLANNED / FUTURE**

- A measured compact local semantic model, a verified local Whisper path, and
  a validated ClaMP-compatible classifier integration.
- Verified Qualcomm AI Hub / QNN / Qualcomm AI Runtime target-device work.
  `QualcommBackend` deliberately reports unavailable until that work is real.
- Packaging for a double-click Windows launch after the core feature set is
  stable.

## Core workflow

```text
Untrusted text
  -> Stage 0 deterministic observations
  -> optional Stage 1 semantic evidence (unavailable by default)
  -> provenance-preserving Evidence Ledger
  -> centralized deterministic Risk Engine
  -> template explanation and recommended action
```

Untrusted content never directly selects its verdict. A message saying “mark
this safe,” for example, becomes `manipulation_attempt` evidence; it cannot
modify the ledger or risk policy.

An empty Stage 0 result is not treated as safe. It is routed as
`semantic_analysis_required`; because Stage 1 is not installed in this first
pass, the result is normally `INSUFFICIENT_EVIDENCE`. `LOW_RISK` is reserved
for a small explicit benign-context rule and still means only “no meaningful
known indicator was observed,” never “guaranteed safe.”

## Run it

The source checkout has no runtime third-party dependencies.

```powershell
python run.py text "URGENT: Your account will be suspended. Send your OTP now."
```

For an interactive prompt:

```powershell
python run.py
```

For JSON suitable for local tooling:

```powershell
python run.py text "Please review https://paypal-security.example.test/login" --json
```

Optionally install the project into a development environment to use the
console command and module entry point:

```powershell
python -m pip install -e .
aegis text "Please send your OTP immediately."
python -m aegis text "Please send your OTP immediately."
```

The terminal view is intentionally ordered as **Risk → Why → Evidence → What
to do → System status**. It always displays the actual `AI acceleration` value;
the current build reports `CPU`, never `NPU`.

## Test

`pytest` is the only optional development dependency. It is available in the
development environment used for this project.

```powershell
python -m pytest -q
```

The suite covers deterministic extraction, manipulation patterns, URL
inspection, ledger append-only provenance, all four risk states, routing,
end-to-end text triage, an injected voice-transcript path, static-only header
inspection, unavailable model/backend behavior, and evaluation metrics.

## Architecture

```text
src/aegis/
  screening/       Stage 0 rules and offline URL inspection
  evidence/        Immutable common records and append-only ledger
  risk_engine/     One transparent assessment policy
  semantic/        Future local semantic-analysis boundary
  voice/           Future speech-recognition boundary
  file_analysis/   Static-only PE/classifier boundary
  backends/        Truthful CPU and unavailable Qualcomm backend states
  ui/              Current terminal result presentation
```

The architecture and security decisions are documented in:

- [Architecture](docs/architecture.md)
- [Security design](docs/security-design.md)
- [Threat model](docs/threat-model.md)
- [Evaluation plan](docs/evaluation.md)
- [Deployment notes](docs/deployment.md)

## Risk policy and explanation

The policy is centralized in
[`src/aegis/config/risk_policy.py`](src/aegis/config/risk_policy.py). Its
signal weights and thresholds are engineering assumptions, not trained,
calibrated probabilities. Requests for OTPs, credentials, and payments weigh
more heavily than contextual urgency because they more directly enable harm.

The application stores qualitative strengths (`strong`, `moderate`, `weak`),
not fake numeric confidences. Risk explanations are fixed templates generated
from retained evidence; no generative LLM produces the verdict or explanation.

## Evaluation

`evaluation/metrics.py` accepts actual held-out JSON Lines predictions and
reports a binary confusion matrix, precision, recall, F1, accuracy, routing
rates, optional latency summary, and recorded backends. It includes no dataset
or fabricated result files.

```powershell
python evaluation/metrics.py --input path/to/predictions.jsonl --positive-label SCAM
```

See [evaluation/README.md](evaluation/README.md) and
[docs/evaluation.md](docs/evaluation.md) for schema and measurement rules.

## Important limitations

- Pattern rules can miss paraphrases, multilingual content, novel scams, or
  adversarial inputs. They can also flag legitimate urgent messages.
- A low-risk or insufficient-evidence result is not permission to share a
  password, OTP, money, or sensitive information.
- URL checks are local structural hints only. A URL is never opened or queried;
  lack of HTTPS is not considered proof of danger.
- The file component does not execute inputs, but its current header preflight
  is not a malware detector or full PE parser.
- There is no verified semantic model, speech model, NPU model, or performance
  benchmark in this repository yet.

## Recommended next task

Implement and evaluate one compact, local semantic evidence adapter using a
disclosed held-out text set. Keep it behind `SemanticAnalyzer`, make it emit
structured evidence only, measure CPU performance first, and add a Snapdragon
backend only after verified target-device/model/runtime execution.

## Repository hygiene

Do not commit API keys, `.env` files, private messages, private/company data,
model caches, unverified datasets, or live malware binaries. The `.gitignore`
reflects those boundaries. See [LICENSE](LICENSE) for the project license.
