# AEGIS Evaluation Guide

This guide explains how to evaluate AEGIS on real or synthetic text datasets and report reproducible results.

## Key principles

1. **No fabricated datasets.** Use real messages or messages similar in structure/complexity to real messages.
2. **Transparent labeling.** Disclose your annotation rubric and any disagreement handling (e.g., majority vote).
3. **Fair comparison.** Compare only on the same held-out split. Do not use data that tuned any AEGIS parameters.
4. **Separate metrics by input type.** Keep text, voice, and file results distinct.
5. **Report the real backend.** A CPU run is CPU; a NPU run is NPU. Do not conflate them.

## Label mapping

AEGIS emits four risk states. Map them to your classification task as follows:

| AEGIS State | Meaning | Common eval label | Guidance |
| --- | --- | --- | --- |
| HIGH_RISK | Strong or combined indicators exceeded the high-risk policy threshold. | SCAM, MALICIOUS, PHISHING | Strongly recommend not following the content or request. |
| SUSPICIOUS | Evidence warrants caution but did not satisfy the high-risk threshold. | SUSPICIOUS, POTENTIALLY_SCAM | Recommend verification before acting. |
| LOW_RISK | No meaningful evidence was found; this is not a safety guarantee. | BENIGN, LEGITIMATE | No warning indicators detected in AEGIS's evidence vocabulary. |
| INSUFFICIENT_EVIDENCE | Available evidence does not support a confident assessment. | UNKNOWN, AMBIGUOUS | Semantic analysis is recommended but not available. |

### Mapping for binary classification

For a binary classification task (e.g., SCAM vs. BENIGN):

| AEGIS State | Prediction |
| --- | --- |
| HIGH_RISK | SCAM |
| SUSPICIOUS | SCAM (conservative) or UNKNOWN (lenient) |
| LOW_RISK | BENIGN |
| INSUFFICIENT_EVIDENCE | UNKNOWN or treat as false negative if ground truth is SCAM |

## Evaluation workflow

### 1. Prepare your dataset

Create a JSON Lines file with one evaluation record per line. Each record must include:

- `expected`: ground-truth label (string, non-empty)
- `predicted`: AEGIS risk state or your chosen label mapping (string, non-empty)

Optional fields:

- `stage_0_resolved`: boolean; whether Stage 0 deterministic screening resolved the message
- `stage_1_invoked`: boolean; whether semantic analysis was requested
- `end_to_end_ms`: non-negative finite number; total latency in milliseconds
- `backend`: string; actual execution backend (e.g., "CPU" or verified "NPU")
- `id`: optional identifier for tracking individual predictions

Example valid record:

```json
{"expected":"SCAM","predicted":"HIGH_RISK","stage_0_resolved":true,"stage_1_invoked":false,"end_to_end_ms":12.4,"backend":"CPU","id":"msg-001"}
```

### 2. Collect predictions

Run AEGIS on each message in your held-out dataset. Record the returned `state` and metadata.

Example script (pseudocode):

```python
from aegis.pipeline import TextTriagePipeline
import json
import time

pipeline = TextTriagePipeline()
predictions = []

for message_id, text, label in held_out_messages:
    start = time.perf_counter()
    result = pipeline.analyze(text)
    elapsed = (time.perf_counter() - start) * 1000  # convert to ms
    
    predictions.append({
        "id": message_id,
        "expected": label,
        "predicted": result.assessment.state.value,
        "stage_0_resolved": result.screening.resolved,
        "stage_1_invoked": result.stage_1_invoked,
        "end_to_end_ms": elapsed,
        "backend": result.execution_backend,
    })

with open("predictions.jsonl", "w") as f:
    for pred in predictions:
        f.write(json.dumps(pred) + "\n")
```

### 3. Run evaluation

Run the metrics script to compute binary metrics for your chosen positive label:

```bash
python evaluation/metrics.py \
    --input path/to/predictions.jsonl \
    --positive-label SCAM
```

This produces precision, recall, F1, accuracy, confusion matrix, routing rates, and optional latency summary.

### 4. Save and report

Optionally save the report to a file:

```bash
python evaluation/metrics.py \
    --input path/to/predictions.jsonl \
    --positive-label SCAM \
    --output path/to/report.json
```

## Example evaluation

### Sample data

See `example_dataset.jsonl` for a minimal example. Do **not** use this for actual evaluation; it is a format illustration only.

### Running the example

```bash
python evaluation/metrics.py \
    --input evaluation/example_dataset.jsonl \
    --positive-label SCAM
```

Output:

```json
{
  "schema_version": 1,
  "records": 5,
  "positive_label": "SCAM",
  "confusion_matrix": {
    "tp": 2,
    "tn": 1,
    "fp": 1,
    "fn": 1
  },
  "metrics": {
    "precision": 0.666...,
    "recall": 0.666...,
    "f1": 0.666...,
    "accuracy": 0.6
  },
  ...
}
```

## Reporting checklist

Before publishing or submitting results:

- [ ] Ground truth is disclosed or sourced from a published dataset.
- [ ] Annotation rubric or labeling criteria are clearly described.
- [ ] Data split is held-out and did not influence any AEGIS parameters.
- [ ] Text, voice, and file results are reported separately.
- [ ] Latency is measured from the same pipeline code under consistent conditions.
- [ ] AI backend is truthfully reported (CPU, not falsely labeled as NPU).
- [ ] Confusion matrix and individual metric values (TP, TN, FP, FN, precision, recall, F1) are all reported.
- [ ] Optional: routing rates (Stage 0 resolved %, Stage 1 requested %) are included.
- [ ] Optional: mean/median latency and backend distribution are included.
- [ ] No fabricated or synthetic dataset is claimed to be real.
- [ ] Limitations and sources of error (false positives, missed attacks, adversarial evasion) are acknowledged.

## Common pitfalls

1. **Using tuned data.** Do not evaluate on the same split used to design screening rules. Always use a held-out set.
2. **Conflating INSUFFICIENT_EVIDENCE with benign.** These are distinct. Do not automatically map INSUFFICIENT_EVIDENCE to BENIGN.
3. **Misreporting backends.** A CPU model is not NPU execution. Report truthfully.
4. **Silently filtering or skipping records.** Include every record, even malformed ones (they should cause an error).
5. **Omitting disagreement handling.** If using multiple human annotators, disclose the agreement threshold and tie-breaking rule.
6. **Not separating input types.** Text, voice, and file analyses may have different performance; report them distinctly.

## Next steps

After evaluation:

- Document the results alongside the methodology and dataset provenance.
- If semantic analysis or other backends are added, re-evaluate on the same held-out split to measure the impact.
- Publish the evaluation on an internal wiki, documentation site, or research venue so that future iterations can be compared fairly.
