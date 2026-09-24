# Evaluation framework

This directory provides a small, reproducible evaluation utility. It contains no
benchmark dataset and no claimed AEGIS results. Add measurements only after
running the actual application on a documented held-out set.

The tool uses only the Python standard library:

    python evaluation/metrics.py --help

## Input format

Provide one JSON object per line. Every non-blank line must contain:

- expected: the ground-truth label
- predicted: the AEGIS or classifier label

Optional fields support routing and performance summaries:

- stage_0_resolved: JSON boolean
- stage_1_invoked: JSON boolean
- end_to_end_ms: non-negative finite number
- backend: a non-empty string such as CPU or verified NPU
- id: optional experiment identifier retained by the data owner but not used by
  the metric calculation

Schema example only:

    {"id":"example-001","expected":"SCAM","predicted":"SCAM","stage_0_resolved":true,"stage_1_invoked":false,"end_to_end_ms":12.4,"backend":"CPU"}

The example is a format illustration, not a performance result. It must not be
included in a reported evaluation set unless it is genuinely collected and
labeled under the experiment's policy.

## Run a binary metric summary

Choose the exact label to treat as positive. For text or voice evaluation:

    python evaluation/metrics.py --input path/to/predictions.jsonl --positive-label SCAM

For held-out ClaMP-classifier data:

    python evaluation/metrics.py --input path/to/clamp_predictions.jsonl --positive-label MALICIOUS

The report includes:

- TP, TN, FP, and FN
- precision, recall, F1, and accuracy
- expected and predicted label counts
- Stage 0 resolution and Stage 1 escalation rates, when those booleans are
  present
- mean, median, minimum, and maximum latency, when the latency field is present
- observed backend counts, when backend is present

The binary counts are one-vs-rest: every label other than the selected positive
label is treated as non-positive for that run. Preserve the original multiclass
labels in the report and disclose any aggregation policy.

Save the same deterministic report to a file:

    python evaluation/metrics.py --input path/to/predictions.jsonl --positive-label SCAM --output path/to/report.json

Custom field names are supported through --expected-key, --predicted-key,
--stage-0-key, --stage-1-key, --latency-key, and --backend-key. The tool rejects
invalid JSON, missing labels, malformed booleans, and invalid latency values
rather than silently changing the denominator.

## Evaluation hygiene

- Use a held-out split that did not tune rules, thresholds, exemplars, or model
  parameters.
- Record dataset source, annotation rubric, class distribution, split process,
  code revision, Python version, OS, device, model/artifact identifier,
  execution backend, warm-up policy, and timing boundaries.
- Keep text, voice, and static-file results separate unless a combined metric is
  explicitly justified.
- Do not turn no-match results into a benign label by default; preserve
  INSUFFICIENT_EVIDENCE where the product returns it.
- Do not commit private conversations, credentials, proprietary data, unverified
  redistributable datasets, large model caches, or live malware binaries.
- Do not call CPU runs NPU runs. A CPU-versus-NPU comparison requires verified
  execution on both backends under comparable conditions.

See ../docs/evaluation.md for the full evaluation protocol and
../docs/threat-model.md for handling boundaries.

## Additional tools

### validate_policy.py

Display and validate the current risk policy configuration:

```powershell
python evaluation/validate_policy.py
```

Shows:
- Signal weights and their point contributions at each strength level
- Policy thresholds (SUSPICIOUS and HIGH_RISK)
- Strength multipliers (strong, moderate, weak)
- Routing policy configuration
- Example calculations for common threat combinations
- Policy validation (checks for consistency issues)

Useful for:
- Understanding how signals contribute to risk states
- Validating custom policy modifications
- Explaining routing decisions in reports

### analyze_misclassifications.py

Analyze false positives and false negatives from predictions:

```powershell
python evaluation/analyze_misclassifications.py --input path/to/predictions.jsonl
```

Produces:
- False positive count with examples
- False negative count with examples
- Confusion matrix showing all label transitions

Save to JSON:

```powershell
python evaluation/analyze_misclassifications.py --input predictions.jsonl --output analysis.json
```

Useful for:
- Identifying systematic failure modes
- Finding patterns in misclassifications
- Iterating on policy adjustments
- Understanding which signals are under/over-weighted
