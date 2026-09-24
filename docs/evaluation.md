# Evaluation plan

## Status

This repository contains an evaluation **framework**, not a benchmark result.
No claimed accuracy, latency, memory use, CPU-versus-NPU comparison, model
quality, or hardware acceleration result exists until it is measured with the
documented inputs and protocol below. Do not infer performance from the
presence of this framework.

The standard-library metric tool is at evaluation/metrics.py. It consumes real,
held-out predictions supplied by the evaluator and prints reproducible summary
statistics. It intentionally ships with no fabricated result file or dataset.

## Evaluation questions

AEGIS should eventually be evaluated along four dimensions:

1. **Detection quality:** Does the system appropriately distinguish benign,
   scam, and ambiguous inputs, and identify relevant evidence categories?
2. **Routing:** How often does Stage 0 resolve an input, and how often does it
   invoke Stage 1?
3. **Performance:** What are model-inference latency, end-to-end latency, memory
   use where measurable, and actual execution backend?
4. **Hardware:** Under comparable conditions, what changes between CPU-only and
   verified NPU execution?

Evaluation must separately identify the input type: text, voice transcript, or
static file. Metrics from one input type must not be represented as results for
another.

## Labels and data governance

For text and voice, use an explicit label vocabulary such as:

| Label | Meaning |
| --- | --- |
| BENIGN | The example is not labeled as a scam or other target threat in the evaluation policy. |
| SCAM | The example is labeled as a target social-engineering threat under the disclosed rubric. |
| AMBIGUOUS | Available information does not support a reliable class assignment. |

A small prototype set is not representative of real-world threat prevalence.
Keep examples, sources, annotation policy, splits, and any exclusions documented
with each experiment. Do not label data by looking at the system's prediction.
Do not include private messages without appropriate permission, credentials, API
tokens, company data, or live malware binaries.

For a binary metric run, choose and state one positive label, such as SCAM for
text/voice or MALICIOUS for a malware classifier. The metric script validates
that expected and predicted labels are present and does not silently discard
invalid rows.

## Reproducible prediction format

Create a JSON Lines file outside version control or in an approved,
redistributable evaluation-data location. Each line represents one held-out
example after analysis:

    {"id":"text-001","expected":"SCAM","predicted":"SCAM","stage_0_resolved":true,"stage_1_invoked":false,"backend":"CPU","end_to_end_ms":12.4}
    {"id":"text-002","expected":"BENIGN","predicted":"AMBIGUOUS","stage_0_resolved":false,"stage_1_invoked":true,"backend":"CPU","end_to_end_ms":15.8}

The lines above show a schema only; they are not an AEGIS result set and must
not be reported as one. The required fields for the metric tool are expected
and predicted. The optional routing fields are stage_0_resolved and
stage_1_invoked.

Run a binary summary with a chosen positive label:

    python evaluation/metrics.py --input path/to/predictions.jsonl --positive-label SCAM

For static malware-classifier results, use the same schema and a suitable
positive label:

    python evaluation/metrics.py --input path/to/clamp_heldout_predictions.jsonl --positive-label MALICIOUS

The tool prints JSON containing TP, TN, FP, FN, precision, recall, F1, accuracy,
label counts, and routing rates when the routing fields are present. Use
--output to save an exact JSON artifact for a particular run:

    python evaluation/metrics.py --input path/to/predictions.jsonl --positive-label SCAM --output path/to/result.json

Store the exact command, code revision, Python version, OS, device, backend,
model/artifact identifier, data split, and timing protocol alongside any
published result.

## Metric definitions

For the declared positive label:

| Metric | Definition |
| --- | --- |
| TP | Expected positive and predicted positive. |
| TN | Expected non-positive and predicted non-positive. |
| FP | Expected non-positive and predicted positive. |
| FN | Expected positive and predicted non-positive. |
| Precision | TP / (TP + FP), or 0 when no positive predictions exist. |
| Recall | TP / (TP + FN), or 0 when no expected positives exist. |
| F1 | Harmonic mean of precision and recall, or 0 when both are 0. |
| Accuracy | (TP + TN) / total evaluated rows. |
| Stage 0 resolution rate | Resolved Stage 0 rows / rows with a routing value. |
| Stage 1 escalation rate | Stage 1 invoked rows / rows with a routing value. |

The script reports rates using only rows that actually contain the relevant
boolean field. This prevents missing routing instrumentation from being treated
as a negative result.

For multiclass reporting, include a confusion matrix and one-vs-rest metrics per
class in a later extension or external analysis. Do not collapse AMBIGUOUS into
BENIGN without disclosing that policy.

## Measurement protocol

### Detection

- Freeze the policy, model, and code revision before evaluating.
- Use a held-out split not used to tune rules, exemplars, thresholds, or model
  parameters.
- Report sample count, class distribution, annotation policy, source
  restrictions, and both false positives and false negatives.
- Inspect evidence-category performance separately when labels support it.
- Treat results as limited to the disclosed population and time period.

### Routing

- Record stage_0_resolved and stage_1_invoked for every analyzed example.
- Report both rates with their denominators.
- Do not curate the test set to force a desired routing percentage.
- For voice, record transcription cost separately: adaptive routing does not
  eliminate the fixed transcription step.

### Performance

- Define end-to-end timing boundaries before recording results. A useful
  boundary starts when local input is handed to AEGIS and ends when the result
  payload is ready.
- Record Stage 0, Stage 1 (if applicable), transcription (if applicable), and
  total latency separately.
- Record warm-up policy, number of runs, summary statistic, input-size range,
  memory method, OS, Python version, device, power mode, and backend.
- Do not describe CPU inference as NPU inference.

### CPU versus NPU

Compare only equivalent model artifacts or clearly disclose any difference.
Keep the input set, preprocessing, batch size, warm-up behavior, timing method,
power mode, and device configuration as comparable as possible. Record the
runtime that actually executed the model. Until verified Qualcomm integration
exists, there is no NPU baseline to publish.

## Malware-classifier evaluation

A future ClaMP-based classifier should be evaluated only on held-out,
redistribution-permitted feature data. The evaluation artifact should identify
the feature-extraction version, split, class definition, classifier version,
and whether any samples were excluded. Report the binary confusion matrix,
precision, recall, F1, TP, TN, FP, and FN.

Never execute samples to obtain these metrics, and do not commit live malware
binaries. Static feature vectors or non-sensitive derived artifacts may be used
only when their licensing and redistribution terms permit it.

