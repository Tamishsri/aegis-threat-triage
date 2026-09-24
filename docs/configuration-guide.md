# AEGIS Configuration Guide

## Custom Policies

AEGIS allows you to customize the threat detection policy without modifying source code. Policies control:

- Signal weights (how much each threat type contributes to risk)
- Strength multipliers (how evidence strength affects scoring)
- Risk thresholds (when to escalate from SUSPICIOUS to HIGH_RISK)
- Routing decisions (which signals trigger immediate HIGH_RISK classification)

### Policy File Format

Policies are stored as JSON files. Here's the structure:

```json
{
  "risk_policy": {
    "signal_weights": {
      "otp_request": 6,
      "credential_request": 6,
      "payment_request": 5,
      "refund_scam": 5,
      "prize_lottery_scam": 5,
      "manipulation_attempt": 5,
      "suspicious_instruction": 4,
      "url_embedded_credentials": 4,
      "url_ip_host": 3,
      "url_punycode": 3,
      "brand_domain_mismatch": 3,
      "account_verification": 3,
      "attachment_request": 2,
      "url_shortener": 2,
      "account_threat": 2,
      "identity_impersonation": 2,
      "unusual_subdomain": 1,
      "suspicious_url_path": 1,
      "urgency": 1
    },
    "strength_multipliers": {
      "strong": 3,
      "moderate": 2,
      "weak": 1
    },
    "suspicious_threshold": 4,
    "high_risk_threshold": 12
  },
  "routing_policy": {
    "minimum_evidence_items_to_resolve": 2,
    "decisive_signals": [
      "otp_request",
      "credential_request",
      "payment_request",
      "refund_scam",
      "prize_lottery_scam",
      "manipulation_attempt",
      "suspicious_instruction",
      "url_embedded_credentials"
    ]
  }
}
```

### Signal Weights

Each signal in `signal_weights` is a numeric value (1-10 recommended):

- **Higher weights (5-6)**: Direct harm signals like OTP/credential requests
- **Medium weights (3-4)**: Contextual signals like URL indicators or suspicious instructions
- **Lower weights (1-2)**: Weak signals like urgency or attachment requests

The actual policy points are calculated as:
```
policy_points = signal_weight × strength_multiplier × evidence_count
```

Example: `otp_request (STRONG) = 6 × 3 × 1 = 18 points`

### Strength Multipliers

Evidence strength qualifies how confident the detection is:

- **strong**: Rare false positives (3x multiplier)
- **moderate**: Some false positives expected (2x multiplier)
- **weak**: More context needed (1x multiplier)

### Thresholds

- **suspicious_threshold**: Minimum points to return SUSPICIOUS risk state (typically 4-6)
- **high_risk_threshold**: Minimum points to return HIGH_RISK state (typically 12-20)

Must satisfy: `suspicious_threshold < high_risk_threshold`

### Decisive Signals

Signals listed in `decisive_signals` immediately produce HIGH_RISK without waiting for more evidence. Use for:

- Direct credential requests (otp_request, credential_request, payment_request)
- High-confidence scam signals (refund_scam, prize_lottery_scam)
- Strong manipulation attempts

## Using Custom Policies

### Export Current Policy

Get a copy of the default policy to modify:

```powershell
python evaluation/validate_policy.py  # Show current config
```

Or programmatically:

```python
from pathlib import Path
from aegis.config.policy_loader import export_default_policy_json

export_default_policy_json(Path("my_policy.json"))
```

### Validate Custom Policy

Before using a custom policy, validate it:

```python
from pathlib import Path
from aegis.config.policy_loader import validate_policy_config

if validate_policy_config(Path("my_policy.json")):
    print("✓ Policy is valid")
else:
    print("✗ Policy has errors")
```

### Load Custom Policy

To use a custom policy in your analysis:

```python
from pathlib import Path
from aegis.config.policy_loader import load_policy_from_json
from aegis.pipeline import TextTriagePipeline
from aegis.risk_engine.engine import RiskEngine

# Load custom policy
risk_policy, routing_policy = load_policy_from_json(Path("my_policy.json"))

# Use with custom engine
engine = RiskEngine(policy=risk_policy, routing_policy=routing_policy)

# Analyze with custom policy
result = pipeline.analyze(text)  # Uses default policy
```

## Policy Customization Examples

### Conservative Policy (Fewer False Positives)

Reduce false positives by increasing thresholds and removing weak signals:

```json
{
  "risk_policy": {
    "signal_weights": {
      "otp_request": 8,
      "credential_request": 8,
      "payment_request": 6,
      "refund_scam": 6,
      "prize_lottery_scam": 6,
      "manipulation_attempt": 6,
      "suspicious_instruction": 5,
      "url_embedded_credentials": 5
    },
    "strength_multipliers": {
      "strong": 3,
      "moderate": 2,
      "weak": 1
    },
    "suspicious_threshold": 6,
    "high_risk_threshold": 18
  },
  "routing_policy": {
    "minimum_evidence_items_to_resolve": 2,
    "decisive_signals": [
      "otp_request",
      "credential_request",
      "payment_request"
    ]
  }
}
```

### Aggressive Policy (Catch More Threats)

Lower thresholds and add contextual signals to catch more potential threats:

```json
{
  "risk_policy": {
    "signal_weights": {
      "otp_request": 6,
      "credential_request": 6,
      "payment_request": 5,
      "refund_scam": 5,
      "prize_lottery_scam": 5,
      "manipulation_attempt": 5,
      "suspicious_instruction": 4,
      "url_embedded_credentials": 4,
      "account_threat": 3,
      "urgency": 3,
      "url_shortener": 3
    },
    "strength_multipliers": {
      "strong": 3,
      "moderate": 2,
      "weak": 1
    },
    "suspicious_threshold": 3,
    "high_risk_threshold": 9
  },
  "routing_policy": {
    "minimum_evidence_items_to_resolve": 1,
    "decisive_signals": [
      "otp_request",
      "credential_request",
      "payment_request",
      "refund_scam",
      "prize_lottery_scam",
      "manipulation_attempt",
      "suspicious_instruction",
      "url_embedded_credentials",
      "account_threat"
    ]
  }
}
```

## Analyzing Impact of Policy Changes

### Generate Threat Report

Analyze how your policy affects detection:

```python
from pathlib import Path
from evaluation.threat_report import generate_threat_report, print_threat_report

report = generate_threat_report(Path("predictions.jsonl"))
print_threat_report(report)
```

Output includes:
- Risk distribution (HIGH_RISK, SUSPICIOUS, LOW_RISK counts)
- Routing statistics (how many Stage 0 resolved)
- Backend usage (CPU vs NPU distribution)
- Performance metrics (latency statistics)

### Compare Policies

A/B test policy changes on held-out evaluation data:

1. Run analysis with policy A → `predictions_a.jsonl`
2. Run analysis with policy B → `predictions_b.jsonl`
3. Generate reports for both
4. Compare confusion matrices and routing rates

```powershell
python evaluation/metrics.py --input predictions_a.jsonl --positive-label SCAM --output report_a.json
python evaluation/metrics.py --input predictions_b.jsonl --positive-label SCAM --output report_b.json
```

## Best Practices

1. **Start with defaults**: Use the default policy and measure baseline performance
2. **Test incrementally**: Change one weight at a time, measure impact
3. **Validate before use**: Always run `validate_policy_config()` after editing
4. **Use held-out data**: Evaluate on data that didn't influence the policy design
5. **Document changes**: Keep notes on why you changed each weight
6. **Keep backups**: Save policy versions as you iterate
7. **Monitor false positives/negatives**: Use threat reports to identify systematic errors

## Troubleshooting

### Policy validation fails

Common issues:
- Missing required fields (check `signal_weights`)
- Invalid JSON syntax (validate with JSON linter)
- Threshold ordering wrong (`suspicious_threshold >= high_risk_threshold`)
- Decisive signal not in `signal_weights`

### Policy doesn't affect results

Confirm the policy is being loaded:
```python
risk_policy, routing = load_policy_from_json(Path("my_policy.json"))
print(risk_policy.high_risk_threshold)  # Should show your value
```

Ensure custom engine is used for analysis (current CLI uses defaults).

### Too many false positives

- Increase thresholds (higher `high_risk_threshold`)
- Reduce weights on contextual signals
- Make fewer signals "decisive"

### Too many false negatives

- Decrease thresholds (lower `high_risk_threshold`)
- Increase weights on key threat signals
- Add signals to `decisive_signals` list
