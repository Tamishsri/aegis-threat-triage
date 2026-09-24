# AEGIS CLI Reference

Complete reference for running AEGIS from the command line.

## Installation

The first time:

```powershell
python -m pip install -e .
```

Or without installation:

```powershell
python run.py --help
```

## Entry points

The installed `aegis` command:

```powershell
aegis --help
```

Or via Python module:

```powershell
python -m aegis --help
```

Or via the convenience launcher (development):

```powershell
python run.py --help
```

All three are equivalent.

## Commands

### Interactive mode

Launch an interactive prompt:

```powershell
python -m aegis
```

You will see:

```
AEGIS - Evidence-First Threat Triage
Paste one message for local analysis, then press Enter.
> 
```

Paste or type a message and press Enter. The result will be printed to the terminal.

### Text analysis (non-interactive)

Analyze a single message directly:

```powershell
python -m aegis text "URGENT: Your account will be suspended. Send your OTP now."
```

Output:

```
AEGIS - Evidence-First Threat Triage
============================================
RISK: HIGH RISK

WHY
This content is high risk because it includes an OTP request, urgency language, and account-threat language.

EVIDENCE
- Otp Request - Strong
  A request to provide a one-time verification code was detected. [deterministic_screening]
- Urgency - Moderate
  Urgency language was detected. [deterministic_screening]
- Account Threat - Moderate
  Language threatening an account consequence was detected. [deterministic_screening]

WHAT TO DO
- Do not respond, click links, open attachments, or continue the requested action.
- Do not share passwords, credentials, or one-time verification codes.
- Verify through an official channel you locate independently.

SYSTEM STATUS
- Local analysis: enabled
- Network: Offline
- AI acceleration: CPU
- Stage 0 resolved: yes (decisive_deterministic_evidence)
- Stage 1 requested: no
- Stage 1 invoked: no
- Semantic analysis: not requested
```

### JSON output

For programmatic use, request JSON instead:

```powershell
python -m aegis text "Send me your password" --json
```

Output:

```json
{
  "evidence": [
    {
      "details": "A request to provide login credentials was detected.",
      "extractor": "deterministic_screening",
      "id": "...",
      "observed_at": "2026-09-24T...",
      "signal": "credential_request",
      "source": "text",
      "span": [
        8,
        28
      ],
      "strength": "strong"
    }
  ],
  "explanation": {
    "recommended_actions": [
      "Do not respond, click links, open attachments, or continue the requested action.",
      "Do not share passwords, credentials, or one-time verification codes.",
      "Verify through an official channel you locate independently."
    ],
    "summary": "This content is high risk because it includes a credential request."
  },
  "network": "Offline",
  "risk": {
    "contributions": [
      {
        "evidence_id": "...",
        "policy_points": 18,
        "signal": "credential_request"
      }
    ],
    "policy_total": 18,
    "rationale": "Strong or combined indicators reached the high-risk policy threshold.",
    "state": "HIGH_RISK"
  },
  "routing": {
    "semantic_status": "not requested",
    "stage_0_reason": "decisive_deterministic_evidence",
    "stage_0_resolved": true,
    "stage_1_invoked": false,
    "stage_1_requested": false
  },
  "source": "text",
  "system": {
    "ai_acceleration": "CPU",
    "local_analysis": true,
    "network": "Offline"
  }
}
```

### Reading from stdin

Pipe text directly:

```powershell
"Verify your account now" | python -m aegis text --stdin
```

Or from a file:

```powershell
Get-Content message.txt | python -m aegis text --stdin
```

Or in PowerShell:

```powershell
python -m aegis text --stdin < message.txt
```

## Output format explanation

### Terminal output

The terminal view is intentionally ordered:

1. **RISK** - The assessment state (LOW_RISK, SUSPICIOUS, HIGH_RISK, INSUFFICIENT_EVIDENCE).
2. **WHY** - A summary of why this risk state was assigned.
3. **EVIDENCE** - The signals that were observed, their strength, and extractor.
4. **WHAT TO DO** - Recommended actions based on the assessment.
5. **SYSTEM STATUS** - Metadata about how the result was computed (backend, stages, network).

All evidence items are preserved and shown; downstream components cannot hide upstream observations.

### JSON output structure

The JSON output is structured as:

- `source` - input source ("text", "voice", or "file")
- `routing` - Stage 0 and Stage 1 routing metadata
  - `stage_0_resolved` - whether Stage 0 deterministic screening resolved the input
  - `stage_0_reason` - reason for routing (e.g., "decisive_deterministic_evidence")
  - `stage_1_requested` - whether semantic analysis was requested
  - `stage_1_invoked` - whether semantic analysis was actually performed
  - `semantic_status` - availability/result of semantic backend
- `risk` - the risk assessment
  - `state` - one of LOW_RISK, SUSPICIOUS, HIGH_RISK, INSUFFICIENT_EVIDENCE
  - `rationale` - explanation of the policy decision
  - `policy_total` - sum of policy points from scored evidence
  - `contributions` - list of evidence items that contributed to the score
- `explanation` - the human-readable result
  - `summary` - the main caution message
  - `recommended_actions` - list of actions to take
- `evidence` - complete list of all evidence items (JSON representation of Evidence objects)
- `system` - actual runtime status
  - `local_analysis` - whether core analysis was local (always true for core text)
  - `network` - network status (Offline for local text analysis)
  - `ai_acceleration` - actual backend used (CPU or verified NPU, never mislabeled)

## Risk states explained

### HIGH_RISK

Strong or combined indicators reached the high-risk policy threshold. Examples:

- An explicit OTP request combined with urgency
- An explicit credential request
- A manipulation attempt combined with other signals
- An explicit payment request
- Refund/lottery scam language combined with action requests

Recommended action: **Do not follow the request. Verify independently.**

### SUSPICIOUS

Evidence warrants caution but did not satisfy the high-risk threshold. Examples:

- Account verification request combined with attachment upload
- Multiple weak signals (2+ account threats or urgency)
- Impersonation claim without strong request signals

Recommended action: **Pause and verify through an official channel you find independently.**

### LOW_RISK

No meaningful evidence was found in AEGIS's current evidence vocabulary. This **does not mean the content is safe**. Examples:

- A message containing only explicit benign context (e.g., "meeting agenda")
- No screening rules matched

Recommended action: **Continue with normal caution. Verify independently before sharing sensitive information.**

### INSUFFICIENT_EVIDENCE

Available observations do not meet the policy threshold, and semantic analysis could not clarify. This commonly means:

- Stage 0 found no matching patterns
- Stage 1 semantic analysis is unavailable (default)

Recommended action: **Treat as potentially suspicious. Verify independently before acting.**

## Version

Check the installed version:

```powershell
aegis --version
```

## Exit codes

- `0` - Success
- `1` - Invalid usage or unexpected error
- `2` - Invalid input or missing required arguments

## Examples

### Batch processing

Analyze multiple messages from a file:

```powershell
$messages = Get-Content messages.txt
foreach ($msg in $messages) {
  $result = python -m aegis text $msg --json | ConvertFrom-Json
  Write-Host "Risk: $($result.risk.state)"
}
```

### Collecting predictions for evaluation

Generate a JSONL evaluation file:

```powershell
$predictions = @()
foreach ($message in $messages) {
  $result = python -m aegis text $message --json | ConvertFrom-Json
  $predictions += @{
    "expected" = "SCAM"  # your ground truth
    "predicted" = $result.risk.state
    "stage_0_resolved" = $result.routing.stage_0_resolved
    "stage_1_invoked" = $result.routing.stage_1_invoked
    "backend" = $result.system.ai_acceleration
  }
}
$predictions | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content predictions.jsonl
```

Then evaluate:

```powershell
python evaluation/metrics.py --input predictions.jsonl --positive-label HIGH_RISK
```

## Help and troubleshooting

### Getting help

```powershell
python -m aegis --help
python -m aegis text --help
```

### No output or slow response

AEGIS should respond within 10ms for most text. If it seems stuck:

1. Check that your text is valid UTF-8
2. Verify Python is running (check terminal)
3. Try a simpler message: `python -m aegis text "test"`

### Unexpected results

1. Check the EVIDENCE section - it shows what was observed
2. Check SYSTEM STATUS to see if semantic analysis was requested (indicates no Stage 0 decision)
3. Review the risk policy in `src/aegis/config/risk_policy.py` to see the weights
4. Use `--json` to inspect the raw evidence and contributions

### Feature not working

Check the SYSTEM STATUS section. Unavailable features (voice, semantic analysis, Snapdragon NPU) will explicitly report why they are unavailable.
