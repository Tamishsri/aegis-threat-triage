# Threat model

## Scope

AEGIS accepts content a user considers suspicious and returns a local,
evidence-based triage result. Its security goal is to make relevant observed
signals visible and apply a transparent caution policy before the user acts.
It does not promise to identify every scam or every malicious executable, and
it does not replace endpoint security controls.

The application does not execute submitted executables. The first-pass
HeaderOnlyPEAnalyzer performs only static MZ/PE-signature preflight; fuller PE
feature extraction and classification remain planned and will remain static-only.

## Assets to protect

- The user's credentials, OTPs, funds, identity, and ability to make an
  informed decision.
- The integrity of the assessment: raw input must not dictate its own verdict.
- Evidence provenance: users and developers must be able to see which analyzer
  observed a signal.
- The host system and local files: untrusted input must not be executed or
  treated as trusted configuration.
- Privacy: core triage is designed to run locally and must not require a cloud
  LLM or cloud threat-intelligence service.

## Trust boundaries

~~~text
attacker-controlled text / transcript / file
                 |
                 | untrusted input boundary
                 v
input handler and analyzer  --> structured evidence --> ledger --> risk policy
                                                              |
                                                              v
                                                    user-facing explanation
~~~

All text, a voice transcript, filenames, metadata, parsed PE fields, model
output, and URL components are untrusted inputs. The rules, risk configuration,
and application code are trusted only to the degree that their local
installation and dependency supply chain are trusted.

## Threats, controls, and residual risk

| Threat | Current or required control | Residual risk |
| --- | --- | --- |
| Social-engineering text | Deterministic signals identify explicit credential, OTP, payment, urgency, account-threat, impersonation, and suspicious-instruction patterns. | Attackers can paraphrase, translate, split, or disguise harmful requests. No keyword match is not a safety guarantee. |
| Prompt manipulation | Obvious patterns such as attempts to ignore instructions or force a safe verdict are preserved as manipulation_attempt evidence. | Pattern rules are not comprehensive and do not make AEGIS prompt-injection-proof. |
| Untrusted voice transcript | Treat the transcript exactly like untrusted text after transcription. | Transcription errors, accents, noise, and adversarial audio can hide or create signals. Voice support is planned, not currently available. |
| Suspicious executable | The current header-only preflight reads bytes without launching the sample. Future file analysis remains static-only. | Static analysis can be evaded by packing, obfuscation, unsupported formats, malformed files, and novel malware. It cannot establish runtime behavior. |
| Model error | A future semantic model is limited to producing evidence through a defined adapter; it cannot directly choose the risk state. | Incorrect, biased, stale, or adversarially influenced model output can still add misleading evidence. |
| Evidence tampering in process | The ledger is designed to append provenance-bearing records and prevent downstream components from silently overwriting upstream observations. | A compromised local application or configuration can still change behavior; code integrity is outside the app's sole control. |
| False positives | Use qualitative strength, transparent explanations, and cautious recommended actions rather than automatic blocking or deletion. | Benign messages may resemble fraud language, causing inconvenience or distrust. |
| False negatives | Explicitly expose INSUFFICIENT_EVIDENCE and avoid equating an empty rule result with safe content. | Harmful content may receive a low or insufficient assessment when it falls outside known evidence vocabulary. |
| URL deception | Optional local structural checks can flag IP hosts, punycode, embedded credentials, suspicious subdomains, and shorteners. | A syntactically ordinary URL can still be malicious; lack of HTTPS alone is not proof of abuse. |
| Resource exhaustion / malformed input | Keep parsers bounded, validate inputs, and avoid executing or recursively unpacking untrusted files. | Very large, malformed, or deliberately expensive inputs may still need explicit limits as file and voice features are implemented. |

## Adversary model

An attacker may send persuasive messages, use urgency or impersonation, embed
URLs, manipulate wording to evade simple rules, include instructions meant to
influence an AI system, submit malformed data, or provide a malicious binary.
They may know the public detection rules and attempt to avoid them.

AEGIS assumes the attacker cannot modify the installed application, its policy,
or the user's operating-system security controls. If those assumptions fail,
AEGIS's local results cannot be trusted.

## Non-goals

AEGIS does not:

- execute, detonate, delete, quarantine, or remediate files;
- provide live reputation, WHOIS, or domain-age checks as a core dependency;
- claim protection against all scams, prompt injection, malware, or adversarial
  inputs;
- use a generative LLM as the security decision-maker; or
- replace Defender, EDR, a firewall, incident response, or professional advice.

## Safe user interpretation

The recommended action is guidance, not proof. A high-risk result supports
pausing and verifying through an official channel; it is not a legal or
forensic conclusion. A low-risk or insufficient-evidence result should not be
used as permission to share credentials, OTPs, money, or sensitive information.

## Review triggers

The threat model should be reviewed before adding a parser, model, third-party
runtime, network capability, file format, or packaging method. New adapters
need tests for malformed inputs, provenance preservation, unavailable backend
behavior, and claims shown to the user.
