# Deployment and local operation

## Current delivery status

The current first-pass delivery is a local Python application with a CLI text
workflow. It is intended to be reliable for development and demonstration on a
Windows PC before packaging work begins.

A double-click, installer-quality application is **PLANNED**. No installer,
PyInstaller bundle, signed executable, or verified Snapdragon runtime is claimed
by this repository yet. The current application reports CPU execution unless a
future backend has been genuinely verified and selected.

## Requirements

- Python 3.10 or newer
- A local clone or source checkout of this repository
- No cloud API key, cloud LLM, or mandatory online threat-intelligence service
  for the core text path

The core package has no runtime third-party dependencies. The optional
development extra installs pytest for the test suite.

## Development install

From the repository root in PowerShell:

    py -3 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"

If local PowerShell execution policy prevents activation, use a Command Prompt
session and activate with:

    .venv\Scripts\activate.bat

Or invoke the virtual environment's Python directly without activating it:

    .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
    .\.venv\Scripts\python.exe -m aegis --help

## Run the application

After installation, inspect the supported CLI arguments:

    python -m aegis --help

Run the local AEGIS entry point:

    python -m aegis

To analyze a message non-interactively:

    python -m aegis text "Please send your OTP immediately."

To read a message from standard input:

    "Please send your OTP immediately." | python -m aegis text --stdin

Add --json to the text command when a structured JSON result is needed:

    python -m aegis text "Please send your OTP immediately." --json

A source-checkout convenience launcher is also provided:

    python run.py

The application should be run from a trusted checkout. It assesses untrusted
content; it does not execute submitted files.

## Test before a demo

After installing the development extra, run:

    python -m pytest

Use the same Python interpreter for installation, running, and testing. This
avoids accidentally testing a globally installed copy instead of the checkout
being demonstrated.

## Runtime behavior and user-facing status

The first-pass product is local and evidence-first:

1. Input enters the text pipeline.
2. Deterministic Stage 0 extracts structured observations.
3. The evidence ledger retains source and extractor provenance.
4. The centralized risk engine produces a transparent risk state.
5. A template explanation and recommended action are shown.

Current hardware status is CPU. Do not describe this as NPU acceleration.
Voice and semantic interfaces exist but no local model is installed; a narrow,
header-only static PE preflight and a classifier interface exist but no
file-analysis CLI feature is shipped. The Snapdragon backend is an unavailable
extension point pending verified target-device/model integration.

## Future Windows packaging plan

Packaging starts only after the core workflow and tests are stable. A practical
Windows route is:

1. Build and test the source application in a clean virtual environment.
2. Select a packaging tool such as PyInstaller after its behavior and license
   are verified for the target environment.
3. Package only the required application code and approved local model assets.
4. Test on a clean Windows target machine without a developer shell.
5. Verify that the bundled application displays its real execution backend and
   gracefully reports unavailable optional components.
6. Document package version, Python runtime, model artifacts, checksums where
   appropriate, and known limitations.

Do not package private data, secrets, unverified model caches, or live malware
samples. Do not represent a CPU bundle as an NPU-enabled bundle.

## Deployment acceptance checklist

Before calling a release or competition build deployable, verify:

- A fresh user can launch the intended entry point without manually editing
  paths or source code.
- The shipped input types are explicitly listed; unavailable voice/file features
  are not presented as working.
- CPU versus NPU status is truthful for the actual run.
- The test suite passes in the packaged or target-like environment.
- No credentials, private datasets, malware binaries, or unwanted model caches
  are included.
- The versioned documentation matches the exact build and its limitations.
