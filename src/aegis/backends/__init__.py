"""Execution-backend abstractions with truthful availability reporting."""

from aegis.backends.base import BackendUnavailable, CPUBackend, InferenceBackend, QualcommBackend

__all__ = ["BackendUnavailable", "CPUBackend", "InferenceBackend", "QualcommBackend"]
