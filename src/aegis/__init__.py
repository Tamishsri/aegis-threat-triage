"""AEGIS: local, evidence-first pre-action threat triage."""

from aegis.pipeline import AnalysisResult, TextTriagePipeline
from aegis.risk_engine import RiskState

__all__ = ["AnalysisResult", "RiskState", "TextTriagePipeline"]

__version__ = "0.1.0"
