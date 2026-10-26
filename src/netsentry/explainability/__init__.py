"""NetSentry AI Explainability Subsystem."""
from .importance import (
    compute_global_importance,
    GlobalFeatureImportance,
)
from .local_explainer import (
    explain_single_flow,
    LocalFlowExplanation,
)
from .narrative import generate_security_narrative
from .error_analysis import (
    perform_comprehensive_error_analysis,
    ErrorAnalysisReport,
)

__all__ = [
    "compute_global_importance",
    "GlobalFeatureImportance",
    "explain_single_flow",
    "LocalFlowExplanation",
    "generate_security_narrative",
    "perform_comprehensive_error_analysis",
    "ErrorAnalysisReport",
]

