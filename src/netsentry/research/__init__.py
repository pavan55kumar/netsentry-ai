"""NetSentry AI Advanced Research Subsystem."""
from .cross_dataset import (
    evaluate_cross_dataset,
    CrossDatasetResult,
    evaluate_joint_domain_generalization,
    JointDomainResult,
    COMMON_NETWORK_FLOW_MAPPING,
)
from .anomaly import (
    benchmark_unsupervised_anomaly,
    AnomalyBenchmarkResult,
    evaluate_unseen_attack_detection,
    UnseenAttackResult,
)
from .unseen import (
    evaluate_unseen_attack_family,
    run_unseen_attack_suite,
    UnseenAttackFamilyResult,
    UnseenAttackSuiteResult,
)
from .generalization_strategies import (
    GeneralizationStrategyResult,
    GeneralizationSuiteResult,
    run_generalization_strategy_experiments,
)
from .drift import (
    simulate_model_drift,
    DriftSimulationResult,
)
from .robustness import (
    PerturbationResult,
    RobustnessSuiteResult,
    evaluate_single_perturbation,
    apply_gaussian_measurement_noise,
    apply_missing_feature_injection,
    apply_extreme_valid_stress,
    apply_adversarial_pacing,
    run_robustness_evaluation_suite,
)

__all__ = [
    "evaluate_cross_dataset",
    "CrossDatasetResult",
    "evaluate_joint_domain_generalization",
    "JointDomainResult",
    "COMMON_NETWORK_FLOW_MAPPING",
    "benchmark_unsupervised_anomaly",
    "AnomalyBenchmarkResult",
    "evaluate_unseen_attack_detection",
    "UnseenAttackResult",
    "evaluate_unseen_attack_family",
    "run_unseen_attack_suite",
    "UnseenAttackFamilyResult",
    "UnseenAttackSuiteResult",
    "GeneralizationStrategyResult",
    "GeneralizationSuiteResult",
    "run_generalization_strategy_experiments",
    "simulate_model_drift",
    "DriftSimulationResult",
    "PerturbationResult",
    "RobustnessSuiteResult",
    "evaluate_single_perturbation",
    "apply_gaussian_measurement_noise",
    "apply_missing_feature_injection",
    "apply_extreme_valid_stress",
    "apply_adversarial_pacing",
    "run_robustness_evaluation_suite",
]



