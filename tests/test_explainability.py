"""Unit tests for NetSentry AI explainability subsystem."""
import unittest
import pandas as pd
from netsentry.models.factory import build_pipeline
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data
from netsentry.explainability.importance import compute_global_importance
from netsentry.explainability.local_explainer import explain_single_flow
from netsentry.explainability.narrative import generate_security_narrative


class ExplainabilityTests(unittest.TestCase):
    def setUp(self):
        self.df = make_demo_dataset(rows=100, random_state=42)
        self.prep = prepare_data(self.df, "label", test_size=0.25, random_state=42)
        self.pipe = build_pipeline("random_forest_500", random_state=42, fast_mode=True)
        self.pipe.fit(self.prep.X_train, self.prep.y_train)

    def test_global_importance_tree_mdi(self):
        imp = compute_global_importance(self.pipe, self.prep.X_train, method="tree_mdi")
        self.assertEqual(len(imp.feature_importances), len(self.prep.feature_names))
        self.assertAlmostEqual(sum(imp.feature_importances.values()), 1.0, places=3)
        self.assertGreater(len(imp.top_features), 0)

    def test_local_explanation_and_narrative(self):
        sample_row = self.prep.X_test.iloc[0]
        expl = explain_single_flow(self.pipe, sample_row, self.prep.X_train, flow_id="flow_test_1")
        self.assertIn("flow_test_1", expl.flow_id)
        self.assertIsNotNone(expl.predicted_name)
        self.assertEqual(len(expl.raw_values), len(self.prep.feature_names))

        narrative = generate_security_narrative(expl, is_calibrated=False)
        self.assertIn(expl.predicted_name.upper(), narrative["verdict"])
        self.assertIn("uncalibrated", narrative["score_description"])
        self.assertGreater(len(narrative["scientific_limitations"]), 0)


if __name__ == "__main__":
    unittest.main()
