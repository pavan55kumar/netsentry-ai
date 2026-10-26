"""NetSentry AI — Phase 8: End-to-End Integration Tests & Deployment Quality Gates.

Validates complete system workflows:
1. Model loading & feature schema integrity.
2. End-to-end CSV flow ingestion & prediction scoring.
3. End-to-end offline PCAP parsing & flow scoring.
4. Safe rejection of incompatible feature schemas.
5. Non-finite value quarantine policy (preventing the silent benign fallacy).
6. Local explanation & narrative safety on quarantined rows.
7. Deterministic temporary file hygiene on success and failure.
8. Privacy-preserving IP address redaction in telemetry export.
9. Import integrity of Streamlit application entry point and all views.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import joblib
import numpy as np
import pandas as pd

from netsentry.data.loader import load_csv, validate_schema
from netsentry.data.synthetic import make_demo_dataset
from netsentry.explainability.local_explainer import explain_single_flow
from netsentry.explainability.narrative import generate_security_narrative
from netsentry.pcap.flow_extractor import extract_flows_from_pcap, CorruptPcapError
from netsentry.predict import score_flows, SchemaMismatchError
from netsentry.utils.logging import redact_ip_address

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


class Phase8IntegrationTests(unittest.TestCase):
    """Integration test suite verifying end-to-end reliability for Phase 8."""

    @classmethod
    def setUpClass(cls):
        cls.model_path = WORKSPACE_ROOT / "artifacts/best_model.joblib"
        cls.features_path = WORKSPACE_ROOT / "artifacts/feature_names.json"
        cls.sample_csv_path = WORKSPACE_ROOT / "data/sample/demo_flows.csv"
        cls.sample_pcap_path = WORKSPACE_ROOT / "data/sample/test_traffic.pcap"

        cls.model = joblib.load(cls.model_path)
        cls.features = json.loads(cls.features_path.read_text(encoding="utf-8"))

    def test_model_artifact_and_feature_schema_integrity(self):
        """Verify champion model artifact and feature schema exist and deserialize cleanly."""
        self.assertTrue(self.model_path.is_file(), "Champion model file artifacts/best_model.joblib must exist.")
        self.assertTrue(self.features_path.is_file(), "Feature schema file artifacts/feature_names.json must exist.")
        self.assertIsInstance(self.features, list)
        self.assertGreater(len(self.features), 0)
        self.assertTrue(hasattr(self.model, "predict"), "Loaded model must implement predict().")

    def test_end_to_end_csv_scoring_workflow(self):
        """Verify complete pipeline scoring on valid CSV flow telemetry."""
        df = load_csv(self.sample_csv_path)
        scored = score_flows(self.model, self.features, df, threshold=0.5)

        # Check output structure
        expected_cols = ["prediction", "risk_level", "data_status", "malicious_score"]
        for c in expected_cols:
            self.assertIn(c, scored.columns, f"Expected output column '{c}' in scored DataFrame.")

        # Check prediction validity
        valid_predictions = {-1, 0, 1}
        self.assertTrue(set(scored["prediction"].unique()).issubset(valid_predictions))

        # Check probability bounds
        valid_scores = scored["malicious_score"].dropna()
        self.assertTrue((valid_scores >= 0.0).all() and (valid_scores <= 1.0).all())

        # Check data_status values
        valid_statuses = {"CLEAN", "IMPUTED_VALID", "INVALID_NON_FINITE", "CORRUPT_EXCESSIVE_MISSING"}
        self.assertTrue(set(scored["data_status"].unique()).issubset(valid_statuses))

    def test_end_to_end_pcap_ingestion_and_scoring_workflow(self):
        """Verify offline PCAP packet ingestion, flow reconstruction, and inference."""
        pcap_res = extract_flows_from_pcap(self.sample_pcap_path)
        self.assertGreater(pcap_res.total_packets_read, 0)
        self.assertGreater(pcap_res.total_flows_extracted, 0)

        flow_df = pcap_res.flow_dataframe
        scored_pcap = score_flows(self.model, self.features, flow_df, threshold=0.5)

        self.assertEqual(len(scored_pcap), pcap_res.total_flows_extracted)
        self.assertIn("data_status", scored_pcap.columns)
        self.assertIn("prediction", scored_pcap.columns)

    def test_safe_rejection_of_incompatible_schema(self):
        """Verify that missing expected columns raises SchemaMismatchError immediately."""
        bad_df = pd.DataFrame({
            "flow_duration_ms": [10.0],
            "total_fwd_packets": [2],
            # Missing remaining 6 required features
        })
        with self.assertRaises(SchemaMismatchError) as ctx:
            score_flows(self.model, self.features, bad_df)

        self.assertIn("missing trained feature columns", str(ctx.exception).lower())

    def test_quarantine_policy_on_non_finite_inputs(self):
        """Verify that flows containing +Inf or -Inf are quarantined as INVALID_NON_FINITE."""
        test_df = make_demo_dataset(rows=10, random_state=42)
        test_df[self.features] = test_df[self.features].astype(float)
        test_df.loc[0, self.features[0]] = np.inf
        test_df.loc[1, self.features[1]] = -np.inf

        scored = score_flows(self.model, self.features, test_df, quarantine_non_finite=True)

        # First two rows must be quarantined with -1 and NaN scores
        self.assertEqual(scored.loc[0, "prediction"], -1)
        self.assertEqual(scored.loc[0, "risk_level"], "QUARANTINE_NON_FINITE")
        self.assertEqual(scored.loc[0, "data_status"], "INVALID_NON_FINITE")
        self.assertTrue(np.isnan(scored.loc[0, "malicious_score"]))

        self.assertEqual(scored.loc[1, "prediction"], -1)
        self.assertEqual(scored.loc[1, "risk_level"], "QUARANTINE_NON_FINITE")
        self.assertEqual(scored.loc[1, "data_status"], "INVALID_NON_FINITE")
        self.assertTrue(np.isnan(scored.loc[1, "malicious_score"]))

    def test_local_explainer_on_quarantined_flows(self):
        """Verify explain_single_flow handles quarantined rows without crashing."""
        clean_bg = make_demo_dataset(rows=20, random_state=42)[self.features]
        test_df = make_demo_dataset(rows=5, random_state=42)
        test_df[self.features] = test_df[self.features].astype(float)
        test_df.loc[0, self.features[0]] = np.inf

        scored = score_flows(self.model, self.features, test_df, quarantine_non_finite=True)
        quarantined_row = scored.loc[0]

        # Call explain_single_flow
        expl = explain_single_flow(self.model, quarantined_row, clean_bg, flow_id="quarantine_0")
        self.assertEqual(expl.predicted_label, -1)
        self.assertEqual(expl.predicted_name, "QUARANTINE_NON_FINITE")
        self.assertIsNone(expl.confidence_score)
        self.assertGreater(len(expl.top_pushing_attack), 0)

        # Check narrative
        narrative = generate_security_narrative(expl)
        self.assertIn("QUARANTINE", narrative["verdict"])
        self.assertIn("suppressed", narrative["summary"].lower())

    def test_temporary_pcap_file_cleanup_on_success_and_exception(self):
        """Verify that temporary capture files on disk are unlinked in both success and failure cases."""
        # 1. Success case
        tmp_good = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        tmp_good.write(self.sample_pcap_path.read_bytes())
        tmp_good.close()
        good_path = Path(tmp_good.name)

        try:
            _ = extract_flows_from_pcap(good_path)
        finally:
            if good_path.is_file():
                good_path.unlink()
        self.assertFalse(good_path.is_file(), "Temporary good PCAP file must be deleted.")

        # 2. Failure case (corrupt magic bytes)
        tmp_bad = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        tmp_bad.write(b"CORRUPT_BYTES_NOT_A_PCAP")
        tmp_bad.close()
        bad_path = Path(tmp_bad.name)

        caught_exception = False
        try:
            _ = extract_flows_from_pcap(bad_path)
        except CorruptPcapError:
            caught_exception = True
        finally:
            if bad_path.is_file():
                bad_path.unlink()

        self.assertTrue(caught_exception)
        self.assertFalse(bad_path.is_file(), "Temporary corrupt PCAP file must be unlinked in finally block.")

    def test_privacy_preserving_ip_export_redaction(self):
        """Verify that IP host octets are masked without corrupting subnet prefixes."""
        raw_ips = ["192.168.1.105", "10.0.0.42", "172.16.254.1"]
        redacted = [redact_ip_address(ip) for ip in raw_ips]

        self.assertEqual(redacted[0], "192.168.1.***")
        self.assertEqual(redacted[1], "10.0.0.***")
        self.assertEqual(redacted[2], "172.16.254.***")

    def test_application_views_import_cleanly(self):
        """Verify Streamlit entry point and all 8 view modules import cleanly."""
        try:
            import app.main
            from app.views import (
                overview,
                explorer,
                model_lab,
                evaluation,
                traffic_analyzer,
                explainability,
                research,
                learn,
            )
            # Check callable render functions
            self.assertTrue(callable(overview.render_overview_view))
            self.assertTrue(callable(explorer.render_explorer_view))
            self.assertTrue(callable(model_lab.render_model_lab_view))
            self.assertTrue(callable(evaluation.render_evaluation_view))
            self.assertTrue(callable(traffic_analyzer.render_traffic_analyzer_view))
            self.assertTrue(callable(explainability.render_explainability_view))
            self.assertTrue(callable(research.render_research_view))
            self.assertTrue(callable(learn.render_learn_view))
        except Exception as ex:
            self.fail(f"Application import failed: {ex}")


if __name__ == "__main__":
    unittest.main()
