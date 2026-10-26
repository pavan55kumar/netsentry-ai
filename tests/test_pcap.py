"""Unit tests for NetSentry AI PCAP ingestion and 5-tuple flow extraction."""
import unittest
from pathlib import Path
from netsentry.pcap.flow_extractor import extract_flows_from_pcap, get_tshark_extraction_command
from netsentry.predict import score_flows
from netsentry.models.factory import build_pipeline
from netsentry.data.synthetic import make_demo_dataset
from netsentry.data.preprocessor import prepare_data


class PcapTests(unittest.TestCase):
    def test_pcap_extraction_and_flow_aggregation(self):
        pcap_file = Path("data/sample/test_traffic.pcap")
        if not pcap_file.is_file():
            self.skipTest("Sample PCAP not present")

        res = extract_flows_from_pcap(pcap_file)
        self.assertGreaterEqual(res.total_packets_read, 1)
        self.assertGreaterEqual(res.total_flows_extracted, 1)
        df = res.flow_dataframe

        # Check required flow features
        expected_cols = [
            "flow_duration_ms",
            "total_fwd_packets",
            "total_backward_packets",
            "flow_bytes_per_second",
            "flow_packets_per_second",
            "syn_flag_count",
            "rst_flag_count",
            "average_packet_size",
        ]
        for col in expected_cols:
            self.assertIn(col, df.columns)

        # Check 5-tuple fields
        self.assertIn("src_ip", df.columns)
        self.assertIn("dst_ip", df.columns)
        self.assertIn("dst_port", df.columns)

    def test_tshark_command_generation(self):
        cmd = get_tshark_extraction_command("capture.pcap", "output.csv")
        self.assertIn("tshark", cmd)
        self.assertIn("frame.time_epoch", cmd)
        self.assertIn("output.csv", cmd)


if __name__ == "__main__":
    unittest.main()
