"""Traffic Analyzer and live flow inference view for NetSentry AI."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import joblib
import pandas as pd
import streamlit as st

try:
    from netsentry.predict import score_flows
    from netsentry.explainability.local_explainer import explain_single_flow
    from netsentry.explainability.narrative import generate_security_narrative
    from netsentry.pcap.flow_extractor import extract_flows_from_pcap
except ImportError:
    from src.netsentry.predict import score_flows
    from src.netsentry.explainability.local_explainer import explain_single_flow
    from src.netsentry.explainability.narrative import generate_security_narrative
    from src.netsentry.pcap.flow_extractor import extract_flows_from_pcap

from ..styles import render_badge, render_kpi


def render_traffic_analyzer_view():
    st.markdown("## 🛰️ Live Traffic Analyzer & Flow Scoring")
    st.caption("Score incoming network connection flows, ingest raw PCAP captures, filter suspicious traffic, and export security audits.")

    model_path = Path("artifacts/best_model.joblib")
    features_path = Path("artifacts/feature_names.json")

    if not model_path.is_file() or not features_path.is_file():
        st.warning("⚠️ No trained champion model found. Please train a model in the **Model Lab** first.")
        return

    try:
        model = joblib.load(model_path)
        features = json.loads(features_path.read_text(encoding="utf-8"))
    except Exception as e:
        st.error(f"Failed to load model pipeline: {e}")
        return

    # Ingestion Source
    col_src, col_thresh = st.columns([3, 1])
    with col_src:
        traffic_source = st.radio(
            "Select Flow Ingestion Stream",
            [
                "Curated Sample Flow Traffic (data/sample/demo_flows.csv)",
                "Upload Unlabeled Flow CSV",
                "Offline Packet Capture (PCAP/PCAPNG Ingestion)",
            ],
            horizontal=True,
        )
    with col_thresh:
        thresh = st.slider("Alert Threshold", min_value=0.1, max_value=0.9, value=0.5, step=0.05)

    input_df: pd.DataFrame | None = None
    pcap_meta: dict | None = None

    if "PCAP" in traffic_source:
        st.info("🔒 **Ethical Notice:** Offline PCAP ingestion allows safe analysis of pre-recorded captures without live wire interception. Ensure explicit authorization before analyzing network traces.")
        pcap_option = st.radio("PCAP Source", ["Included Sample Capture (data/sample/test_traffic.pcap)", "Upload Custom .pcap/.pcapng File"], horizontal=True)
        
        target_pcap_path = None
        is_temporary_file = False
        if "Included" in pcap_option:
            pcap_file = Path("data/sample/test_traffic.pcap")
            if pcap_file.is_file():
                target_pcap_path = pcap_file
            else:
                st.warning("Sample PCAP not found in data/sample/test_traffic.pcap")
        else:
            pcap_upload = st.file_uploader("Upload raw packet capture", type=["pcap", "pcapng"], key="pcap_uploader")
            if pcap_upload is not None:
                # Enforce 50 MB upload limit to prevent memory exhaustion
                if pcap_upload.size > 50 * 1024 * 1024:
                    st.error("⚠️ Uploaded PCAP exceeds maximum safe limit of 50 MB.")
                    return
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
                try:
                    tmp.write(pcap_upload.read())
                    tmp.flush()
                finally:
                    tmp.close()
                target_pcap_path = Path(tmp.name)
                is_temporary_file = True

        if target_pcap_path is not None:
            with st.spinner("Parsing raw packets and reconstructing bidirectional 5-tuple flows..."):
                try:
                    pcap_result = extract_flows_from_pcap(target_pcap_path)
                    input_df = pcap_result.flow_dataframe
                    pcap_meta = pcap_result.to_dict()
                    
                    st.success(f"Reconstructed {pcap_result.total_flows_extracted} flows from {pcap_result.total_packets_read} packets ({pcap_result.capture_duration_sec:.2f}s capture duration).")
                    with st.expander("🔍 Inspect PCAP Extraction Summary & 5-Tuple Details"):
                        st.json(pcap_meta)
                except Exception as ex:
                    st.error(f"Error parsing PCAP capture: {ex}")
                    return
                finally:
                    # Privacy & hygiene: securely delete uploaded packet captures immediately after parsing
                    if is_temporary_file and target_pcap_path.is_file():
                        try:
                            target_pcap_path.unlink()
                        except Exception:
                            pass

    elif "Upload" in traffic_source:
        uploaded = st.file_uploader("Upload CSV containing flow records", type=["csv"], key="analyzer_upload")
        if uploaded is not None:
            if uploaded.size > 50 * 1024 * 1024:
                st.error("⚠️ Uploaded CSV exceeds maximum safe limit of 50 MB.")
                return
            try:
                input_df = pd.read_csv(uploaded, low_memory=False)
                input_df.columns = [str(c).strip() for c in input_df.columns]
                if len(input_df) == 0:
                    st.warning("⚠️ Uploaded CSV is empty (0 data rows).")
                    return
            except Exception as e:
                st.error(f"Failed to read CSV: {e}")
                return
    else:
        sample_path = Path("data/sample/demo_flows.csv")
        if sample_path.is_file():
            input_df = pd.read_csv(sample_path, low_memory=False)
            input_df.columns = [str(c).strip() for c in input_df.columns]

    if input_df is None or len(input_df) == 0:
        st.info("Awaiting flow data for analysis.")
        return

    # Check required features
    missing_feats = [f for f in features if f not in input_df.columns]
    if missing_feats:
        st.error(
            f"⚠️ **Schema Incompatibility:** The active champion model expects {len(features)} features ({features[:5]}...), "
            f"but the current input provides {len(input_df.columns)} columns. "
            f"Missing features: {missing_feats[:6]}."
        )
        st.markdown(
            "> [!NOTE]\n"
            "> If you extracted flows from PCAP or uploaded a dataset from a different schema family (e.g. NetSentry 8-feature schema vs CIC-IDS2017 77-feature schema), "
            "> please select or train a matching model in the **Model Lab**."
        )
        with st.expander("📋 View Extracted / Raw Flow Table"):
            st.dataframe(input_df.head(100), use_container_width=True)
        return

    # Score flows
    with st.spinner("Scoring flow records through active pipeline..."):
        scored_df = score_flows(model, features, input_df, threshold=thresh)

    total_flows = len(scored_df)
    flagged_flows = int((scored_df["prediction"] == 1).sum())
    flagged_pct = (flagged_flows / max(total_flows, 1)) * 100.0

    critical_count = int((scored_df.get("risk_level", "") == "CRITICAL").sum())
    high_count = int((scored_df.get("risk_level", "") == "HIGH").sum())

    # Summary KPI Bar
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(render_kpi("Total Flows Scored", f"{total_flows:,}", "Active Stream", "#38bdf8"), unsafe_allow_html=True)
    with k2:
        st.markdown(render_kpi("Flagged Threats", f"{flagged_flows:,}", f"{flagged_pct:.1f}% Positive Class", "#f43f5e" if flagged_flows > 0 else "#10b981"), unsafe_allow_html=True)
    with k3:
        st.markdown(render_kpi("Critical Risk", f"{critical_count:,}", "Immediate Escalation", "#f43f5e"), unsafe_allow_html=True)
    with k4:
        st.markdown(render_kpi("High Risk", f"{high_count:,}", "Requires Analyst Review", "#f59e0b"), unsafe_allow_html=True)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    st.info(
        "🛡️ **Score Interpretation & Methodology Notice:** The displayed prediction reflects statistical similarity to known training attack patterns. "
        "Confidence scores from supervised pipelines represent estimated class probabilities; they do **not** constitute absolute proof of malicious intent. "
        "For unsupervised anomaly models, scores represent relative geometric outlier distance and must not be interpreted as calibrated probabilities."
    )

    # Filtering
    filter_choice = st.radio(
        "Filter View",
        ["All Flows", "Flagged Malicious Only", "Critical & High Risk Only"],
        horizontal=True,
    )

    if filter_choice == "Flagged Malicious Only":
        display_df = scored_df[scored_df["prediction"] == 1]
    elif filter_choice == "Critical & High Risk Only":
        display_df = scored_df[scored_df["risk_level"].isin(["CRITICAL", "HIGH"])]
    else:
        display_df = scored_df

    st.markdown("##### 📋 Scored Flow Telemetry")
    st.dataframe(display_df.head(200), use_container_width=True)
    st.caption(f"Displaying {len(display_df):,} of {total_flows:,} flows.")

    # Export Scored Data
    csv_bytes = scored_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Export Scored Telemetry to CSV",
        data=csv_bytes,
        file_name="netsentry_scored_traffic.csv",
        mime="text/csv",
    )

    st.markdown("---")

    # Single Flow Deep Inspection
    st.markdown("##### 🔬 Individual Flow Deep Inspection & Security Diagnosis")
    if len(display_df) > 0:
        flow_indices = list(display_df.index)
        selected_idx = st.selectbox("Select Flow Record to Diagnose", flow_indices, index=0)
        selected_row = scored_df.loc[selected_idx]

        expl = explain_single_flow(model, selected_row, scored_df[features], flow_id=f"Flow #{selected_idx}")
        narrative = generate_security_narrative(expl)

        is_mal = expl.predicted_name.lower() not in {"benign", "normal", "0"}
        alert_class = "soc-alert-malicious" if is_mal else "soc-alert-benign"

        st.markdown(
            f"""
            <div class="soc-alert {alert_class}">
                <h4>{narrative['verdict']} — {narrative['score_description']}</h4>
                <p><b>Summary:</b> {narrative['summary']}</p>
                <p><b>Actionable SOC Advice:</b> {narrative['actionable_recommendation']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander("🔍 Inspect Underlying Flow Features & Normal Medians"):
            comp_table = []
            for feat in features:
                val = expl.raw_values.get(feat, 0.0)
                med = expl.normal_medians.get(feat, 0.0)
                z = expl.deviations.get(feat, 0.0)
                comp_table.append({
                    "Feature": feat,
                    "Observed Value": round(val, 3),
                    "Baseline Normal Median": round(med, 3),
                    "Deviation (Z-Score)": round(z, 2),
                })
            st.dataframe(pd.DataFrame(comp_table), use_container_width=True)
    else:
        st.info("No flows match the current filter criteria.")
