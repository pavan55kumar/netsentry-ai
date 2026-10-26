"""Dataset Explorer view for NetSentry AI."""
from __future__ import annotations

from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

from src.netsentry.data.loader import load_csv, validate_schema
from ..styles import render_kpi, render_badge


DCN_FEATURE_GLOSSARY = {
    "Flow Duration": "Total duration of the bidirectional network connection (often measured in microseconds or milliseconds). Short durations (<10ms) indicate rapid scanning or teardown; long durations indicate sustained transfers or slowloris attacks.",
    "Total Fwd Packets": "Number of packets transmitted from the connection initiator (client) to responder (server). High forward packets with zero backward packets suggests an unanswered SYN flood or port scan probe.",
    "Total Backward Packets": "Number of packets transmitted in reverse from responder to initiator. Normal connections have balanced forward and backward acknowledgments.",
    "Flow Bytes/s": "Data throughput rate. Volumetric attacks (DDoS, video exfiltration) manifest as extreme spikes in bytes per second.",
    "Flow Packets/s": "Transmission density. Packet rate spikes without payload bytes represent pure header flooding (SYN, UDP, ICMP floods).",
    "SYN Flag Count": "Count of Synchronize flags seen in the flow. Used to initiate TCP connections. A disproportionate number of SYN packets indicates half-open SYN scanning or DoS.",
    "RST Flag Count": "Count of Reset flags. Indicates an abrupt connection termination. High RST rates suggest firewalls rejecting unauthorized connection attempts or port scanning closed ports.",
    "Average Packet Size": "Mean size of packet payloads and headers in bytes. Small sizes (~40-64 bytes) indicate pure TCP control frames or ping floods. Large sizes (~1460 bytes) indicate full MTU data transfers.",
}


def render_explorer_view():
    st.markdown("## 🔍 Network Flow Dataset Explorer")
    st.caption("Inspect raw flow records, validate schemas, audit class balance, and learn DCN flow attributes.")

    # Dataset Source Selector
    st.markdown("##### 📁 Select Flow Dataset Source")
    ds_options = {
        "CIC-IDS2017 Sample (1,500 flows, Multi-Attack)": "data/sample/cicids2017_sample.csv",
        "UNSW-NB15 Sample (1,500 flows, Modern Attacks)": "data/sample/unsw_nb15_sample.csv",
        "NetSentry Synthetic Demo (1,200 flows, Educational)": "data/sample/demo_flows.csv",
        "Upload Custom Network Flow CSV": "upload",
    }

    selected_label = st.selectbox("Active Dataset", list(ds_options.keys()), index=0)
    source_val = ds_options[selected_label]

    df: pd.DataFrame | None = None
    if source_val == "upload":
        uploaded = st.file_uploader("Upload Network Flow CSV", type=["csv"])
        if uploaded is not None:
            try:
                df = pd.read_csv(uploaded, low_memory=False)
                df.columns = [str(c).strip() for c in df.columns]
                st.session_state["loaded_df"] = df
                st.session_state["loaded_source_name"] = uploaded.name
            except Exception as e:
                st.error(f"Failed to parse uploaded CSV: {e}")
                return
        elif "loaded_df" in st.session_state:
            df = st.session_state["loaded_df"]
    else:
        file_path = Path(source_val)
        if file_path.is_file():
            df = load_csv(file_path)
            st.session_state["loaded_df"] = df
            st.session_state["loaded_source_name"] = file_path.name
        else:
            st.warning(f"Sample file '{source_val}' not found. Please generate samples first.")
            return

    if df is None:
        st.info("Please select or upload a dataset to begin.")
        return

    # Potential label column identification
    label_candidates = [c for c in df.columns if any(k in c.lower() for k in ["label", "attack", "class", "target", "category"])]
    default_label = label_candidates[0] if label_candidates else df.columns[-1]

    col_lbl, col_rows = st.columns([2, 1])
    with col_lbl:
        active_label_col = st.selectbox("Designate Label / Target Column", list(df.columns), index=list(df.columns).index(default_label))
    with col_rows:
        preview_rows = st.slider("Preview Rows", min_value=5, max_value=50, value=10)

    # Data Quality & Schema Report
    report = validate_schema(df, label_column=active_label_col)

    st.markdown("##### 🩺 Data Quality & Schema Assessment")
    q1, q2, q3, q4, q5 = st.columns(5)
    with q1:
        st.markdown(render_kpi("Total Records", f"{report.total_rows:,}", "Flow Connections", "#38bdf8"), unsafe_allow_html=True)
    with q2:
        st.markdown(render_kpi("Numeric Features", f"{len(report.numeric_columns)}", f"{len(report.categorical_columns)} Categorical", "#00f0ff"), unsafe_allow_html=True)
    with q3:
        inf_sum = sum(report.infinite_counts.values())
        st.markdown(render_kpi("Infinite Values", f"{inf_sum}", "Zero Duration Divisions", "#f59e0b" if inf_sum > 0 else "#10b981"), unsafe_allow_html=True)
    with q4:
        st.markdown(render_kpi("Duplicate Rows", f"{report.exact_duplicate_rows}", "Exact Match Feature Vectors", "#a855f7"), unsafe_allow_html=True)
    with q5:
        st.markdown(render_kpi("Detected Schema", report.detected_schema, "Standardized Topology", "#10b981"), unsafe_allow_html=True)

    if report.warnings or report.recommendations:
        for w in report.warnings:
            st.warning(f"⚠️ {w}")
        for r in report.recommendations:
            st.info(f"💡 {r}")

    # Tabs for Data Inspection
    tab_preview, tab_dist, tab_glossary = st.tabs(["📋 Flow Records Preview", "📊 Label Distribution & Imbalance", "📖 DCN Feature Dictionary"])

    with tab_preview:
        st.dataframe(df.head(preview_rows), use_container_width=True)
        st.caption(f"Showing top {preview_rows} of {len(df):,} flows with {len(df.columns)} columns.")

    with tab_dist:
        col_chart, col_stats = st.columns([3, 2])
        with col_chart:
            counts = df[active_label_col].value_counts().reset_index()
            counts.columns = ["Class", "Count"]
            fig = px.bar(
                counts,
                x="Class",
                y="Count",
                color="Class",
                text="Count",
                title=f"Distribution of Target: {active_label_col}",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(15,23,42,0.6)",
                font_color="#f1f5f9",
                height=320,
            )
            fig.update_traces(textposition="outside")
            st.plotly_chart(fig, use_container_width=True)

        with col_stats:
            st.markdown(
                f"""
                <div class="netsentry-card">
                    <b>Total Classes:</b> {len(counts)}<br>
                    <b>Majority Class:</b> {counts.iloc[0]['Class']} ({counts.iloc[0]['Count']:,} flows - {counts.iloc[0]['Count']/len(df)*100:.1f}%)<br>
                    <b>Minority Class:</b> {counts.iloc[-1]['Class']} ({counts.iloc[-1]['Count']:,} flows - {counts.iloc[-1]['Count']/len(df)*100:.1f}%)<br><br>
                    <b>Cyber Imbalance Note:</b> In production environments, benign traffic routinely comprises over 98% of total flows. 
                    Standard accuracy is heavily biased by the majority class. NetSentry evaluates models on Macro-F1 and Precision-Recall AUC to avoid the accuracy trap.
                </div>
                """,
                unsafe_allow_html=True,
            )

    with tab_glossary:
        st.markdown("##### 🌐 Data Communication & Networking (DCN) Flow Attributes")
        for feat_name, explanation in DCN_FEATURE_GLOSSARY.items():
            with st.expander(f"📌 {feat_name}"):
                st.write(explanation)
