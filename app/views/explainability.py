"""Explainability Lab view for NetSentry AI."""
from __future__ import annotations

import json
from pathlib import Path
import joblib
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.netsentry.explainability.importance import compute_global_importance
from src.netsentry.explainability.local_explainer import explain_single_flow
from src.netsentry.explainability.narrative import generate_security_narrative
from ..styles import render_kpi, render_badge


def render_explainability_view():
    st.markdown("## 🧠 Explainability Lab (XAI)")
    st.caption("Interpret global model decision boundaries, explain local flow classifications, and audit model reasoning.")

    model_path = Path("artifacts/best_model.joblib")
    features_path = Path("artifacts/feature_names.json")

    if not model_path.is_file() or not features_path.is_file():
        st.warning("⚠️ No fitted model pipeline found. Please train a model in the **Model Lab** first.")
        return

    try:
        model = joblib.load(model_path)
        features = json.loads(features_path.read_text(encoding="utf-8"))
    except Exception as e:
        st.error(f"Failed to load model: {e}")
        return

    # Check for test data
    ref_df = st.session_state.get("loaded_df", None)
    if ref_df is None:
        sample_path = Path("data/sample/demo_flows.csv")
        if sample_path.is_file():
            ref_df = pd.read_csv(sample_path)
            ref_df.columns = [str(c).strip() for c in ref_df.columns]

    if ref_df is None:
        st.info("Please load or upload a dataset in **Dataset Explorer** to enable explainability attributions.")
        return

    tab_global, tab_local, tab_disclaimer = st.tabs([
        "🌐 Global Feature Importance",
        "🔬 Local Flow Attribution",
        "⚠️ Scientific Limitations & Honesty",
    ])

    with tab_global:
        st.markdown("##### 🌐 Global Feature Importance Rankings")
        st.caption("Which network flow attributes contribute most to the overall intrusion detection decisions across all traffic?")

        with st.spinner("Computing global feature importance..."):
            feat_subset = [f for f in features if f in ref_df.columns]
            glob_imp = compute_global_importance(model, ref_df[feat_subset])

        imp_df = pd.DataFrame(
            list(glob_imp.feature_importances.items()),
            columns=["Feature", "Importance Score"],
        ).sort_values(by="Importance Score", ascending=True)

        fig = px.bar(
            imp_df,
            x="Importance Score",
            y="Feature",
            orientation="h",
            color="Importance Score",
            color_continuous_scale="Tealgrn",
            title=f"Method: {glob_imp.method}",
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            font_color="#f1f5f9",
            height=380,
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown(
            f"""
            <div class="netsentry-card">
                <b>Top Driving Flow Features:</b> {", ".join(glob_imp.top_features)}<br>
                <b>Technical Meaning:</b> {glob_imp.description}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with tab_local:
        st.markdown("##### 🔬 Single Flow Decision Breakdown")
        st.caption("Select a connection flow to inspect exactly which attributes drove its classification.")

        feat_subset = [f for f in features if f in ref_df.columns]
        flow_idx = st.selectbox("Select Flow Record from Reference Dataset", list(range(min(len(ref_df), 100))), index=0)
        selected_flow = ref_df.iloc[flow_idx]

        expl = explain_single_flow(model, selected_flow, ref_df[feat_subset], flow_id=f"Flow #{flow_idx}")
        narrative = generate_security_narrative(expl)

        is_mal = expl.predicted_name.lower() not in {"benign", "normal", "0"}
        alert_class = "soc-alert-malicious" if is_mal else "soc-alert-benign"

        st.markdown(
            f"""
            <div class="soc-alert {alert_class}">
                <h3>{narrative['verdict']} — {narrative['score_description']}</h3>
                <p><b>Executive Summary:</b> {narrative['summary']}</p>
                <p><b>Recommended Action:</b> {narrative['actionable_recommendation']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Plotly Deviation Waterfall
        dev_items = list(expl.deviations.items())
        dev_df = pd.DataFrame(dev_items, columns=["Feature", "Z-Score vs Baseline"]).sort_values(by="Z-Score vs Baseline")

        fig_dev = px.bar(
            dev_df,
            x="Z-Score vs Baseline",
            y="Feature",
            orientation="h",
            color="Z-Score vs Baseline",
            color_continuous_scale="RdBu_r",
            title="Feature Deviation from Normal Baseline Distribution (Standard Deviations σ)",
        )
        fig_dev.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            font_color="#f1f5f9",
            height=350,
        )
        st.plotly_chart(fig_dev, use_container_width=True)

    with tab_disclaimer:
        st.markdown("##### ⚠️ Scientific Limitations, Correlation vs. Causation, and Uncertainty")
        st.markdown(
            """
            <div class="netsentry-card">
                <h4>Core Scientific Guardrails</h4>
                <ul>
                    <li><b>Correlation vs. Causation:</b> Machine learning detects mathematical correlations present in historical packet captures. A high packet rate strongly correlates with DoS attacks, but can also be caused by legitimate software updates or network speedtests. ML flags potential threats, but human analysts determine intent.</li>
                    <li><b>Probability Calibration Notice:</b> Model confidence scores (e.g. 0.88) represent raw sigmoid or tree fraction outputs. Unless explicitly verified with Platt scaling or Brier score evaluation, do not treat raw outputs as true Bayesian posterior probabilities.</li>
                    <li><b>Distribution Dependence:</b> Intrusion detectors assume the operational network shares the same statistical topology as the training data. If your network switches to new protocols, background noise increases, or attackers alter their signatures, performance will degrade.</li>
                    <li><b>Never Deploy Without Human Review:</b> Fully automated blocking firewalls based solely on uncalibrated ML models risk knocking mission-critical services offline. Always combine ML alerts with stateful firewall rules and security review.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
