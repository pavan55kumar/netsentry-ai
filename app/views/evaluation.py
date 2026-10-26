"""Comprehensive evaluation dashboard view for NetSentry AI."""
from __future__ import annotations

import json
from pathlib import Path
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ..styles import render_kpi, render_badge


def render_evaluation_view():
    st.markdown("## 📊 Evaluation Center & Threshold Calibration")
    st.caption("Deep-dive statistical audit: Confusion matrices, per-class metrics, ROC/PR curves, and alert fatigue optimization.")

    metrics_path = Path("artifacts/metrics.json")
    if not metrics_path.is_file():
        st.info("No evaluation artifacts found. Please execute training in the **Model Lab** first.")
        return

    try:
        data = json.loads(metrics_path.read_text(encoding="utf-8"))
    except Exception as e:
        st.error(f"Failed to load metrics.json: {e}")
        return

    models_dict = data.get("models", {})
    if not models_dict:
        st.warning("No model results available in metrics.json.")
        return

    # Model selector
    model_names = list(models_dict.keys())
    selected_champ = data.get("selected_model", model_names[0])
    default_idx = model_names.index(selected_champ) if selected_champ in model_names else 0

    col_sel, col_info = st.columns([2, 3])
    with col_sel:
        active_model = st.selectbox("Inspect Model Evaluation", model_names, index=default_idx)
    with col_info:
        m_info = models_dict[active_model]
        cv_score = m_info.get("cv_macro_f1_mean", 0.0)
        st.markdown(
            f"**Validation Baseline:** CV Macro-F1 = `{cv_score:.3f}` &nbsp;|&nbsp; "
            f"**Tuned:** `{m_info.get('is_tuned', False)}` &nbsp;|&nbsp; "
            f"**Holdout Partition:** `{data.get('rows_test', 0):,}` flows",
        )

    holdout = m_info.get("holdout_metrics", {})

    # Top KPI Metrics Cards
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        st.markdown(render_kpi("Accuracy", f"{holdout.get('accuracy', 0.0)*100:.1f}%", "Overall Correct", "#38bdf8"), unsafe_allow_html=True)
    with k2:
        st.markdown(render_kpi("Macro-F1", f"{holdout.get('macro_f1', 0.0):.3f}", "Unweighted Class Mean", "#00f0ff"), unsafe_allow_html=True)
    with k3:
        st.markdown(render_kpi("Attack Recall", f"{holdout.get('recall_malicious', 0.0)*100:.1f}%", "True Positive Rate", "#10b981"), unsafe_allow_html=True)
    with k4:
        st.markdown(render_kpi("Attack Precision", f"{holdout.get('precision_malicious', 0.0)*100:.1f}%", "Alarm Fidelity", "#3b82f6"), unsafe_allow_html=True)
    with k5:
        fpr_v = holdout.get('false_positive_rate', 0.0)
        st.markdown(render_kpi("False Alarm (FPR)", f"{fpr_v*100:.2f}%", f"{holdout.get('false_positives', 0)} Benign Alarms", "#f59e0b" if fpr_v > 0.05 else "#10b981"), unsafe_allow_html=True)
    with k6:
        st.markdown(render_kpi("Inference Speed", f"{holdout.get('inference_latency_ms', 0.0):.3f}ms", "Per Flow Latency", "#a855f7"), unsafe_allow_html=True)

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # Tabs for Visualizations
    tab_cm, tab_perclass, tab_threshold, tab_tradeoff = st.tabs([
        "🔲 Confusion Matrix",
        "🎯 Per-Class Granular Metrics",
        "🎚️ Decision Threshold Optimizer",
        "⚖️ Security Trade-Off Analysis",
    ])

    with tab_cm:
        col_cm_plot, col_cm_desc = st.columns([3, 2])
        cm_data = holdout.get("confusion_matrix", [[0, 0], [0, 0]])
        cm_arr = np.array(cm_data)

        with col_cm_plot:
            labels = ["Benign", "Malicious"] if len(cm_arr) == 2 else [f"Class {i}" for i in range(len(cm_arr))]
            fig_cm = px.imshow(
                cm_arr,
                labels=dict(x="Predicted Class", y="Actual Ground Truth", color="Flows"),
                x=labels,
                y=labels,
                text_auto=True,
                color_continuous_scale="Blues",
            )
            fig_cm.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(15,23,42,0.6)",
                font_color="#f1f5f9",
                height=350,
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with col_cm_desc:
            st.markdown("##### 📌 Confusion Matrix Breakdown")
            if len(cm_arr) == 2:
                tn = holdout.get("true_negatives", 0)
                fp = holdout.get("false_positives", 0)
                fn = holdout.get("false_negatives", 0)
                tp = holdout.get("true_positives", 0)
                st.markdown(
                    f"""
                    <div class="netsentry-card">
                        <b>True Negatives (TN):</b> {tn:,} benign flows correctly permitted.<br>
                        <b>False Positives (FP):</b> {fp:,} benign flows wrongly flagged (False Alarms).<br>
                        <b>False Negatives (FN):</b> {fn:,} attacks that slipped past undetected (Breach Risk).<br>
                        <b>True Positives (TP):</b> {tp:,} attacks correctly intercepted.<br><br>
                        <b>False Alarm Rate (FPR):</b> {holdout.get('false_positive_rate', 0.0)*100:.2f}%<br>
                        <b>Missed Attack Rate (FNR):</b> {holdout.get('false_negative_rate', 0.0)*100:.2f}%
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.info("Multi-class confusion matrix displayed across all attack categories.")

    with tab_perclass:
        per_class = holdout.get("per_class", {})
        if per_class:
            pc_df = pd.DataFrame(per_class).T
            st.dataframe(pc_df.style.format({
                "precision": "{:.3f}",
                "recall": "{:.3f}",
                "f1": "{:.3f}",
                "support": "{:,.0f}",
            }), use_container_width=True)

            # Bar chart of per-class F1
            pc_plot_df = pc_df.reset_index().rename(columns={"index": "Class"})
            fig_pc = px.bar(
                pc_plot_df,
                x="Class",
                y=["precision", "recall", "f1"],
                barmode="group",
                title="Per-Class Precision, Recall, and F1-Score",
            )
            fig_pc.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(15,23,42,0.6)",
                font_color="#f1f5f9",
                height=320,
            )
            st.plotly_chart(fig_pc, use_container_width=True)
        else:
            st.write("Per-class breakdown not available.")

    with tab_threshold:
        st.markdown("##### 🎚️ Operational Alert Threshold Sweep")
        st.caption("Adjust the classification boundary from 0.05 to 0.95 to balance false alarms vs detection sensitivity.")

        # Interactive slider simulation
        current_thresh = st.slider("Active Decision Threshold (τ)", min_value=0.10, max_value=0.90, value=0.50, step=0.05)
        
        # Display simulated impact
        # As threshold increases: Precision increases, Recall decreases, FPR decreases
        base_p = holdout.get("precision_malicious", 0.8)
        base_r = holdout.get("recall_malicious", 0.8)
        
        sim_p = min(base_p * (1.0 + (current_thresh - 0.5) * 0.4), 0.999)
        sim_r = max(base_r * (1.0 - (current_thresh - 0.5) * 0.5), 0.05)
        sim_f1 = (2 * sim_p * sim_r) / max(sim_p + sim_r, 1e-4)
        sim_fpr = max(fpr_v * (1.0 - (current_thresh - 0.5) * 0.8), 0.001)

        t_col1, t_col2, t_col3, t_col4 = st.columns(4)
        with t_col1:
            st.markdown(render_kpi("Simulated Precision", f"{sim_p * 100:.1f}%", "Confidence of Alarm", "#38bdf8"), unsafe_allow_html=True)
        with t_col2:
            st.markdown(render_kpi("Simulated Recall", f"{sim_r * 100:.1f}%", "Attack Detection Rate", "#10b981"), unsafe_allow_html=True)
        with t_col3:
            st.markdown(render_kpi("Simulated Macro-F1", f"{sim_f1:.3f}", "Operating Balance", "#00f0ff"), unsafe_allow_html=True)
        with t_col4:
            st.markdown(render_kpi("Simulated FPR", f"{sim_fpr * 100:.2f}%", "False Alarm Burden", "#f59e0b" if sim_fpr > 0.03 else "#10b981"), unsafe_allow_html=True)

        st.markdown(
            f"""
            <div class="netsentry-card" style="margin-top: 15px;">
                <b>SOC Analyst Recommendation at τ = {current_thresh:.2f}:</b><br>
                {"High Security Posture: Catches maximum intrusions but causes elevated alert fatigue." if current_thresh < 0.4 else "Conservative Posture: Suppresses noisy false alarms; only triggers on high-confidence indicators." if current_thresh > 0.6 else "Balanced Posture: Standard operational baseline."}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with tab_tradeoff:
        st.markdown("##### ⚖️ Security Operations Trade-Off Analysis")
        st.markdown(
            """
            | Objective | Preferred Metric | Typical Consequence |
            | :--- | :--- | :--- |
            | **Catch Stealthy Zero-Days** | High Recall | Higher False Alarm Rate (FPR), causing alert fatigue in human analysts. |
            | **Automated Firewall Blocking** | High Precision & Low FPR | Misses low-and-slow probes, but guarantees critical services are not blocked. |
            | **Hardware Wire-Speed Filter** | Sub-millisecond Latency | Simpler models (Decision Tree/Logistic Regression) have lower F1 than deep ensembles. |
            | **Balanced Evaluation** | Macro-F1 & PR-AUC | Prevents deceptive 99% accuracy driven entirely by benign background traffic. |
            """
        )
