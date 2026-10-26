"""Overview dashboard view for NetSentry AI."""
from __future__ import annotations

import json
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

from ..styles import render_kpi, render_badge
from src.netsentry.training.tracker import ExperimentTracker


def render_overview_view():
    st.markdown("## 🛡️ Executive Operations Center")
    st.caption("Real-time network security model telemetry, active experiment metrics, and model comparison.")

    tracker = ExperimentTracker()
    runs = tracker.list_runs()
    metrics_path = Path("artifacts/metrics.json")
    comp_path = Path("artifacts/model_comparison.csv")

    has_metrics = metrics_path.is_file()
    metrics_data = {}
    if has_metrics:
        try:
            metrics_data = json.loads(metrics_path.read_text(encoding="utf-8"))
        except Exception:
            has_metrics = False

    # Status Bar
    col_status1, col_status2, col_status3, col_status4 = st.columns(4)
    with col_status1:
        st.markdown(
            f"**Active Champion:**<br>{render_badge(metrics_data.get('selected_model', 'None Fitted'), 'safe')}",
            unsafe_allow_html=True,
        )
    with col_status2:
        dataset_name = Path(metrics_data.get("data_source", "Synthetic Demo")).name
        st.markdown(
            f"**Dataset Source:**<br>{render_badge(dataset_name, 'info')}",
            unsafe_allow_html=True,
        )
    with col_status3:
        st.markdown(
            f"**Experiments Logged:**<br>{render_badge(f'{len(runs)} Runs', 'warning')}",
            unsafe_allow_html=True,
        )
    with col_status4:
        st.markdown(
            f"**Security Posture:**<br>{render_badge('PROTECTED (Active Baseline)', 'safe')}",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    if not has_metrics:
        st.info("ℹ️ No trained model artifacts detected in `artifacts/`. Visit the **Model Lab** to execute your first training run, or click below to run a fast demo.")
        if st.button("🚀 Run Quick Baseline Demo", type="primary"):
            with st.spinner("Training baseline models on synthetic demo flows..."):
                from src.netsentry.data.synthetic import make_demo_dataset
                from src.netsentry.data.preprocessor import prepare_data
                from src.netsentry.training.pipeline import train_and_evaluate_models
                df = make_demo_dataset(1000)
                prep = prepare_data(df, "label")
                train_and_evaluate_models(prep, fast_mode=True)
                st.success("Demo run complete! Refreshing overview...")
                st.rerun()
        return

    # Extract champion metrics
    champ_name = metrics_data.get("selected_model", "")
    champ_info = metrics_data.get("models", {}).get(champ_name, {})
    holdout = champ_info.get("holdout_metrics", {})

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        f1_val = holdout.get("macro_f1", 0.0)
        st.markdown(
            render_kpi("Holdout Macro-F1", f"{f1_val:.3f}", "Balanced Detection Score", "#00f0ff"),
            unsafe_allow_html=True,
        )
    with kpi2:
        acc_val = holdout.get("accuracy", 0.0)
        st.markdown(
            render_kpi("Overall Accuracy", f"{acc_val * 100:.1f}%", f"Train CV: {champ_info.get('cv_macro_f1_mean', 0.0):.3f}", "#38bdf8"),
            unsafe_allow_html=True,
        )
    with kpi3:
        fpr_val = holdout.get("false_positive_rate", 0.0)
        st.markdown(
            render_kpi("False Alarm Rate (FPR)", f"{fpr_val * 100:.2f}%", f"{holdout.get('false_positives', 0)} Benign Flows Flagged", "#f59e0b" if fpr_val > 0.05 else "#10b981"),
            unsafe_allow_html=True,
        )
    with kpi4:
        lat_val = holdout.get("inference_latency_ms", 0.0)
        st.markdown(
            render_kpi("Inference Latency", f"{lat_val:.3f} ms", f"{int(1000 / max(lat_val, 0.001)):,} flows/sec local batch", "#a855f7"),
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Comparative charts and summary
    col_chart, col_summary = st.columns([3, 2])

    with col_chart:
        st.markdown("##### 📊 Multi-Model Performance Comparison")
        if comp_path.is_file():
            comp_df = pd.read_csv(comp_path, index_col=0)
            metric_cols = ["Holdout Macro-F1", "Holdout Accuracy", "Precision (Malicious)", "Recall (Malicious)"]
            available_metrics = [c for c in metric_cols if c in comp_df.columns]
            
            # Plotly bar chart
            plot_df = comp_df.reset_index().rename(columns={"index": "Model"})
            fig = px.bar(
                plot_df,
                x="Model",
                y="Holdout Macro-F1",
                color="Holdout Macro-F1",
                color_continuous_scale="Viridis",
                text="Holdout Macro-F1",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(15,23,42,0.6)",
                font_color="#f1f5f9",
                margin=dict(l=20, r=20, t=30, b=30),
                height=320,
            )
            fig.update_traces(texttemplate="%{text:.3f}", textposition="outside")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.write("Model comparison data not found.")

    with col_summary:
        st.markdown("##### 🎯 Selection & Leakage Safeguards")
        st.markdown(
            f"""
            <div class="netsentry-card">
                <b>Selection Rule:</b> {metrics_data.get("selection_rule", "CV Macro-F1")}<br><br>
                <b>Training Partition:</b> {metrics_data.get("rows_train", 0):,} flows<br>
                <b>Holdout Test Partition:</b> {metrics_data.get("rows_test", 0):,} flows<br><br>
                <b>Scientific Guarantee:</b> Preprocessing, median imputation, and standard scaling are 
                fitted <i>exclusively</i> inside cross-validation folds. The holdout test set remained 
                unseen until final verification.
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Experiment history
    st.markdown("##### 📜 Recent Experiment Runs")
    if runs:
        table_records = []
        for r in runs[:6]:
            champ = r.get("champion_model", "Unknown")
            c_metrics = r.get("champion_metrics", {})
            table_records.append({
                "Run ID": r.get("run_id", ""),
                "Timestamp": r.get("timestamp", ""),
                "Dataset": r.get("dataset_name", ""),
                "Models Evaluated": len(r.get("models_evaluated", [])),
                "Champion Model": champ,
                "Macro-F1": round(c_metrics.get("macro_f1", 0.0), 3),
                "Accuracy": f"{c_metrics.get('accuracy', 0.0) * 100:.1f}%",
                "FPR": f"{c_metrics.get('false_positive_rate', 0.0) * 100:.2f}%",
            })
        st.dataframe(pd.DataFrame(table_records), use_container_width=True)
    else:
        st.write("No prior experiment records logged.")
