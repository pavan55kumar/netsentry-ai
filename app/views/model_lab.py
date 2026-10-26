"""Model Lab interactive training and benchmark workbench for NetSentry AI."""
from __future__ import annotations

from pathlib import Path
import pandas as pd
import streamlit as st

from src.netsentry.data.preprocessor import prepare_data
from src.netsentry.data.loader import load_csv
from src.netsentry.models.factory import get_available_models, BASE_MODELS, ADVANCED_MODELS
from src.netsentry.training.pipeline import train_and_evaluate_models
from ..styles import render_badge


def render_model_lab_view():
    st.markdown("## 🧪 Model Lab & Training Pipeline")
    st.caption("Configure algorithms, leakage-free cross-validation, hyperparameter tuning, and train champion models.")

    # Check for active dataset
    df = st.session_state.get("loaded_df", None)
    if df is None:
        default_sample = Path("data/sample/cicids2017_sample.csv")
        if default_sample.is_file():
            df = load_csv(default_sample)
            st.session_state["loaded_df"] = df
            st.session_state["loaded_source_name"] = default_sample.name
        else:
            st.info("No active dataset loaded. Please visit the **Dataset Explorer** first.")
            return

    ds_name = st.session_state.get("loaded_source_name", "Active Dataset")
    st.markdown(f"**Training Source:** `{ds_name}` ({len(df):,} flows, {len(df.columns)} columns)")

    # Model Selection
    st.markdown("##### 1. Select Algorithms to Benchmark")
    available_models = get_available_models()

    col_m1, col_m2 = st.columns(2)
    selected_models = []

    with col_m1:
        st.markdown("**Base Supervised Algorithms:**")
        for k in BASE_MODELS:
            spec = available_models[k]
            default_check = k in ["logistic_regression", "random_forest_500", "hist_gradient_boosting"]
            if st.checkbox(f"{spec.display_name} ({spec.family})", value=default_check, key=f"chk_{k}"):
                selected_models.append(k)

    with col_m2:
        st.markdown("**Advanced & Unsupervised Algorithms:**")
        for k in ADVANCED_MODELS:
            spec = available_models[k]
            default_check = k in ["support_vector_machine", "isolation_forest"]
            badge_text = "Unsupervised" if spec.is_unsupervised else spec.family
            if st.checkbox(f"{spec.display_name} [{badge_text}]", value=default_check, key=f"chk_{k}"):
                selected_models.append(k)

    if not selected_models:
        st.warning("⚠️ Please select at least one algorithm to train.")
        return

    # Configuration Options
    st.markdown("##### 2. Scientific Experiment Settings")
    col_c1, col_c2, col_c3 = st.columns(3)

    with col_c1:
        test_size = st.slider("Holdout Test Size", min_value=0.15, max_value=0.35, value=0.25, step=0.05)
        cv_folds = st.slider("Training Cross-Validation Folds", min_value=2, max_value=7, value=5)

    with col_c2:
        split_strat = st.selectbox("Partitioning Strategy", ["stratified", "temporal", "group"], index=0)
        fast_mode = st.checkbox("⚡ Fast Laptop Mode (Reduced Estimators)", value=True, help="Trains in seconds by using 100 trees instead of 500.")

    with col_c3:
        tune_models = st.checkbox("🔍 RandomizedSearchCV Hyperparameter Tuning", value=False, help="Optimizes hyperparameters on training folds.")
        multiclass = st.checkbox("🎯 Multi-Class Target Classification", value=False, help="Preserves individual attack categories instead of binary grouping.")

    # Target Column & Exclusions
    label_candidates = [c for c in df.columns if any(k in c.lower() for k in ["label", "attack", "class", "target", "category"])]
    default_lbl = label_candidates[0] if label_candidates else df.columns[-1]

    col_target, col_drop = st.columns([1, 2])
    with col_target:
        label_col = st.selectbox("Target Label Column", list(df.columns), index=list(df.columns).index(default_lbl))
    with col_drop:
        potential_drops = [c for c in df.columns if any(k in c.lower() for k in ["flow id", "flow_id", "timestamp", "src ip", "dst ip"])]
        extra_drops = st.multiselect("Columns to Exclude (Prevent Leakage)", list(df.columns), default=potential_drops)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Launch Training
    if st.button("🚀 Launch Training & Evaluation Pipeline", type="primary"):
        progress_bar = st.progress(0.0)
        status_text = st.empty()

        def update_progress(msg: str, pct: float):
            status_text.text(f"⏳ {msg}")
            progress_bar.progress(pct)

        try:
            update_progress("Cleaning data and creating un-leaked partitions...", 0.05)
            prepared = prepare_data(
                frame=df,
                label_column=label_col,
                test_size=test_size,
                extra_drop_columns=extra_drops,
                multiclass=multiclass,
                split_strategy=split_strat,
            )

            result = train_and_evaluate_models(
                prepared=prepared,
                model_keys=selected_models,
                cv_folds=cv_folds,
                tune_models=tune_models,
                fast_mode=fast_mode,
                progress_callback=update_progress,
            )

            status_text.empty()
            progress_bar.empty()

            st.success(f"🎉 Pipeline Execution Complete! Champion model selected: **{result.champion_model_name}**")

            # Display Results Table
            st.markdown("##### 🏆 Multi-Model Benchmark Results")
            st.dataframe(result.comparison_table, use_container_width=True)

            # Accuracy Trap Callout
            base_info = result.baseline_summary
            st.markdown(
                f"""
                <div class="soc-alert soc-alert-benign">
                    <b>⚠️ The Accuracy Trap Baseline Check:</b> {base_info.get('accuracy_trap_explanation', '')}
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Download comparison CSV
            csv_data = result.comparison_table.to_csv().encode("utf-8")
            st.download_button(
                "📥 Download Benchmark Comparison CSV",
                data=csv_data,
                file_name="netsentry_model_comparison.csv",
                mime="text/csv",
            )

        except Exception as e:
            status_text.empty()
            progress_bar.empty()
            st.error(f"❌ Training Pipeline Error: {e}")
