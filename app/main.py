"""NetSentry AI — Advanced ML Research Platform & Premium Security UI.

Entrypoint for the Streamlit research interface.
"""
from __future__ import annotations

import streamlit as st

# Configure page layout and metadata
st.set_page_config(
    page_title="NetSentry AI — Research Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom cybersecurity dark navy design system
from app.styles import CUSTOM_CSS, render_badge
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Import modular views
from app.views.overview import render_overview_view
from app.views.explorer import render_explorer_view
from app.views.model_lab import render_model_lab_view
from app.views.evaluation import render_evaluation_view
from app.views.traffic_analyzer import render_traffic_analyzer_view
from app.views.explainability import render_explainability_view
from app.views.research import render_research_view
from app.views.learn import render_learn_view


def main():
    # Sidebar Brand & Navigation
    with st.sidebar:
        st.markdown(
            """
            <div style="padding: 0.5rem 0 1rem 0;">
                <h2 style="margin: 0; color: #00f0ff; letter-spacing: -0.02em; font-weight: 700;">
                    🛡️ NetSentry AI
                </h2>
                <div style="font-size: 0.78rem; color: #94a3b8; font-weight: 500; letter-spacing: 0.04em; text-transform: uppercase;">
                    ML Research & Anomaly Platform
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        nav_options = [
            "🛡️ Overview",
            "🔍 Dataset Explorer",
            "🧪 Model Lab",
            "📊 Evaluation Center",
            "🛰️ Traffic Analyzer",
            "🧠 Explainability Lab",
            "🔬 Research Workbench",
            "🎓 Learn DCN + ML",
        ]

        active_tab = st.radio("Navigation", nav_options, index=0, label_visibility="collapsed")

        st.markdown("---")
        st.markdown("##### ⚙️ System Status")
        st.markdown(
            f"""
            <div style="display: flex; flex-direction: column; gap: 0.4rem;">
                <div>Engine: {render_badge("ONLINE", "safe")}</div>
                <div>Flow Ingestion: {render_badge("PCAP & Flow CSV", "info")}</div>
                <div>Leakage Guard: {render_badge("ENFORCED", "safe")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("---")
        st.markdown(
            """
            <div style="font-size: 0.75rem; color: #64748b; line-height: 1.4;">
                <b>NetSentry AI v2.0</b><br>
                Information Science & Engineering<br>
                Research & Academic Portfolio
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Route to designated view
    if active_tab == "🛡️ Overview":
        render_overview_view()
    elif active_tab == "🔍 Dataset Explorer":
        render_explorer_view()
    elif active_tab == "🧪 Model Lab":
        render_model_lab_view()
    elif active_tab == "📊 Evaluation Center":
        render_evaluation_view()
    elif active_tab == "🛰️ Traffic Analyzer":
        render_traffic_analyzer_view()
    elif active_tab == "🧠 Explainability Lab":
        render_explainability_view()
    elif active_tab == "🔬 Research Workbench":
        render_research_view()
    elif active_tab == "🎓 Learn DCN + ML":
        render_learn_view()


if __name__ == "__main__":
    main()
