"""Cybersecurity dark navy styling and custom UI components for NetSentry AI."""

CUSTOM_CSS = """
<style>
/* Base Dark Theme Overrides */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');

:root {
    --bg-darkest: #070b14;
    --bg-card: #0f172a;
    --bg-card-hover: #162036;
    --border-color: rgba(56, 189, 248, 0.18);
    --border-glow: rgba(0, 240, 255, 0.35);
    --cyan-accent: #00f0ff;
    --blue-accent: #38bdf8;
    --emerald-safe: #10b981;
    --amber-warning: #f59e0b;
    --crimson-threat: #f43f5e;
    --text-primary: #f1f5f9;
    --text-muted: #94a3b8;
}

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    color: var(--text-primary);
}

code, pre, [class*="mono"] {
    font-family: 'JetBrains Mono', monospace !important;
}

/* App Background */
.stApp {
    background: radial-gradient(circle at 15% 15%, #0f1c34 0%, #070b14 65%, #04070d 100%);
    background-attachment: fixed;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #0b1120 !important;
    border-right: 1px solid rgba(56, 189, 248, 0.15) !important;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNav"] {
    padding-top: 1rem;
}

/* Header & Card Containers */
.netsentry-card {
    background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(11, 17, 32, 0.95) 100%);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.35);
    backdrop-filter: blur(8px);
    transition: border-color 0.25s ease, box-shadow 0.25s ease;
}

.netsentry-card:hover {
    border-color: var(--border-glow);
    box-shadow: 0 6px 28px rgba(0, 240, 255, 0.08);
}

/* KPI Stat Badges */
.kpi-container {
    display: flex;
    flex-direction: column;
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(56, 189, 248, 0.15);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    border-left: 4px solid var(--cyan-accent);
}

.kpi-title {
    font-size: 0.82rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    margin-bottom: 0.35rem;
}

.kpi-value {
    font-size: 1.85rem;
    font-weight: 700;
    color: var(--text-primary);
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.1;
}

.kpi-subtitle {
    font-size: 0.75rem;
    color: var(--text-muted);
    margin-top: 0.35rem;
}

/* Status Pills */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem 0.65rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.status-pill-safe {
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.status-pill-threat {
    background: rgba(244, 63, 94, 0.15);
    color: #fb7185;
    border: 1px solid rgba(244, 63, 94, 0.3);
}

.status-pill-warning {
    background: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.status-pill-info {
    background: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.3);
}

/* SOC Alert Box */
.soc-alert {
    padding: 1rem 1.25rem;
    border-radius: 8px;
    margin: 1rem 0;
    border-left: 4px solid;
    background: rgba(15, 23, 42, 0.85);
}

.soc-alert-malicious {
    border-color: var(--crimson-threat);
    background: linear-gradient(90deg, rgba(244, 63, 94, 0.12) 0%, rgba(15, 23, 42, 0.9) 100%);
}

.soc-alert-benign {
    border-color: var(--emerald-safe);
    background: linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(15, 23, 42, 0.9) 100%);
}

/* Custom Table Polish */
div[data-testid="stTable"], div[data-testid="stDataFrame"] {
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border-color);
}

/* Tabs Header */
button[data-baseweb="tab"] {
    background-color: transparent !important;
    font-weight: 600 !important;
    padding: 0.6rem 1.2rem !important;
    border-radius: 6px !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    background: rgba(56, 189, 248, 0.12) !important;
    color: var(--cyan-accent) !important;
    border-bottom: 2px solid var(--cyan-accent) !important;
}

/* Clean Button Styling */
button[kind="primary"] {
    background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%) !important;
    border: 1px solid rgba(56, 189, 248, 0.4) !important;
    font-weight: 600 !important;
    letter-spacing: 0.02em !important;
    box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35) !important;
}

button[kind="primary"]:hover {
    box-shadow: 0 6px 20px rgba(0, 240, 255, 0.45) !important;
    border-color: var(--cyan-accent) !important;
}
</style>
"""


def render_kpi(title: str, value: str | int | float, subtitle: str = "", border_color: str = "#00f0ff") -> str:
    """Render an HTML KPI stat widget with neon accent border."""
    return f"""
    <div class="kpi-container" style="border-left-color: {border_color};">
        <div class="kpi-title">{title}</div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-subtitle">{subtitle}</div>
    </div>
    """


def render_badge(text: str, badge_type: str = "info") -> str:
    """Render a colored status pill."""
    type_class = f"status-pill-{badge_type}"
    return f'<span class="status-pill {type_class}">{text}</span>'
