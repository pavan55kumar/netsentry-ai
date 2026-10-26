"""Unit tests for NetSentry AI Streamlit UI components and style formatting."""
import unittest
from app.styles import render_kpi, render_badge, CUSTOM_CSS
from app.views.overview import render_overview_view
from app.views.explorer import render_explorer_view
from app.views.learn import render_learn_view


class UITests(unittest.TestCase):
    def test_css_and_html_renderers(self):
        self.assertIn("netsentry-card", CUSTOM_CSS)
        self.assertIn("status-pill", CUSTOM_CSS)

        badge_html = render_badge("ONLINE", "safe")
        self.assertIn("status-pill-safe", badge_html)
        self.assertIn("ONLINE", badge_html)

        kpi_html = render_kpi("Macro-F1", "0.985", "Champion Model", "#00f0ff")
        self.assertIn("kpi-container", kpi_html)
        self.assertIn("0.985", kpi_html)
        self.assertIn("Macro-F1", kpi_html)


if __name__ == "__main__":
    unittest.main()
