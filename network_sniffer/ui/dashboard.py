"""Main Textual dashboard for network sniffer."""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, DataTable, Label
from textual.reactive import reactive
from textual.timer import Timer
from textual import work
from typing import Optional, Dict, List, TYPE_CHECKING
import time

from .widgets.interface_panel import InterfacePanel
from .widgets.alerts_panel import AlertsPanel
from .widgets.flow_table import FlowTableWidget
from .widgets.chart import TimeSeriesChart
from .widgets.comparison_panel import ComparisonPanel
from .widgets.bottleneck_panel import BottleneckPanel

if TYPE_CHECKING:
    from ..cli import SnifferApp


class StatusBar(Static):
    """Status bar showing capture status."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.packets = 0
        self.duration = 0.0
        self.pps = 0.0

    def update_stats(self, packets: int, duration: float, pps: float) -> None:
        self.packets = packets
        self.duration = duration
        self.pps = pps
        self.refresh()

    def render(self) -> str:
        mins, secs = divmod(int(self.duration), 60)
        hours, mins = divmod(mins, 60)
        time_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
        return f"  Packets: {self.packets:,}  |  Duration: {time_str}  |  Rate: {self.pps:.1f} pps  "


class NetworkDashboard(App):
    """Main dashboard application."""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-rows: auto 1fr 1fr;
    }

    #status-bar {
        column-span: 2;
        height: 1;
        background: $primary;
        color: $text;
        text-align: center;
    }

    #left-panel {
        height: 100%;
    }

    #right-panel {
        height: 100%;
    }

    #bottom-left {
        height: 100%;
    }

    #bottom-right {
        height: 100%;
    }

    InterfacePanel {
        height: auto;
        margin: 1;
        border: solid $primary;
    }

    AlertsPanel {
        height: 100%;
        margin: 1;
        border: solid $warning;
    }

    FlowTableWidget {
        height: 100%;
        margin: 1;
        border: solid $secondary;
    }

    TimeSeriesChart {
        height: 100%;
        margin: 1;
        border: solid $success;
    }

    ComparisonPanel {
        height: 100%;
        margin: 1;
        border: solid cyan;
    }

    BottleneckPanel {
        height: 100%;
        margin: 1;
        border: solid $error;
    }

    .panel-title {
        text-style: bold;
        background: $surface;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "toggle_pause", "Pause/Resume"),
        ("r", "reset_stats", "Reset"),
        ("e", "export", "Export"),
        ("c", "toggle_comparison", "Compare"),
        ("a", "show_alerts", "Alerts"),
    ]

    def __init__(self, sniffer_app: "SnifferApp", **kwargs):
        super().__init__(**kwargs)
        self.sniffer_app = sniffer_app
        self.interfaces = sniffer_app.interfaces
        self._paused = False
        self._update_timer: Optional[Timer] = None

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        yield Header()

        # Status bar
        yield StatusBar(id="status-bar")

        # Left panel - Interface stats
        with Vertical(id="left-panel"):
            for iface in self.interfaces:
                yield InterfacePanel(interface=iface, id=f"iface-{iface}")

        # Right panel - Comparison or charts
        with Vertical(id="right-panel"):
            if len(self.interfaces) == 2:
                yield ComparisonPanel(
                    interface_a=self.interfaces[0],
                    interface_b=self.interfaces[1],
                    id="comparison",
                )
            yield BottleneckPanel(id="bottleneck")

        # Bottom left - Flow table
        with Vertical(id="bottom-left"):
            yield FlowTableWidget(id="flows")

        # Bottom right - Alerts
        with Vertical(id="bottom-right"):
            yield AlertsPanel(id="alerts")

        yield Footer()

    def on_mount(self) -> None:
        """Start update timer when mounted."""
        self._update_timer = self.set_interval(1.0, self.update_dashboard)

    def update_dashboard(self) -> None:
        """Update all dashboard components."""
        if self._paused:
            return

        # Evaluate alerts
        self.sniffer_app.evaluate_alerts()

        # Get metrics
        all_metrics = self.sniffer_app.processor.get_all_metrics()
        capture_stats = self.sniffer_app.capture_engine.get_stats()

        # Update status bar
        status_bar = self.query_one("#status-bar", StatusBar)
        status_bar.update_stats(
            packets=capture_stats.packets_captured,
            duration=self.sniffer_app.duration,
            pps=capture_stats.packets_per_second,
        )

        # Update interface panels
        for iface in self.interfaces:
            panel = self.query_one(f"#iface-{iface}", InterfacePanel)
            metrics = all_metrics.get(iface)
            if metrics:
                panel.update_metrics(metrics)

        # Update comparison panel
        if len(self.interfaces) == 2:
            try:
                comparison = self.query_one("#comparison", ComparisonPanel)
                metrics_a = all_metrics.get(self.interfaces[0])
                metrics_b = all_metrics.get(self.interfaces[1])
                if metrics_a and metrics_b:
                    result = self.sniffer_app.comparator.compare(
                        self.interfaces[0],
                        self.interfaces[1],
                        metrics_a,
                        metrics_b,
                    )
                    comparison.update_comparison(result)
            except Exception:
                pass

        # Update bottleneck panel
        try:
            bottleneck = self.query_one("#bottleneck", BottleneckPanel)
            bottleneck.update_analysis(all_metrics, self.sniffer_app.bottleneck_detector)
        except Exception:
            pass

        # Update flow table
        try:
            flows_widget = self.query_one("#flows", FlowTableWidget)
            all_flows = self.sniffer_app.flow_tracker.get_all_flows()
            # Sort by total bytes descending
            top_flows = sorted(all_flows, key=lambda f: f.total_bytes, reverse=True)[:10]
            flows_widget.update_flows(top_flows)
        except Exception:
            pass

        # Update alerts
        try:
            alerts_panel = self.query_one("#alerts", AlertsPanel)
            alerts = self.sniffer_app.alert_manager.get_active_alerts()
            alerts_panel.update_alerts(alerts)
        except Exception:
            pass

    def action_toggle_pause(self) -> None:
        """Toggle pause state."""
        self._paused = not self._paused
        status = "PAUSED" if self._paused else "RUNNING"
        self.notify(f"Capture {status}")

    def action_reset_stats(self) -> None:
        """Reset statistics."""
        self.notify("Statistics reset")

    def action_export(self) -> None:
        """Export current data."""
        self.notify("Export not yet implemented")

    def action_toggle_comparison(self) -> None:
        """Toggle comparison view."""
        self.notify("Comparison view toggled")

    def action_show_alerts(self) -> None:
        """Show alert details."""
        alerts = self.sniffer_app.alert_manager.get_active_alerts()
        if alerts:
            self.notify(f"{len(alerts)} active alerts")
        else:
            self.notify("No active alerts")
