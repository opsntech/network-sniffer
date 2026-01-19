"""Alerts panel widget."""

from textual.widgets import Static
from typing import List

from ...alerts.alert_manager import Alert, AlertSeverity


class AlertsPanel(Static):
    """Panel showing active alerts."""

    DEFAULT_CSS = """
    AlertsPanel {
        height: 100%;
        padding: 1;
        background: $surface;
    }

    AlertsPanel .title {
        text-style: bold;
        color: $warning;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._alerts: List[Alert] = []

    def update_alerts(self, alerts: List[Alert]) -> None:
        """Update displayed alerts."""
        self._alerts = alerts
        self.refresh()

    def render(self) -> str:
        """Render the alerts panel."""
        lines = ["[bold yellow]ALERTS[/bold yellow]", ""]

        if not self._alerts:
            lines.append("[green]No active alerts[/green]")
            return "\n".join(lines)

        # Sort by severity (critical first)
        sorted_alerts = sorted(
            self._alerts,
            key=lambda a: (
                0 if a.severity == AlertSeverity.CRITICAL else
                1 if a.severity == AlertSeverity.WARNING else 2
            )
        )

        for alert in sorted_alerts[:10]:  # Show max 10
            if alert.severity == AlertSeverity.CRITICAL:
                prefix = "[bold red][CRITICAL][/bold red]"
            elif alert.severity == AlertSeverity.WARNING:
                prefix = "[yellow][WARNING][/yellow]"
            else:
                prefix = "[blue][INFO][/blue]"

            # Truncate message if too long
            msg = alert.message
            if len(msg) > 50:
                msg = msg[:47] + "..."

            lines.append(f"  {prefix} {msg}")
            lines.append(f"    [dim]{alert.interface} - {alert.duration_str} ago[/dim]")

        # Show total count if more
        if len(self._alerts) > 10:
            lines.append(f"  [dim]... and {len(self._alerts) - 10} more[/dim]")

        return "\n".join(lines)
