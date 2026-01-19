"""Bottleneck analysis panel widget."""

from textual.widgets import Static
from typing import Dict, Optional

from ...models.metrics import InterfaceMetrics
from ...analysis.bottleneck_detector import BottleneckDetector


class BottleneckPanel(Static):
    """Panel showing bottleneck analysis for all interfaces."""

    DEFAULT_CSS = """
    BottleneckPanel {
        height: auto;
        padding: 1;
        background: $surface;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._analysis: Dict[str, dict] = {}

    def update_analysis(
        self,
        all_metrics: Dict[str, InterfaceMetrics],
        detector: BottleneckDetector
    ) -> None:
        """Update bottleneck analysis."""
        self._analysis = {}
        for iface, metrics in all_metrics.items():
            result = detector.get_overall_health(iface, metrics)
            self._analysis[iface] = result
        self.refresh()

    def render(self) -> str:
        """Render the bottleneck panel."""
        lines = ["[bold red]BOTTLENECK ANALYSIS[/bold red]", ""]

        if not self._analysis:
            lines.append("[dim]Analyzing...[/dim]")
            return "\n".join(lines)

        for iface, analysis in self._analysis.items():
            status = analysis.get("status", "unknown")
            health = analysis.get("health_score", 100)
            bottlenecks = analysis.get("bottlenecks", [])

            # Status color
            if status == "healthy":
                status_color = "green"
            elif status in ("minor_issues", "warning"):
                status_color = "yellow"
            else:
                status_color = "red"

            # Health color
            if health >= 90:
                health_color = "green"
            elif health >= 70:
                health_color = "yellow"
            else:
                health_color = "red"

            lines.append(f"[bold]{iface}[/bold]")
            lines.append(
                f"  Status: [{status_color}]{status.upper()}[/{status_color}]  "
                f"Health: [{health_color}]{health:.0f}/100[/{health_color}]"
            )

            if bottlenecks:
                lines.append("  [dim]Issues detected:[/dim]")
                for bottleneck in bottlenecks[:3]:
                    severity = bottleneck.get("severity", "low")
                    if severity == "high" or severity == "critical":
                        sev_color = "red"
                    elif severity == "medium":
                        sev_color = "yellow"
                    else:
                        sev_color = "white"

                    issue_type = bottleneck.get("type", "unknown")
                    lines.append(f"    [{sev_color}]- {issue_type}[/{sev_color}]")

                    # Show recommendation if available
                    rec = bottleneck.get("recommendation", "")
                    if rec:
                        lines.append(f"      [dim]{rec[:45]}...[/dim]" if len(rec) > 45 else f"      [dim]{rec}[/dim]")
            else:
                lines.append("  [green]No bottlenecks detected[/green]")

            lines.append("")

        return "\n".join(lines)
