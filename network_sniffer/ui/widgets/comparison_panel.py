"""Comparison panel widget for comparing two interfaces."""

from textual.widgets import Static
from typing import Optional

from ...analysis.comparator import ComparisonResult


class ComparisonPanel(Static):
    """Panel showing side-by-side interface comparison."""

    DEFAULT_CSS = """
    ComparisonPanel {
        height: auto;
        padding: 1;
        background: $surface;
    }
    """

    def __init__(
        self,
        interface_a: str,
        interface_b: str,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.interface_a = interface_a
        self.interface_b = interface_b
        self._result: Optional[ComparisonResult] = None

    def update_comparison(self, result: ComparisonResult) -> None:
        """Update comparison result."""
        self._result = result
        self.refresh()

    def render(self) -> str:
        """Render the comparison panel."""
        lines = ["[bold cyan]INTERFACE COMPARISON[/bold cyan]", ""]

        if not self._result:
            lines.append("[dim]Collecting data...[/dim]")
            return "\n".join(lines)

        r = self._result

        # Interface names header
        lines.append(f"  [bold]{r.interface_a:^15}[/bold]  vs  [bold]{r.interface_b:^15}[/bold]")
        lines.append("")

        # Metrics comparison
        metrics_to_show = [
            ("Latency", "latency_ms", "latency", "ms", True),  # lower is better
            ("Jitter", "jitter_ms", "jitter", "ms", True),
            ("Loss", "loss_percent", "packet_loss", "%", True),
            ("Bandwidth", "bandwidth_mbps", "bandwidth", "Mbps", False),  # higher is better
        ]

        for label, metric_key, winner_key, unit, lower_better in metrics_to_show:
            val_a = r.metrics_a.get(metric_key, 0)
            val_b = r.metrics_b.get(metric_key, 0)
            winner = r.winners.get(winner_key, "tie")

            # Determine colors
            if winner == r.interface_a:
                color_a = "green"
                color_b = "red"
            elif winner == r.interface_b:
                color_a = "red"
                color_b = "green"
            else:
                color_a = color_b = "white"

            # Format values
            if "percent" in metric_key or unit == "%":
                val_a_str = f"{val_a:6.2f}{unit}"
                val_b_str = f"{val_b:6.2f}{unit}"
            else:
                val_a_str = f"{val_a:6.1f}{unit}"
                val_b_str = f"{val_b:6.1f}{unit}"

            lines.append(
                f"  {label:10} [{color_a}]{val_a_str:>12}[/{color_a}]  vs  "
                f"[{color_b}]{val_b_str:<12}[/{color_b}]"
            )

        lines.append("")

        # Overall scores
        score_a = r.score_a
        score_b = r.score_b

        if score_a > score_b:
            score_a_style = "bold green"
            score_b_style = "red"
        elif score_b > score_a:
            score_a_style = "red"
            score_b_style = "bold green"
        else:
            score_a_style = score_b_style = "yellow"

        lines.append(
            f"  [bold]Score[/bold]      [{score_a_style}]{score_a:>10.0f}[/{score_a_style}]  vs  "
            f"[{score_b_style}]{score_b:<10.0f}[/{score_b_style}]"
        )

        lines.append("")

        # Winner
        if r.overall_winner != "tie":
            lines.append(f"  [bold green]WINNER: {r.overall_winner}[/bold green]")
            lines.append(f"  Confidence: {r.confidence * 100:.0f}%")
        else:
            lines.append("  [yellow]RESULT: Tie[/yellow]")

        lines.append("")

        # Recommendation
        lines.append("[dim]Recommendation:[/dim]")
        # Word wrap recommendation
        rec = r.recommendation
        words = rec.split()
        current_line = "  "
        for word in words:
            if len(current_line) + len(word) + 1 > 55:
                lines.append(current_line)
                current_line = "  " + word
            else:
                current_line += " " + word if current_line.strip() else "  " + word
        if current_line.strip():
            lines.append(current_line)

        return "\n".join(lines)
