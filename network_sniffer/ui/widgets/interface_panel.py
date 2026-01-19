"""Interface status panel widget."""

from textual.widgets import Static
from textual.reactive import reactive
from typing import Optional

from ...models.metrics import InterfaceMetrics


class InterfacePanel(Static):
    """Panel showing metrics for a single interface."""

    DEFAULT_CSS = """
    InterfacePanel {
        height: auto;
        padding: 1;
        background: $surface;
    }

    InterfacePanel .title {
        text-style: bold;
        color: $primary;
    }

    InterfacePanel .metric-row {
        height: 1;
    }

    InterfacePanel .label {
        width: 15;
        color: $text-muted;
    }

    InterfacePanel .value {
        width: 15;
    }

    InterfacePanel .good {
        color: $success;
    }

    InterfacePanel .warning {
        color: $warning;
    }

    InterfacePanel .critical {
        color: $error;
    }
    """

    def __init__(self, interface: str, **kwargs):
        super().__init__(**kwargs)
        self.interface = interface
        self._metrics: Optional[InterfaceMetrics] = None

    def update_metrics(self, metrics: InterfaceMetrics) -> None:
        """Update displayed metrics."""
        self._metrics = metrics
        self.refresh()

    def render(self) -> str:
        """Render the panel content."""
        lines = [f"[bold cyan]{self.interface}[/bold cyan]"]
        lines.append("")

        if not self._metrics:
            lines.append("[dim]Waiting for data...[/dim]")
            return "\n".join(lines)

        m = self._metrics

        # Status line
        status = "[green]CAPTURING[/green]"
        lines.append(f"  Status: {status}")

        # Packets
        lines.append(f"  Packets: [white]{m.total_packets:,}[/white]")

        # Bandwidth
        lines.append(f"  Bandwidth: [white]{m.bandwidth_mbps:.2f} Mbps[/white]")

        # Packet Loss with color coding
        loss = m.packet_loss_rate
        if loss < 0.5:
            loss_color = "green"
        elif loss < 2:
            loss_color = "yellow"
        else:
            loss_color = "red"
        lines.append(f"  Packet Loss: [{loss_color}]{loss:.2f}%[/{loss_color}]")

        # Latency
        latency = m.avg_latency
        if latency < 50:
            lat_color = "green"
        elif latency < 150:
            lat_color = "yellow"
        else:
            lat_color = "red"
        lines.append(f"  Latency: [{lat_color}]{latency:.1f} ms[/{lat_color}]")

        # P95 Latency
        p95 = m.get_latency_percentile(95) or 0
        lines.append(f"  P95 Latency: [white]{p95:.1f} ms[/white]")

        # Jitter
        jitter = m.avg_jitter
        if jitter < 10:
            jit_color = "green"
        elif jitter < 30:
            jit_color = "yellow"
        else:
            jit_color = "red"
        lines.append(f"  Jitter: [{jit_color}]{jitter:.1f} ms[/{jit_color}]")

        # Retransmissions
        retrans = m.retransmissions
        if retrans == 0:
            retrans_color = "green"
        elif retrans < 100:
            retrans_color = "yellow"
        else:
            retrans_color = "red"
        lines.append(f"  Retransmits: [{retrans_color}]{retrans:,}[/{retrans_color}]")

        # Health Score (calculated inline)
        health = self._calculate_health()
        if health >= 90:
            health_color = "green"
        elif health >= 70:
            health_color = "yellow"
        else:
            health_color = "red"
        lines.append(f"  Health: [{health_color}]{health:.0f}/100[/{health_color}]")

        return "\n".join(lines)

    def _calculate_health(self) -> float:
        """Calculate health score for the interface."""
        if not self._metrics:
            return 100.0

        score = 100.0
        m = self._metrics

        # Packet loss penalty (weight: 40%)
        loss = m.packet_loss_rate
        if loss > 0:
            score -= min(40, loss * 20)

        # Latency penalty (weight: 30%)
        latency = m.avg_latency
        if latency > 0:
            score -= min(30, (latency / 200) * 30)

        # Jitter penalty (weight: 20%)
        jitter = m.avg_jitter
        if jitter > 0:
            score -= min(20, (jitter / 50) * 20)

        # Retransmit penalty (weight: 10%)
        retrans_rate = m.retransmissions / max(m.total_packets, 1) * 100
        if retrans_rate > 0:
            score -= min(10, retrans_rate * 5)

        return max(0, score)
