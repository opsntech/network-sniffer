"""Flow table widget showing top network flows."""

from textual.widgets import Static
from typing import List

from ...models.flow import Flow


class FlowTableWidget(Static):
    """Table showing top network flows."""

    DEFAULT_CSS = """
    FlowTableWidget {
        height: 100%;
        padding: 1;
        background: $surface;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._flows: List[Flow] = []

    def update_flows(self, flows: List[Flow]) -> None:
        """Update displayed flows."""
        self._flows = flows
        self.refresh()

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable."""
        if bytes_val >= 1_000_000_000:
            return f"{bytes_val / 1_000_000_000:.1f}GB"
        elif bytes_val >= 1_000_000:
            return f"{bytes_val / 1_000_000:.1f}MB"
        elif bytes_val >= 1_000:
            return f"{bytes_val / 1_000:.1f}KB"
        else:
            return f"{bytes_val}B"

    def render(self) -> str:
        """Render the flow table."""
        lines = ["[bold blue]TOP FLOWS[/bold blue]", ""]

        if not self._flows:
            lines.append("[dim]No flows captured yet...[/dim]")
            return "\n".join(lines)

        # Header
        lines.append(
            "[dim]"
            f"{'Source':<22} {'Destination':<22} {'Proto':<6} {'Bytes':>8} {'Loss':>6}"
            "[/dim]"
        )
        lines.append("[dim]" + "-" * 70 + "[/dim]")

        for flow in self._flows[:10]:
            # Source
            src = f"{flow.key.src_ip}"
            if flow.key.src_port:
                src += f":{flow.key.src_port}"
            src = src[:21]

            # Destination
            dst = f"{flow.key.dst_ip}"
            if flow.key.dst_port:
                dst += f":{flow.key.dst_port}"
            dst = dst[:21]

            # Protocol
            proto = flow.key.protocol.value[:5].upper()

            # Bytes
            bytes_str = self._format_bytes(flow.total_bytes)

            # Loss rate
            loss = flow.packet_loss_rate
            if loss < 0.5:
                loss_color = "green"
            elif loss < 2:
                loss_color = "yellow"
            else:
                loss_color = "red"
            loss_str = f"[{loss_color}]{loss:5.1f}%[/{loss_color}]"

            lines.append(f"{src:<22} {dst:<22} {proto:<6} {bytes_str:>8} {loss_str}")

        return "\n".join(lines)
