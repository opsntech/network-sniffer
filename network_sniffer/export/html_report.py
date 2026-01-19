"""HTML report generator for network diagnostics."""

from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from ..models.metrics import InterfaceMetrics
from ..models.flow import Flow
from ..alerts.alert_manager import Alert, AlertSeverity
from ..analysis.comparator import ComparisonResult


class HTMLReportGenerator:
    """Generate standalone HTML diagnostic reports."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        metrics: Dict[str, InterfaceMetrics],
        flows: List[Flow],
        alerts: List[Alert],
        comparison: Optional[ComparisonResult] = None,
        title: str = "Network Diagnostic Report",
        filename: Optional[str] = None
    ) -> str:
        """Generate complete HTML diagnostic report."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.html"

        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin: 30px 0 15px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h3 {{ color: #4ecdc4; margin: 20px 0 10px; }}
        .meta {{ color: #888; margin-bottom: 30px; }}
        .card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        th {{ background: #0f3460; color: #00d4ff; }}
        tr:hover {{ background: #1a3a5c; }}
        .good {{ color: #4ecdc4; }}
        .warning {{ color: #ffd93d; }}
        .critical {{ color: #ff6b6b; }}
        .metric-value {{ font-size: 24px; font-weight: bold; }}
        .metric-label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
        .alert-item {{
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .alert-critical {{ background: rgba(255,107,107,0.1); border-color: #ff6b6b; }}
        .alert-warning {{ background: rgba(255,217,61,0.1); border-color: #ffd93d; }}
        .winner {{ background: linear-gradient(135deg, #4ecdc4, #44a08d); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: bold; }}
        .recommendation {{
            background: #0f3460;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #00d4ff;
            margin-top: 15px;
        }}
        .progress-bar {{
            height: 8px;
            background: #333;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }}
        .progress-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }}
        footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p class="meta">Generated: {report_time}</p>

        {self._generate_summary_section(metrics, alerts, comparison)}

        {self._generate_comparison_section(comparison) if comparison else ""}

        {self._generate_interface_sections(metrics)}

        {self._generate_alerts_section(alerts)}

        {self._generate_flows_section(flows)}

        <footer>
            <p>Network Sniffer Diagnostic Report</p>
            <p>Use this report as evidence for vendor escalation</p>
        </footer>
    </div>
</body>
</html>"""

        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            f.write(html)

        return str(filepath)

    def _generate_summary_section(
        self,
        metrics: Dict[str, InterfaceMetrics],
        alerts: List[Alert],
        comparison: Optional[ComparisonResult]
    ) -> str:
        """Generate executive summary section."""
        critical_alerts = sum(1 for a in alerts if a.severity == AlertSeverity.CRITICAL)
        warning_alerts = sum(1 for a in alerts if a.severity == AlertSeverity.WARNING)

        # Calculate overall health
        total_packets = sum(m.total_packets for m in metrics.values())
        avg_loss = sum(m.packet_loss_rate for m in metrics.values()) / max(len(metrics), 1)

        status_class = "good" if critical_alerts == 0 and avg_loss < 1 else ("warning" if critical_alerts == 0 else "critical")
        status_text = "HEALTHY" if status_class == "good" else ("DEGRADED" if status_class == "warning" else "CRITICAL")

        winner_text = ""
        if comparison and comparison.overall_winner != "tie":
            winner_text = f'<p>Recommended interface: <span class="winner">{comparison.overall_winner}</span></p>'

        return f"""
        <h2>Executive Summary</h2>
        <div class="card">
            <div class="grid">
                <div>
                    <p class="metric-label">Overall Status</p>
                    <p class="metric-value {status_class}">{status_text}</p>
                </div>
                <div>
                    <p class="metric-label">Interfaces Analyzed</p>
                    <p class="metric-value">{len(metrics)}</p>
                </div>
                <div>
                    <p class="metric-label">Total Packets</p>
                    <p class="metric-value">{total_packets:,}</p>
                </div>
                <div>
                    <p class="metric-label">Active Alerts</p>
                    <p class="metric-value {'critical' if critical_alerts > 0 else 'good'}">{critical_alerts + warning_alerts}</p>
                </div>
            </div>
            {winner_text}
        </div>"""

    def _generate_comparison_section(self, result: ComparisonResult) -> str:
        """Generate interface comparison section."""
        def get_class(winner: str, iface: str) -> str:
            if winner == iface:
                return "good"
            elif winner == "tie":
                return ""
            return "critical"

        return f"""
        <h2>Interface Comparison</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Metric</th>
                    <th>{result.interface_a}</th>
                    <th>{result.interface_b}</th>
                    <th>Winner</th>
                </tr>
                <tr>
                    <td>Latency</td>
                    <td class="{get_class(result.winners.get('latency'), result.interface_a)}">{result.metrics_a.get('latency_ms', 0):.1f} ms</td>
                    <td class="{get_class(result.winners.get('latency'), result.interface_b)}">{result.metrics_b.get('latency_ms', 0):.1f} ms</td>
                    <td>{result.winners.get('latency', 'tie')}</td>
                </tr>
                <tr>
                    <td>Packet Loss</td>
                    <td class="{get_class(result.winners.get('packet_loss'), result.interface_a)}">{result.metrics_a.get('loss_percent', 0):.2f}%</td>
                    <td class="{get_class(result.winners.get('packet_loss'), result.interface_b)}">{result.metrics_b.get('loss_percent', 0):.2f}%</td>
                    <td>{result.winners.get('packet_loss', 'tie')}</td>
                </tr>
                <tr>
                    <td>Jitter</td>
                    <td class="{get_class(result.winners.get('jitter'), result.interface_a)}">{result.metrics_a.get('jitter_ms', 0):.1f} ms</td>
                    <td class="{get_class(result.winners.get('jitter'), result.interface_b)}">{result.metrics_b.get('jitter_ms', 0):.1f} ms</td>
                    <td>{result.winners.get('jitter', 'tie')}</td>
                </tr>
                <tr>
                    <td>Bandwidth</td>
                    <td class="{get_class(result.winners.get('bandwidth'), result.interface_a)}">{result.metrics_a.get('bandwidth_mbps', 0):.1f} Mbps</td>
                    <td class="{get_class(result.winners.get('bandwidth'), result.interface_b)}">{result.metrics_b.get('bandwidth_mbps', 0):.1f} Mbps</td>
                    <td>{result.winners.get('bandwidth', 'tie')}</td>
                </tr>
                <tr style="font-weight: bold;">
                    <td>Overall Score</td>
                    <td class="{'good' if result.score_a > result.score_b else ''}">{result.score_a:.0f}/100</td>
                    <td class="{'good' if result.score_b > result.score_a else ''}">{result.score_b:.0f}/100</td>
                    <td class="winner">{result.overall_winner}</td>
                </tr>
            </table>
            <p>Confidence: {result.confidence * 100:.0f}%</p>
            <div class="recommendation">
                <strong>Recommendation:</strong> {result.recommendation}
            </div>
        </div>"""

    def _generate_interface_sections(self, metrics: Dict[str, InterfaceMetrics]) -> str:
        """Generate per-interface detail sections."""
        sections = ["<h2>Interface Details</h2>", '<div class="grid">']

        for iface, m in metrics.items():
            health = self._calculate_health(m)
            health_class = "good" if health >= 90 else ("warning" if health >= 70 else "critical")

            loss_class = "good" if m.packet_loss_rate < 0.5 else ("warning" if m.packet_loss_rate < 2 else "critical")
            latency_class = "good" if m.avg_latency < 50 else ("warning" if m.avg_latency < 150 else "critical")
            jitter_class = "good" if m.avg_jitter < 10 else ("warning" if m.avg_jitter < 30 else "critical")

            sections.append(f"""
            <div class="card">
                <h3>{iface}</h3>
                <p class="metric-label">Health Score</p>
                <p class="metric-value {health_class}">{health:.0f}/100</p>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {health}%; background: {'#4ecdc4' if health >= 90 else ('#ffd93d' if health >= 70 else '#ff6b6b')};"></div>
                </div>
                <table>
                    <tr><td>Total Packets</td><td>{m.total_packets:,}</td></tr>
                    <tr><td>Bandwidth</td><td>{m.bandwidth_mbps:.2f} Mbps</td></tr>
                    <tr><td>Packet Loss</td><td class="{loss_class}">{m.packet_loss_rate:.2f}%</td></tr>
                    <tr><td>Avg Latency</td><td class="{latency_class}">{m.avg_latency:.1f} ms</td></tr>
                    <tr><td>P95 Latency</td><td>{m.get_latency_percentile(95) or 0:.1f} ms</td></tr>
                    <tr><td>Jitter</td><td class="{jitter_class}">{m.avg_jitter:.1f} ms</td></tr>
                    <tr><td>Retransmissions</td><td>{m.retransmissions:,}</td></tr>
                    <tr><td>RX Dropped</td><td>{m.rx_dropped:,}</td></tr>
                </table>
            </div>""")

        sections.append("</div>")
        return "\n".join(sections)

    def _generate_alerts_section(self, alerts: List[Alert]) -> str:
        """Generate alerts section."""
        if not alerts:
            return """
            <h2>Alerts</h2>
            <div class="card">
                <p class="good">No active alerts</p>
            </div>"""

        alert_items = []
        for alert in sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:20]:
            alert_class = "alert-critical" if alert.severity == AlertSeverity.CRITICAL else "alert-warning"
            severity = alert.severity.value.upper()
            alert_items.append(f"""
                <div class="alert-item {alert_class}">
                    <strong>[{severity}]</strong> {alert.message}<br>
                    <small>{alert.interface} - {alert.timestamp.strftime('%H:%M:%S')}</small>
                </div>""")

        return f"""
        <h2>Alerts ({len(alerts)} active)</h2>
        <div class="card">
            {''.join(alert_items)}
        </div>"""

    def _generate_flows_section(self, flows: List[Flow]) -> str:
        """Generate top flows section."""
        if not flows:
            return """
            <h2>Top Flows</h2>
            <div class="card">
                <p>No flow data available</p>
            </div>"""

        rows = []
        for flow in flows[:15]:
            loss = flow.packet_loss_rate
            loss_class = "good" if loss < 0.5 else ("warning" if loss < 2 else "critical")

            src = f"{flow.key.src_ip}:{flow.key.src_port or ''}"
            dst = f"{flow.key.dst_ip}:{flow.key.dst_port or ''}"

            bytes_str = self._format_bytes(flow.total_bytes)

            # Handle protocol as either enum or string
            proto = flow.key.protocol
            if hasattr(proto, 'value'):
                proto = proto.value

            rows.append(f"""
                <tr>
                    <td>{src}</td>
                    <td>{dst}</td>
                    <td>{proto}</td>
                    <td>{bytes_str}</td>
                    <td class="{loss_class}">{loss:.2f}%</td>
                </tr>""")

        return f"""
        <h2>Top Flows</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Bytes</th>
                    <th>Loss %</th>
                </tr>
                {''.join(rows)}
            </table>
        </div>"""

    def _calculate_health(self, m: InterfaceMetrics) -> float:
        """Calculate health score."""
        score = 100.0
        score -= min(40, m.packet_loss_rate * 20)
        score -= min(30, (m.avg_latency / 200) * 30)
        score -= min(20, (m.avg_jitter / 50) * 20)
        retrans_rate = m.retransmissions / max(m.total_packets, 1) * 100
        score -= min(10, retrans_rate * 5)
        return max(0, score)

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable."""
        if bytes_val >= 1_000_000_000:
            return f"{bytes_val / 1_000_000_000:.1f} GB"
        elif bytes_val >= 1_000_000:
            return f"{bytes_val / 1_000_000:.1f} MB"
        elif bytes_val >= 1_000:
            return f"{bytes_val / 1_000:.1f} KB"
        return f"{bytes_val} B"
