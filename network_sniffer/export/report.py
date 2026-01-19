"""Unified report generator combining all export formats."""

from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from .json_exporter import JSONExporter
from .csv_exporter import CSVExporter
from .html_report import HTMLReportGenerator

from ..models.metrics import InterfaceMetrics
from ..models.flow import Flow
from ..alerts.alert_manager import Alert
from ..analysis.comparator import ComparisonResult
from ..storage.metrics_store import MetricsStore


class ReportGenerator:
    """Unified interface for generating reports in multiple formats."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.json_exporter = JSONExporter(output_dir)
        self.csv_exporter = CSVExporter(output_dir)
        self.html_generator = HTMLReportGenerator(output_dir)

    def generate_full_report(
        self,
        metrics: Dict[str, InterfaceMetrics],
        flows: List[Flow],
        alerts: List[Alert],
        comparison: Optional[ComparisonResult] = None,
        metrics_store: Optional[MetricsStore] = None,
        formats: List[str] = None,
        base_filename: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate reports in specified formats.

        Args:
            metrics: Interface metrics dictionary
            flows: List of tracked flows
            alerts: List of alerts
            comparison: Optional comparison result
            metrics_store: Optional metrics store for time-series data
            formats: List of formats to generate ('json', 'csv', 'html'). Default: all
            base_filename: Base filename (timestamp added automatically)

        Returns:
            Dictionary mapping format to output filepath
        """
        if formats is None:
            formats = ["json", "csv", "html"]

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if base_filename:
            base = base_filename
        else:
            base = f"network_report_{timestamp}"

        results = {}

        if "json" in formats:
            filepath = self.json_exporter.export_full_report(
                metrics=metrics,
                flows=flows,
                alerts=alerts,
                comparison=comparison,
                filename=f"{base}.json"
            )
            results["json"] = filepath

        if "csv" in formats:
            # Export metrics snapshot
            filepath = self.csv_exporter.export_metrics_snapshot(
                metrics=metrics,
                filename=f"{base}_metrics.csv"
            )
            results["csv_metrics"] = filepath

            # Export flows
            filepath = self.csv_exporter.export_flows(
                flows=flows,
                filename=f"{base}_flows.csv"
            )
            results["csv_flows"] = filepath

            # Export time-series if store available
            if metrics_store:
                interfaces = list(metrics.keys())
                filepath = self.csv_exporter.export_all_time_series(
                    store=metrics_store,
                    interfaces=interfaces,
                    filename=f"{base}_timeseries.csv"
                )
                results["csv_timeseries"] = filepath

        if "html" in formats:
            filepath = self.html_generator.generate_report(
                metrics=metrics,
                flows=flows,
                alerts=alerts,
                comparison=comparison,
                title="Network Diagnostic Report",
                filename=f"{base}.html"
            )
            results["html"] = filepath

        return results

    def generate_quick_summary(
        self,
        metrics: Dict[str, InterfaceMetrics],
        comparison: Optional[ComparisonResult] = None
    ) -> str:
        """Generate a quick text summary for console output."""
        lines = [
            "=" * 60,
            "NETWORK DIAGNOSTIC SUMMARY",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        for iface, m in metrics.items():
            health = self._calculate_health(m)
            status = "HEALTHY" if health >= 90 else ("DEGRADED" if health >= 70 else "CRITICAL")

            p95 = m.get_latency_percentile(95) or 0
            lines.extend([
                f"Interface: {iface}",
                f"  Status: {status} (Health: {health:.0f}/100)",
                f"  Packets: {m.total_packets:,}",
                f"  Bandwidth: {m.bandwidth_mbps:.2f} Mbps",
                f"  Packet Loss: {m.packet_loss_rate:.2f}%",
                f"  Latency: {m.avg_latency:.1f}ms (P95: {p95:.1f}ms)",
                f"  Jitter: {m.avg_jitter:.1f}ms",
                f"  Retransmissions: {m.retransmissions:,}",
                "",
            ])

        if comparison:
            lines.extend([
                "-" * 60,
                "COMPARISON RESULT",
                "-" * 60,
                f"  {comparison.interface_a}: Score {comparison.score_a:.0f}",
                f"  {comparison.interface_b}: Score {comparison.score_b:.0f}",
                f"  Winner: {comparison.overall_winner}",
                f"  Confidence: {comparison.confidence * 100:.0f}%",
                "",
                f"  Recommendation: {comparison.recommendation}",
            ])

        lines.append("=" * 60)
        return "\n".join(lines)

    def _calculate_health(self, m: InterfaceMetrics) -> float:
        """Calculate health score."""
        score = 100.0
        score -= min(40, m.packet_loss_rate * 20)
        score -= min(30, (m.avg_latency / 200) * 30)
        score -= min(20, (m.avg_jitter / 50) * 20)
        retrans_rate = m.retransmissions / max(m.total_packets, 1) * 100
        score -= min(10, retrans_rate * 5)
        return max(0, score)
