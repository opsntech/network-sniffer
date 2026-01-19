"""CSV export functionality."""

import csv
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

from ..models.metrics import InterfaceMetrics
from ..models.flow import Flow
from ..storage.metrics_store import MetricsStore


class CSVExporter:
    """Export metrics and data to CSV format for spreadsheet analysis."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_metrics_snapshot(
        self,
        metrics: Dict[str, InterfaceMetrics],
        filename: Optional[str] = None
    ) -> str:
        """Export current metrics snapshot to CSV."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"metrics_snapshot_{timestamp}.csv"

        filepath = self.output_dir / filename

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                "interface",
                "total_packets",
                "total_bytes",
                "packets_per_second",
                "bandwidth_mbps",
                "packet_loss_percent",
                "avg_latency_ms",
                "p95_latency_ms",
                "p99_latency_ms",
                "avg_jitter_ms",
                "retransmissions",
                "out_of_order",
                "duplicate_acks",
                "rx_dropped",
                "tx_dropped",
            ])

            # Data rows
            for iface, m in metrics.items():
                p95 = m.get_latency_percentile(95) or 0
                p99 = m.get_latency_percentile(99) or 0
                writer.writerow([
                    iface,
                    m.total_packets,
                    m.total_bytes,
                    f"{m.packets_per_second:.2f}",
                    f"{m.bandwidth_mbps:.2f}",
                    f"{m.packet_loss_rate:.4f}",
                    f"{m.avg_latency:.2f}",
                    f"{p95:.2f}",
                    f"{p99:.2f}",
                    f"{m.avg_jitter:.2f}",
                    m.retransmissions,
                    m.out_of_order,
                    m.duplicate_acks,
                    m.rx_dropped,
                    m.tx_dropped,
                ])

        return str(filepath)

    def export_time_series(
        self,
        store: MetricsStore,
        interface: str,
        metric: str,
        points: int = 3600,
        filename: Optional[str] = None
    ) -> str:
        """Export time-series data for a specific metric."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"timeseries_{interface}_{metric}_{timestamp}.csv"

        filepath = self.output_dir / filename

        values = store.get_time_series(interface, metric, points)

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["index", "value"])
            for i, value in enumerate(values):
                writer.writerow([i, f"{value:.4f}"])

        return str(filepath)

    def export_all_time_series(
        self,
        store: MetricsStore,
        interfaces: List[str],
        points: int = 3600,
        filename: Optional[str] = None
    ) -> str:
        """Export all time-series data for all interfaces."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"timeseries_all_{timestamp}.csv"

        filepath = self.output_dir / filename

        metrics = ["packets_per_second", "bandwidth_mbps", "latency_ms", "jitter_ms", "loss_percent"]

        # Gather all data
        all_data = {}
        max_len = 0

        for iface in interfaces:
            for metric in metrics:
                key = f"{iface}_{metric}"
                values = store.get_time_series(iface, metric, points)
                all_data[key] = values
                max_len = max(max_len, len(values))

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            header = ["index"]
            for iface in interfaces:
                for metric in metrics:
                    header.append(f"{iface}_{metric}")
            writer.writerow(header)

            # Data rows
            for i in range(max_len):
                row = [i]
                for iface in interfaces:
                    for metric in metrics:
                        key = f"{iface}_{metric}"
                        values = all_data.get(key, [])
                        if i < len(values):
                            row.append(f"{values[i]:.4f}")
                        else:
                            row.append("")
                writer.writerow(row)

        return str(filepath)

    def export_flows(
        self,
        flows: List[Flow],
        filename: Optional[str] = None
    ) -> str:
        """Export flow data to CSV."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"flows_{timestamp}.csv"

        filepath = self.output_dir / filename

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "total_packets",
                "total_bytes",
                "packet_loss_percent",
                "avg_rtt_ms",
                "jitter_ms",
                "retransmits",
                "first_seen",
                "last_seen",
                "duration_seconds",
            ])

            # Data rows
            for flow in flows:
                duration = flow.last_seen - flow.first_seen
                proto = flow.key.protocol
                if hasattr(proto, 'value'):
                    proto = proto.value
                writer.writerow([
                    flow.key.src_ip,
                    flow.key.src_port or "",
                    flow.key.dst_ip,
                    flow.key.dst_port or "",
                    proto,
                    flow.total_packets,
                    flow.total_bytes,
                    f"{flow.packet_loss_rate:.4f}",
                    f"{flow.avg_rtt_ms or 0:.2f}",
                    f"{flow.jitter_ms or 0:.2f}",
                    flow.retransmits,
                    f"{flow.first_seen:.3f}",
                    f"{flow.last_seen:.3f}",
                    f"{duration:.3f}",
                ])

        return str(filepath)

    def export_comparison_history(
        self,
        comparisons: List[dict],
        filename: Optional[str] = None
    ) -> str:
        """Export comparison history to CSV."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"comparison_history_{timestamp}.csv"

        filepath = self.output_dir / filename

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                "timestamp",
                "interface_a",
                "interface_b",
                "score_a",
                "score_b",
                "winner",
                "latency_a",
                "latency_b",
                "loss_a",
                "loss_b",
                "jitter_a",
                "jitter_b",
            ])

            # Data rows
            for comp in comparisons:
                writer.writerow([
                    comp.get("timestamp", ""),
                    comp.get("interface_a", ""),
                    comp.get("interface_b", ""),
                    comp.get("score_a", ""),
                    comp.get("score_b", ""),
                    comp.get("winner", ""),
                    comp.get("latency_a", ""),
                    comp.get("latency_b", ""),
                    comp.get("loss_a", ""),
                    comp.get("loss_b", ""),
                    comp.get("jitter_a", ""),
                    comp.get("jitter_b", ""),
                ])

        return str(filepath)
