"""JSON export functionality."""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..models.metrics import InterfaceMetrics
from ..models.flow import Flow
from ..alerts.alert_manager import Alert
from ..analysis.comparator import ComparisonResult


class JSONExporter:
    """Export metrics and analysis results to JSON format."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_metrics(
        self,
        metrics: Dict[str, InterfaceMetrics],
        filename: Optional[str] = None
    ) -> str:
        """Export interface metrics to JSON."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"metrics_{timestamp}.json"

        data = {
            "export_time": datetime.now().isoformat(),
            "interfaces": {}
        }

        for iface, m in metrics.items():
            data["interfaces"][iface] = {
                "total_packets": m.total_packets,
                "total_bytes": m.total_bytes,
                "packets_per_second": m.packets_per_second,
                "bandwidth_mbps": m.bandwidth_mbps,
                "packet_loss_rate": m.packet_loss_rate,
                "avg_latency_ms": m.avg_latency,
                "p95_latency_ms": m.get_latency_percentile(95) or 0,
                "p99_latency_ms": m.get_latency_percentile(99) or 0,
                "avg_jitter_ms": m.avg_jitter,
                "retransmissions": m.retransmissions,
                "out_of_order": m.out_of_order,
                "duplicate_acks": m.duplicate_acks,
                "rx_dropped": m.rx_dropped,
                "tx_dropped": m.tx_dropped,
                "protocol_counts": m.protocol_counts,
            }

        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        return str(filepath)

    def export_flows(
        self,
        flows: List[Flow],
        filename: Optional[str] = None
    ) -> str:
        """Export flow data to JSON."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"flows_{timestamp}.json"

        data = {
            "export_time": datetime.now().isoformat(),
            "total_flows": len(flows),
            "flows": []
        }

        for flow in flows:
            proto = flow.key.protocol
            if hasattr(proto, 'value'):
                proto = proto.value
            data["flows"].append({
                "src_ip": flow.key.src_ip,
                "dst_ip": flow.key.dst_ip,
                "src_port": flow.key.src_port,
                "dst_port": flow.key.dst_port,
                "protocol": proto,
                "total_packets": flow.total_packets,
                "total_bytes": flow.total_bytes,
                "packet_loss_rate": flow.packet_loss_rate,
                "avg_rtt_ms": flow.avg_rtt_ms,
                "jitter_ms": flow.jitter_ms,
                "retransmits": flow.retransmits,
                "first_seen": flow.first_seen,
                "last_seen": flow.last_seen,
            })

        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        return str(filepath)

    def export_alerts(
        self,
        alerts: List[Alert],
        filename: Optional[str] = None
    ) -> str:
        """Export alerts to JSON."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"alerts_{timestamp}.json"

        data = {
            "export_time": datetime.now().isoformat(),
            "total_alerts": len(alerts),
            "alerts": []
        }

        for alert in alerts:
            data["alerts"].append({
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "type": alert.alert_type.value,
                "severity": alert.severity.value,
                "interface": alert.interface,
                "message": alert.message,
                "metric_name": alert.metric_name,
                "metric_value": alert.metric_value,
                "threshold_value": alert.threshold_value,
                "resolved": alert.resolved,
                "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            })

        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        return str(filepath)

    def export_comparison(
        self,
        result: ComparisonResult,
        filename: Optional[str] = None
    ) -> str:
        """Export comparison result to JSON."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"comparison_{timestamp}.json"

        data = {
            "export_time": datetime.now().isoformat(),
            "comparison_time": result.timestamp.isoformat(),
            "interface_a": result.interface_a,
            "interface_b": result.interface_b,
            "metrics_a": result.metrics_a,
            "metrics_b": result.metrics_b,
            "winners": result.winners,
            "overall_winner": result.overall_winner,
            "score_a": result.score_a,
            "score_b": result.score_b,
            "confidence": result.confidence,
            "recommendation": result.recommendation,
        }

        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        return str(filepath)

    def export_full_report(
        self,
        metrics: Dict[str, InterfaceMetrics],
        flows: List[Flow],
        alerts: List[Alert],
        comparison: Optional[ComparisonResult] = None,
        filename: Optional[str] = None
    ) -> str:
        """Export complete diagnostic report to JSON."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"full_report_{timestamp}.json"

        data = {
            "report_time": datetime.now().isoformat(),
            "summary": {
                "interfaces_analyzed": list(metrics.keys()),
                "total_flows": len(flows),
                "total_alerts": len(alerts),
            },
            "interfaces": {},
            "top_flows": [],
            "alerts": [],
        }

        # Add interface metrics
        for iface, m in metrics.items():
            data["interfaces"][iface] = {
                "total_packets": m.total_packets,
                "total_bytes": m.total_bytes,
                "packets_per_second": m.packets_per_second,
                "bandwidth_mbps": m.bandwidth_mbps,
                "packet_loss_rate": m.packet_loss_rate,
                "avg_latency_ms": m.avg_latency,
                "p95_latency_ms": m.get_latency_percentile(95) or 0,
                "avg_jitter_ms": m.avg_jitter,
                "retransmissions": m.retransmissions,
            }

        # Add top flows
        for flow in flows[:20]:
            proto = flow.key.protocol
            if hasattr(proto, 'value'):
                proto = proto.value
            data["top_flows"].append({
                "src": f"{flow.key.src_ip}:{flow.key.src_port or ''}",
                "dst": f"{flow.key.dst_ip}:{flow.key.dst_port or ''}",
                "protocol": proto,
                "bytes": flow.total_bytes,
                "loss_rate": flow.packet_loss_rate,
            })

        # Add alerts
        for alert in alerts:
            data["alerts"].append({
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity.value,
                "interface": alert.interface,
                "message": alert.message,
            })

        # Add comparison if available
        if comparison:
            data["comparison"] = {
                "interface_a": comparison.interface_a,
                "interface_b": comparison.interface_b,
                "winner": comparison.overall_winner,
                "score_a": comparison.score_a,
                "score_b": comparison.score_b,
                "recommendation": comparison.recommendation,
            }

        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        return str(filepath)
