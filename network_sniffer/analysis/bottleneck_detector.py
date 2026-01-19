"""Network bottleneck detection."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

from ..models.metrics import InterfaceMetrics


class BottleneckType(Enum):
    """Types of network bottlenecks."""
    BANDWIDTH = "bandwidth"
    LATENCY = "latency"
    PACKET_LOSS = "packet_loss"
    JITTER = "jitter"
    BUFFER = "buffer"
    CONGESTION = "congestion"


@dataclass
class Bottleneck:
    """Identified network bottleneck."""
    type: BottleneckType
    location: str
    severity: float  # 0.0 - 1.0
    description: str
    evidence: List[str]
    recommendations: List[str]

    @property
    def severity_label(self) -> str:
        if self.severity >= 0.8:
            return "critical"
        elif self.severity >= 0.6:
            return "high"
        elif self.severity >= 0.4:
            return "medium"
        else:
            return "low"


@dataclass
class BottleneckThresholds:
    """Configurable thresholds for bottleneck detection."""
    bandwidth_utilization_high: float = 0.80  # 80%
    bandwidth_utilization_critical: float = 0.95  # 95%
    latency_high_ms: float = 100.0
    latency_critical_ms: float = 500.0
    packet_loss_high: float = 0.01  # 1%
    packet_loss_critical: float = 0.05  # 5%
    jitter_high_ms: float = 30.0
    jitter_critical_ms: float = 100.0
    retransmit_high: float = 0.02  # 2%


class BottleneckDetector:
    """
    Identifies network bottlenecks by correlating multiple metrics.
    """

    def __init__(self, thresholds: Optional[BottleneckThresholds] = None):
        self.thresholds = thresholds or BottleneckThresholds()

    def analyze(self, interface: str, metrics: InterfaceMetrics) -> List[Bottleneck]:
        """
        Analyze all metrics for an interface and identify bottlenecks.
        """
        bottlenecks = []

        # 1. Bandwidth bottleneck
        bandwidth_bottleneck = self._check_bandwidth(interface, metrics)
        if bandwidth_bottleneck:
            bottlenecks.append(bandwidth_bottleneck)

        # 2. Latency bottleneck
        latency_bottleneck = self._check_latency(interface, metrics)
        if latency_bottleneck:
            bottlenecks.append(latency_bottleneck)

        # 3. Packet loss bottleneck
        loss_bottleneck = self._check_packet_loss(interface, metrics)
        if loss_bottleneck:
            bottlenecks.append(loss_bottleneck)

        # 4. Jitter bottleneck
        jitter_bottleneck = self._check_jitter(interface, metrics)
        if jitter_bottleneck:
            bottlenecks.append(jitter_bottleneck)

        # 5. Interface buffer issues
        buffer_bottleneck = self._check_buffer(interface, metrics)
        if buffer_bottleneck:
            bottlenecks.append(buffer_bottleneck)

        return bottlenecks

    def _check_bandwidth(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Optional[Bottleneck]:
        """Check for bandwidth saturation."""
        if not metrics.link_speed_mbps or metrics.utilization_percent <= 0:
            return None

        if metrics.utilization_percent >= self.thresholds.bandwidth_utilization_critical * 100:
            severity = 0.95
        elif metrics.utilization_percent >= self.thresholds.bandwidth_utilization_high * 100:
            severity = 0.7
        else:
            return None

        return Bottleneck(
            type=BottleneckType.BANDWIDTH,
            location=f"Interface {interface}",
            severity=severity,
            description="Link bandwidth saturation",
            evidence=[
                f"Utilization: {metrics.utilization_percent:.1f}%",
                f"Link speed: {metrics.link_speed_mbps} Mbps",
                f"Current throughput: {metrics.bandwidth_mbps:.1f} Mbps",
            ],
            recommendations=[
                "Upgrade link capacity",
                "Implement traffic shaping/QoS",
                "Identify and limit bandwidth-heavy applications",
                "Consider load balancing across interfaces",
            ],
        )

    def _check_latency(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Optional[Bottleneck]:
        """Check for high latency."""
        if metrics.avg_latency <= 0:
            return None

        if metrics.avg_latency >= self.thresholds.latency_critical_ms:
            severity = 0.9
        elif metrics.avg_latency >= self.thresholds.latency_high_ms:
            severity = 0.6
        else:
            return None

        return Bottleneck(
            type=BottleneckType.LATENCY,
            location=f"Network path from {interface}",
            severity=severity,
            description="High network latency",
            evidence=[
                f"Average RTT: {metrics.avg_latency:.1f} ms",
                f"Max RTT: {metrics.max_latency:.1f} ms",
                f"Min RTT: {metrics.min_latency:.1f} ms" if metrics.min_latency != float('inf') else "Min RTT: N/A",
            ],
            recommendations=[
                "Check routing path with traceroute",
                "Investigate intermediate hops for congestion",
                "Consider CDN for content delivery",
                "Check for packet queuing/bufferbloat",
                "Verify ISP SLA compliance",
            ],
        )

    def _check_packet_loss(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Optional[Bottleneck]:
        """Check for packet loss."""
        loss_rate = metrics.packet_loss_rate / 100  # Convert from percentage

        if loss_rate >= self.thresholds.packet_loss_critical:
            severity = 0.95
        elif loss_rate >= self.thresholds.packet_loss_high:
            severity = 0.7
        else:
            return None

        return Bottleneck(
            type=BottleneckType.PACKET_LOSS,
            location=f"Network path from {interface}",
            severity=severity,
            description="Significant packet loss detected",
            evidence=[
                f"Packet loss rate: {metrics.packet_loss_rate:.2f}%",
                f"TCP retransmissions: {metrics.retransmissions}",
                f"Duplicate ACKs: {metrics.duplicate_acks}",
                f"Out-of-order packets: {metrics.out_of_order}",
            ],
            recommendations=[
                "Check physical layer (cables, connectors, ports)",
                "Verify switch/router buffer configuration",
                "Check for network congestion",
                "Inspect firewall/IDS for dropped packets",
                "Review error logs on network devices",
            ],
        )

    def _check_jitter(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Optional[Bottleneck]:
        """Check for high jitter."""
        if metrics.avg_jitter <= 0:
            return None

        if metrics.avg_jitter >= self.thresholds.jitter_critical_ms:
            severity = 0.8
        elif metrics.avg_jitter >= self.thresholds.jitter_high_ms:
            severity = 0.5
        else:
            return None

        return Bottleneck(
            type=BottleneckType.JITTER,
            location=f"Network path from {interface}",
            severity=severity,
            description="High jitter affecting real-time applications",
            evidence=[
                f"Average jitter: {metrics.avg_jitter:.1f} ms",
                f"Current jitter: {metrics.current_jitter:.1f} ms",
                f"VoIP threshold (30ms): {'EXCEEDED' if metrics.avg_jitter > 30 else 'OK'}",
            ],
            recommendations=[
                "Enable QoS for real-time traffic (VoIP, video)",
                "Reduce buffer sizes to address bufferbloat",
                "Prioritize time-sensitive traffic",
                "Check for competing bursty traffic patterns",
            ],
        )

    def _check_buffer(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Optional[Bottleneck]:
        """Check for interface buffer issues."""
        total_drops = metrics.rx_dropped + metrics.tx_dropped

        if total_drops <= 0:
            return None

        # Severity based on drops relative to total packets
        if metrics.total_packets > 0:
            drop_rate = total_drops / metrics.total_packets
            if drop_rate >= 0.01:  # >1% drops
                severity = 0.85
            elif drop_rate >= 0.001:  # >0.1% drops
                severity = 0.6
            else:
                severity = 0.4
        else:
            severity = 0.5

        return Bottleneck(
            type=BottleneckType.BUFFER,
            location=f"Interface {interface}",
            severity=severity,
            description="Interface buffer drops detected",
            evidence=[
                f"RX dropped: {metrics.rx_dropped}",
                f"TX dropped: {metrics.tx_dropped}",
                f"RX errors: {metrics.rx_errors}",
                f"TX errors: {metrics.tx_errors}",
            ],
            recommendations=[
                "Increase ring buffer size (ethtool -G on Linux)",
                "Enable interrupt coalescing",
                "Check for driver or firmware updates",
                "Consider upgrading network interface",
            ],
        )

    def get_overall_health(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Dict:
        """Get overall network health assessment."""
        bottlenecks = self.analyze(interface, metrics)

        if not bottlenecks:
            health_score = 100
            status = "healthy"
        else:
            # Calculate health score based on bottleneck severities
            max_severity = max(b.severity for b in bottlenecks)
            health_score = max(0, int((1 - max_severity) * 100))

            if max_severity >= 0.8:
                status = "critical"
            elif max_severity >= 0.6:
                status = "degraded"
            elif max_severity >= 0.4:
                status = "warning"
            else:
                status = "minor_issues"

        return {
            "interface": interface,
            "health_score": health_score,
            "status": status,
            "bottleneck_count": len(bottlenecks),
            "bottlenecks": [
                {
                    "type": b.type.value,
                    "severity": b.severity_label,
                    "description": b.description,
                }
                for b in bottlenecks
            ],
            "top_issue": bottlenecks[0].description if bottlenecks else None,
            "top_recommendation": bottlenecks[0].recommendations[0] if bottlenecks else None,
        }
