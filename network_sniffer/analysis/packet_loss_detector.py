"""Packet loss detection and localization."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections import defaultdict
import platform

from ..models.packet import PacketInfo, Protocol
from ..models.flow import FlowKey
from ..models.metrics import InterfaceMetrics
from ..capture.platform_adapter import get_platform_adapter


@dataclass
class LossLocation:
    """Identifies where packet loss is occurring."""
    location: str  # "interface", "network_congestion", "network_path", "socket_buffer"
    interface: str
    evidence: List[str]
    severity: str  # "low", "medium", "high", "critical"
    suggested_action: str


@dataclass
class RetransmitStats:
    """TCP retransmission statistics."""
    total_retransmits: int = 0
    fast_retransmits: int = 0  # After 3 dup ACKs (< 200ms)
    timeout_retransmits: int = 0  # RTO expiry (> 200ms)
    flows_with_retransmits: Set[FlowKey] = field(default_factory=set)

    @property
    def retransmit_pattern(self) -> str:
        """Determine dominant retransmit pattern."""
        if self.total_retransmits == 0:
            return "none"
        if self.fast_retransmits > self.timeout_retransmits:
            return "congestion"  # Fast retransmits suggest congestion
        return "path_issue"  # Timeout retransmits suggest path problems


class PacketLossDetector:
    """
    Comprehensive packet loss detection and localization.
    Identifies WHERE packet loss is occurring in the network path.
    """

    def __init__(self):
        self.adapter = get_platform_adapter()

        # Per-interface retransmit tracking
        self._retransmit_stats: Dict[str, RetransmitStats] = defaultdict(RetransmitStats)

        # Baseline interface stats (for delta calculation)
        self._baseline_stats: Dict[str, Dict[str, int]] = {}

        # Current interface stats
        self._current_stats: Dict[str, Dict[str, int]] = {}

    def record_retransmit(
        self, interface: str, flow_key: FlowKey, delay_seconds: float
    ) -> None:
        """Record a TCP retransmission."""
        stats = self._retransmit_stats[interface]
        stats.total_retransmits += 1
        stats.flows_with_retransmits.add(flow_key)

        # Classify retransmit type based on delay
        if delay_seconds < 0.2:  # < 200ms suggests fast retransmit
            stats.fast_retransmits += 1
        else:
            stats.timeout_retransmits += 1

    def get_retransmit_stats(self, interface: str) -> RetransmitStats:
        """Get retransmission statistics for an interface."""
        return self._retransmit_stats.get(interface, RetransmitStats())

    def update_interface_stats(self, interface: str) -> Dict[str, int]:
        """
        Update interface-level statistics from OS.
        Returns delta from baseline.
        """
        current = self.adapter.get_interface_stats(interface)
        self._current_stats[interface] = current

        if interface not in self._baseline_stats:
            self._baseline_stats[interface] = current.copy()
            return {k: 0 for k in current}

        # Calculate deltas
        baseline = self._baseline_stats[interface]
        delta = {}
        for key, value in current.items():
            delta[key] = value - baseline.get(key, 0)

        return delta

    def localize_loss(self, interface: str, metrics: InterfaceMetrics) -> List[LossLocation]:
        """
        Analyze multiple data sources to determine WHERE packet loss
        is occurring in the network path.

        Returns list of identified loss locations with evidence.
        """
        locations = []

        # 1. Check interface-level drops (driver/hardware issue)
        interface_loss = self._check_interface_drops(interface)
        if interface_loss:
            locations.append(interface_loss)

        # 2. Check TCP retransmissions (network path issue)
        network_loss = self._check_network_loss(interface, metrics)
        if network_loss:
            locations.append(network_loss)

        # 3. Check for socket buffer issues
        buffer_loss = self._check_buffer_drops()
        if buffer_loss:
            locations.append(buffer_loss)

        return locations

    def _check_interface_drops(self, interface: str) -> Optional[LossLocation]:
        """Check for interface-level packet drops."""
        delta = self.update_interface_stats(interface)

        # Key metrics indicating interface-level drops
        rx_dropped = delta.get("rx_dropped", 0)
        rx_fifo_errors = delta.get("rx_fifo_errors", 0)
        rx_missed = delta.get("rx_missed_errors", 0)
        rx_errors = delta.get("rx_errors", 0)

        total_interface_drops = rx_dropped + rx_fifo_errors + rx_missed

        if total_interface_drops > 0 or rx_errors > 0:
            evidence = []
            if rx_dropped > 0:
                evidence.append(f"rx_dropped: {rx_dropped}")
            if rx_fifo_errors > 0:
                evidence.append(f"rx_fifo_errors: {rx_fifo_errors} (ring buffer overflow)")
            if rx_missed > 0:
                evidence.append(f"rx_missed_errors: {rx_missed}")
            if rx_errors > 0:
                evidence.append(f"rx_errors: {rx_errors}")

            # Determine severity
            if total_interface_drops > 100:
                severity = "critical"
            elif total_interface_drops > 10:
                severity = "high"
            else:
                severity = "medium"

            return LossLocation(
                location="interface",
                interface=interface,
                evidence=evidence,
                severity=severity,
                suggested_action=(
                    "Interface receive buffer overflow detected. Consider:\n"
                    "1) Increase ring buffer size (Linux: ethtool -G)\n"
                    "2) Enable interrupt coalescing\n"
                    "3) Check for driver issues or firmware updates\n"
                    "4) Reduce traffic load on this interface"
                ),
            )

        return None

    def _check_network_loss(
        self, interface: str, metrics: InterfaceMetrics
    ) -> Optional[LossLocation]:
        """Check for network-level packet loss via TCP retransmissions."""
        stats = self._retransmit_stats.get(interface, RetransmitStats())

        if stats.total_retransmits < 5:
            return None

        pattern = stats.retransmit_pattern
        evidence = [
            f"Total retransmits: {stats.total_retransmits}",
            f"Fast retransmits: {stats.fast_retransmits}",
            f"Timeout retransmits: {stats.timeout_retransmits}",
            f"Affected flows: {len(stats.flows_with_retransmits)}",
        ]

        if pattern == "congestion":
            evidence.append("Pattern: Fast retransmits dominate (network congestion likely)")
            location = "network_congestion"
            action = (
                "Network congestion detected. Consider:\n"
                "1) Check bandwidth utilization on the network path\n"
                "2) Review switch/router queue depths and buffer sizes\n"
                "3) Implement QoS/traffic shaping policies\n"
                "4) Identify bandwidth-heavy applications"
            )
        else:
            evidence.append("Pattern: Timeout retransmits dominate (path issue likely)")
            location = "network_path"
            action = (
                "Network path issue detected. Consider:\n"
                "1) Run traceroute to check routing stability\n"
                "2) Check for physical link errors (cables, connectors)\n"
                "3) Review firewall/IDS logs for dropped packets\n"
                "4) Contact network administrator or ISP"
            )

        # Determine severity based on loss rate
        if metrics.total_packets > 0:
            loss_rate = stats.total_retransmits / metrics.total_packets
            if loss_rate > 0.05:
                severity = "critical"
            elif loss_rate > 0.02:
                severity = "high"
            elif loss_rate > 0.01:
                severity = "medium"
            else:
                severity = "low"
        else:
            severity = "medium"

        return LossLocation(
            location=location,
            interface=interface,
            evidence=evidence,
            severity=severity,
            suggested_action=action,
        )

    def _check_buffer_drops(self) -> Optional[LossLocation]:
        """Check for socket buffer drops (Linux only)."""
        if platform.system() != "Linux":
            return None

        try:
            # Read UDP receive buffer errors from /proc/net/snmp
            with open("/proc/net/snmp") as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                if line.startswith("Udp:") and i + 1 < len(lines):
                    headers = line.split()
                    values = lines[i + 1].split()

                    if "RcvbufErrors" in headers:
                        idx = headers.index("RcvbufErrors")
                        if idx < len(values):
                            errors = int(values[idx])
                            if errors > 0:
                                return LossLocation(
                                    location="socket_buffer",
                                    interface="system",
                                    evidence=[f"UDP RcvbufErrors: {errors}"],
                                    severity="medium",
                                    suggested_action=(
                                        "Socket buffer overflow detected. Consider:\n"
                                        "1) Increase socket receive buffer: "
                                        "sysctl -w net.core.rmem_max=26214400\n"
                                        "2) Application may not be reading fast enough\n"
                                        "3) Increase application's socket buffer size"
                                    ),
                                )
                    break

        except (IOError, ValueError, IndexError):
            pass

        return None

    def get_loss_summary(self, interface: str, metrics: InterfaceMetrics) -> Dict:
        """Get comprehensive loss summary for an interface."""
        locations = self.localize_loss(interface, metrics)
        stats = self._retransmit_stats.get(interface, RetransmitStats())
        interface_stats = self._current_stats.get(interface, {})

        return {
            "interface": interface,
            "loss_locations": [
                {
                    "location": loc.location,
                    "severity": loc.severity,
                    "evidence": loc.evidence,
                    "action": loc.suggested_action,
                }
                for loc in locations
            ],
            "retransmit_stats": {
                "total": stats.total_retransmits,
                "fast": stats.fast_retransmits,
                "timeout": stats.timeout_retransmits,
                "pattern": stats.retransmit_pattern,
                "affected_flows": len(stats.flows_with_retransmits),
            },
            "interface_stats": {
                "rx_dropped": interface_stats.get("rx_dropped", 0),
                "tx_dropped": interface_stats.get("tx_dropped", 0),
                "rx_errors": interface_stats.get("rx_errors", 0),
                "tx_errors": interface_stats.get("tx_errors", 0),
            },
            "has_issues": len(locations) > 0,
            "worst_severity": max(
                (loc.severity for loc in locations),
                key=lambda s: ["low", "medium", "high", "critical"].index(s),
                default="none",
            ) if locations else "none",
        }
