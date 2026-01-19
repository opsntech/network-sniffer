"""Industry-standard alert thresholds for network quality metrics."""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertType(Enum):
    """Types of network alerts."""
    HIGH_PACKET_LOSS = "high_packet_loss"
    HIGH_LATENCY = "high_latency"
    HIGH_JITTER = "high_jitter"
    BANDWIDTH_SATURATION = "bandwidth_saturation"
    TCP_RETRANSMIT_SPIKE = "tcp_retransmit_spike"
    CONNECTION_TIMEOUT = "connection_timeout"
    INTERFACE_DROPS = "interface_drops"
    INTERFACE_ERRORS = "interface_errors"


@dataclass
class ThresholdConfig:
    """Configuration for a specific threshold."""
    warning: float
    critical: float
    unit: str = ""
    description: str = ""


class AlertThresholds:
    """
    Industry-standard thresholds for network quality metrics.
    Based on ITU-T, Cisco, and VoIP industry recommendations.
    """

    # Packet Loss Thresholds (percentage)
    PACKET_LOSS: Dict[str, ThresholdConfig] = {
        "voip": ThresholdConfig(
            warning=0.5, critical=1.0, unit="%",
            description="VoIP requires <1% loss for acceptable quality"
        ),
        "video": ThresholdConfig(
            warning=1.0, critical=2.5, unit="%",
            description="Video conferencing threshold"
        ),
        "general": ThresholdConfig(
            warning=1.0, critical=5.0, unit="%",
            description="General network traffic"
        ),
    }

    # Latency Thresholds (milliseconds, one-way)
    LATENCY: Dict[str, ThresholdConfig] = {
        "voip": ThresholdConfig(
            warning=100, critical=150, unit="ms",
            description="ITU G.114 standard for voice"
        ),
        "video": ThresholdConfig(
            warning=100, critical=150, unit="ms",
            description="Video conferencing threshold"
        ),
        "gaming": ThresholdConfig(
            warning=50, critical=100, unit="ms",
            description="Online gaming threshold"
        ),
        "general": ThresholdConfig(
            warning=100, critical=200, unit="ms",
            description="General application traffic"
        ),
    }

    # Jitter Thresholds (milliseconds)
    JITTER: Dict[str, ThresholdConfig] = {
        "voip": ThresholdConfig(
            warning=20, critical=30, unit="ms",
            description="VoIP jitter threshold"
        ),
        "video": ThresholdConfig(
            warning=30, critical=50, unit="ms",
            description="Video conferencing threshold"
        ),
        "general": ThresholdConfig(
            warning=30, critical=50, unit="ms",
            description="General real-time traffic"
        ),
    }

    # Bandwidth Utilization Thresholds (percentage)
    BANDWIDTH: Dict[str, ThresholdConfig] = {
        "general": ThresholdConfig(
            warning=80, critical=95, unit="%",
            description="Link bandwidth utilization"
        ),
    }

    def __init__(self, profile: str = "general"):
        """
        Initialize with a specific profile.

        Args:
            profile: One of "voip", "video", "gaming", "general"
        """
        self.profile = profile

    def get_packet_loss_thresholds(self) -> ThresholdConfig:
        """Get packet loss thresholds for current profile."""
        return self.PACKET_LOSS.get(self.profile, self.PACKET_LOSS["general"])

    def get_latency_thresholds(self) -> ThresholdConfig:
        """Get latency thresholds for current profile."""
        return self.LATENCY.get(self.profile, self.LATENCY["general"])

    def get_jitter_thresholds(self) -> ThresholdConfig:
        """Get jitter thresholds for current profile."""
        return self.JITTER.get(self.profile, self.JITTER["general"])

    def get_bandwidth_thresholds(self) -> ThresholdConfig:
        """Get bandwidth thresholds."""
        return self.BANDWIDTH["general"]

    def check_packet_loss(self, loss_percent: float) -> Optional[AlertSeverity]:
        """Check packet loss against thresholds."""
        thresholds = self.get_packet_loss_thresholds()
        if loss_percent >= thresholds.critical:
            return AlertSeverity.CRITICAL
        elif loss_percent >= thresholds.warning:
            return AlertSeverity.WARNING
        return None

    def check_latency(self, latency_ms: float) -> Optional[AlertSeverity]:
        """Check latency against thresholds."""
        thresholds = self.get_latency_thresholds()
        if latency_ms >= thresholds.critical:
            return AlertSeverity.CRITICAL
        elif latency_ms >= thresholds.warning:
            return AlertSeverity.WARNING
        return None

    def check_jitter(self, jitter_ms: float) -> Optional[AlertSeverity]:
        """Check jitter against thresholds."""
        thresholds = self.get_jitter_thresholds()
        if jitter_ms >= thresholds.critical:
            return AlertSeverity.CRITICAL
        elif jitter_ms >= thresholds.warning:
            return AlertSeverity.WARNING
        return None

    def check_bandwidth(self, utilization_percent: float) -> Optional[AlertSeverity]:
        """Check bandwidth utilization against thresholds."""
        thresholds = self.get_bandwidth_thresholds()
        if utilization_percent >= thresholds.critical:
            return AlertSeverity.CRITICAL
        elif utilization_percent >= thresholds.warning:
            return AlertSeverity.WARNING
        return None

    def get_quality_rating(
        self, metric_type: str, value: float
    ) -> str:
        """
        Get quality rating for a metric value.

        Returns: "excellent", "good", "acceptable", "poor", or "critical"
        """
        if metric_type == "packet_loss":
            thresholds = self.get_packet_loss_thresholds()
            if value <= 0:
                return "excellent"
            elif value <= thresholds.warning / 2:
                return "good"
            elif value <= thresholds.warning:
                return "acceptable"
            elif value <= thresholds.critical:
                return "poor"
            else:
                return "critical"

        elif metric_type == "latency":
            thresholds = self.get_latency_thresholds()
            if value <= 50:
                return "excellent"
            elif value <= thresholds.warning:
                return "good"
            elif value <= thresholds.warning * 1.5:
                return "acceptable"
            elif value <= thresholds.critical:
                return "poor"
            else:
                return "critical"

        elif metric_type == "jitter":
            thresholds = self.get_jitter_thresholds()
            if value <= 10:
                return "excellent"
            elif value <= thresholds.warning:
                return "good"
            elif value <= thresholds.warning * 1.5:
                return "acceptable"
            elif value <= thresholds.critical:
                return "poor"
            else:
                return "critical"

        return "unknown"
