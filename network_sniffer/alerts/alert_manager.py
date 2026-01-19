"""Alert management system."""

from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional
from datetime import datetime, timedelta
from enum import Enum
import uuid
import time

from ..models.metrics import InterfaceMetrics
from .thresholds import AlertThresholds


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of alerts."""
    HIGH_PACKET_LOSS = "high_packet_loss"
    HIGH_LATENCY = "high_latency"
    HIGH_JITTER = "high_jitter"
    BANDWIDTH_SATURATION = "bandwidth_saturation"
    TCP_RETRANSMIT_SPIKE = "tcp_retransmit_spike"
    INTERFACE_DROPS = "interface_drops"
    CONNECTION_DEGRADED = "connection_degraded"


@dataclass
class Alert:
    """Alert notification."""
    id: str
    timestamp: datetime
    alert_type: AlertType
    severity: AlertSeverity
    interface: str
    message: str
    metric_name: str = ""
    metric_value: float = 0.0
    threshold_value: float = 0.0
    resolved: bool = False
    resolved_at: Optional[datetime] = None

    @property
    def age_seconds(self) -> float:
        """Get alert age in seconds."""
        return (datetime.now() - self.timestamp).total_seconds()

    @property
    def duration_str(self) -> str:
        """Get human-readable duration."""
        age = self.age_seconds
        if age < 60:
            return f"{int(age)}s"
        elif age < 3600:
            return f"{int(age/60)}m"
        else:
            return f"{int(age/3600)}h"


@dataclass
class AlertRule:
    """Configurable alert rule."""
    name: str
    alert_type: AlertType
    metric: str  # "packet_loss", "latency", "jitter", etc.
    threshold_warning: float
    threshold_critical: float
    cooldown_seconds: int = 60  # Minimum time between alerts
    hysteresis_count: int = 3  # Consecutive violations before alerting
    enabled: bool = True


class AlertManager:
    """
    Manages alert rules, evaluation, and notification.
    Includes hysteresis and rate limiting to prevent alert fatigue.
    """

    def __init__(self, thresholds: Optional[AlertThresholds] = None):
        self.thresholds = thresholds or AlertThresholds()

        # Alert rules
        self._rules: List[AlertRule] = []

        # Active alerts
        self._active_alerts: Dict[str, Alert] = {}

        # Alert history
        self._alert_history: List[Alert] = []
        self._max_history = 1000

        # Hysteresis tracking (consecutive violations)
        self._violation_counts: Dict[str, int] = {}

        # Cooldown tracking
        self._last_alert_time: Dict[str, float] = {}

        # Notification callbacks
        self._callbacks: List[Callable[[Alert], None]] = []

        # Load default rules
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load default alert rules."""
        self._rules = [
            AlertRule(
                name="High Packet Loss",
                alert_type=AlertType.HIGH_PACKET_LOSS,
                metric="packet_loss",
                threshold_warning=1.0,
                threshold_critical=5.0,
                cooldown_seconds=60,
            ),
            AlertRule(
                name="High Latency",
                alert_type=AlertType.HIGH_LATENCY,
                metric="latency",
                threshold_warning=150.0,
                threshold_critical=400.0,
                cooldown_seconds=60,
            ),
            AlertRule(
                name="High Jitter",
                alert_type=AlertType.HIGH_JITTER,
                metric="jitter",
                threshold_warning=30.0,
                threshold_critical=100.0,
                cooldown_seconds=60,
            ),
            AlertRule(
                name="Bandwidth Saturation",
                alert_type=AlertType.BANDWIDTH_SATURATION,
                metric="utilization",
                threshold_warning=80.0,
                threshold_critical=95.0,
                cooldown_seconds=120,
            ),
            AlertRule(
                name="TCP Retransmissions",
                alert_type=AlertType.TCP_RETRANSMIT_SPIKE,
                metric="retransmit_rate",
                threshold_warning=2.0,
                threshold_critical=5.0,
                cooldown_seconds=60,
            ),
        ]

    def add_callback(self, callback: Callable[[Alert], None]) -> None:
        """Add notification callback."""
        self._callbacks.append(callback)

    def evaluate(self, interface: str, metrics: InterfaceMetrics) -> List[Alert]:
        """
        Evaluate all rules for an interface and return new alerts.
        """
        new_alerts = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            # Get metric value
            value = self._get_metric_value(rule.metric, metrics)
            if value is None:
                continue

            # Determine severity
            if value >= rule.threshold_critical:
                severity = AlertSeverity.CRITICAL
                threshold = rule.threshold_critical
            elif value >= rule.threshold_warning:
                severity = AlertSeverity.WARNING
                threshold = rule.threshold_warning
            else:
                # No violation - reset hysteresis and check for resolution
                self._handle_no_violation(rule, interface)
                continue

            # Handle violation with hysteresis
            alert = self._handle_violation(
                rule, interface, value, threshold, severity
            )
            if alert:
                new_alerts.append(alert)

        return new_alerts

    def _get_metric_value(
        self, metric: str, metrics: InterfaceMetrics
    ) -> Optional[float]:
        """Extract metric value from InterfaceMetrics."""
        mapping = {
            "packet_loss": metrics.packet_loss_rate,
            "latency": metrics.avg_latency,
            "jitter": metrics.avg_jitter,
            "utilization": metrics.utilization_percent,
            "retransmit_rate": (
                metrics.retransmissions / max(metrics.total_packets, 1) * 100
            ),
        }
        return mapping.get(metric)

    def _handle_violation(
        self,
        rule: AlertRule,
        interface: str,
        value: float,
        threshold: float,
        severity: AlertSeverity,
    ) -> Optional[Alert]:
        """Handle a threshold violation."""
        key = f"{interface}:{rule.metric}"

        # Increment violation count (hysteresis)
        self._violation_counts[key] = self._violation_counts.get(key, 0) + 1

        # Check if we've exceeded hysteresis threshold
        if self._violation_counts[key] < rule.hysteresis_count:
            return None

        # Check cooldown
        last_alert = self._last_alert_time.get(key, 0)
        if time.time() - last_alert < rule.cooldown_seconds:
            return None

        # Check if already alerting
        if key in self._active_alerts:
            # Update existing alert if severity increased
            existing = self._active_alerts[key]
            if severity.value != existing.severity.value:
                existing.severity = severity
                existing.metric_value = value
            return None

        # Create new alert
        alert = Alert(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(),
            alert_type=rule.alert_type,
            severity=severity,
            interface=interface,
            message=f"{rule.name} on {interface}: {value:.2f} (threshold: {threshold})",
            metric_name=rule.metric,
            metric_value=value,
            threshold_value=threshold,
        )

        # Store and track
        self._active_alerts[key] = alert
        self._alert_history.append(alert)
        self._last_alert_time[key] = time.time()

        # Trim history
        if len(self._alert_history) > self._max_history:
            self._alert_history = self._alert_history[-self._max_history:]

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception:
                pass

        return alert

    def _handle_no_violation(self, rule: AlertRule, interface: str) -> None:
        """Handle when metric returns to normal."""
        key = f"{interface}:{rule.metric}"

        # Reset hysteresis
        self._violation_counts[key] = 0

        # Resolve active alert
        if key in self._active_alerts:
            alert = self._active_alerts[key]
            alert.resolved = True
            alert.resolved_at = datetime.now()
            del self._active_alerts[key]

    def get_active_alerts(self) -> List[Alert]:
        """Get all active (unresolved) alerts."""
        return list(self._active_alerts.values())

    def get_alerts_by_interface(self, interface: str) -> List[Alert]:
        """Get active alerts for a specific interface."""
        return [
            alert for alert in self._active_alerts.values()
            if alert.interface == interface
        ]

    def get_alert_history(
        self, limit: int = 100, interface: Optional[str] = None
    ) -> List[Alert]:
        """Get recent alert history."""
        history = self._alert_history
        if interface:
            history = [a for a in history if a.interface == interface]
        return history[-limit:]

    def get_alert_summary(self) -> Dict:
        """Get summary of current alert status."""
        active = self.get_active_alerts()

        critical_count = sum(
            1 for a in active if a.severity == AlertSeverity.CRITICAL
        )
        warning_count = sum(
            1 for a in active if a.severity == AlertSeverity.WARNING
        )

        # Group by interface
        by_interface = {}
        for alert in active:
            if alert.interface not in by_interface:
                by_interface[alert.interface] = []
            by_interface[alert.interface].append(alert.alert_type.value)

        return {
            "total_active": len(active),
            "critical": critical_count,
            "warning": warning_count,
            "by_interface": by_interface,
            "worst_severity": "critical" if critical_count > 0 else (
                "warning" if warning_count > 0 else "none"
            ),
        }

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert (remove from active)."""
        for key, alert in list(self._active_alerts.items()):
            if alert.id == alert_id:
                alert.resolved = True
                alert.resolved_at = datetime.now()
                del self._active_alerts[key]
                return True
        return False

    def clear_all(self) -> int:
        """Clear all active alerts. Returns count cleared."""
        count = len(self._active_alerts)
        now = datetime.now()
        for alert in self._active_alerts.values():
            alert.resolved = True
            alert.resolved_at = now
        self._active_alerts.clear()
        return count
