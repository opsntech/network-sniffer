"""Metrics data structures."""

from dataclasses import dataclass, field
from typing import Dict, Optional, Deque, List
from collections import deque
from datetime import datetime
import statistics


@dataclass
class InterfaceMetrics:
    """Real-time metrics for a network interface."""
    interface_name: str

    # Counters (absolute values)
    total_packets: int = 0
    total_bytes: int = 0
    total_errors: int = 0

    # Rate calculations (per second, rolling window)
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # Protocol breakdown
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    protocol_bytes: Dict[str, int] = field(default_factory=dict)

    # Latency metrics (milliseconds)
    current_latency: float = 0.0
    avg_latency: float = 0.0
    min_latency: float = float('inf')
    max_latency: float = 0.0
    latency_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))

    # Jitter metrics (milliseconds)
    current_jitter: float = 0.0
    avg_jitter: float = 0.0
    jitter_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))

    # Packet loss indicators
    packets_lost: int = 0
    retransmissions: int = 0
    duplicate_acks: int = 0
    out_of_order: int = 0

    # Interface-level drops (from OS)
    rx_dropped: int = 0
    tx_dropped: int = 0
    rx_errors: int = 0
    tx_errors: int = 0

    # Bandwidth utilization
    link_speed_mbps: Optional[float] = None
    utilization_percent: float = 0.0

    # Timestamps for rate calculation
    _last_update: float = 0.0
    _last_packets: int = 0
    _last_bytes: int = 0

    def add_latency_sample(self, latency_ms: float) -> None:
        """Add a latency sample and update statistics."""
        self.latency_samples.append(latency_ms)
        self.current_latency = latency_ms

        if latency_ms < self.min_latency:
            self.min_latency = latency_ms
        if latency_ms > self.max_latency:
            self.max_latency = latency_ms

        # Update average
        samples = list(self.latency_samples)
        self.avg_latency = sum(samples) / len(samples)

    def add_jitter_sample(self, jitter_ms: float) -> None:
        """Add a jitter sample and update statistics."""
        self.jitter_samples.append(jitter_ms)
        self.current_jitter = jitter_ms

        samples = list(self.jitter_samples)
        self.avg_jitter = sum(samples) / len(samples)

    def calculate_rates(self, current_time: float) -> None:
        """Calculate packets/bytes per second."""
        if self._last_update > 0:
            time_delta = current_time - self._last_update
            if time_delta > 0:
                self.packets_per_second = (self.total_packets - self._last_packets) / time_delta
                self.bytes_per_second = (self.total_bytes - self._last_bytes) / time_delta

                # Calculate utilization if link speed known
                if self.link_speed_mbps:
                    bits_per_second = self.bytes_per_second * 8
                    link_bits_per_second = self.link_speed_mbps * 1_000_000
                    self.utilization_percent = (bits_per_second / link_bits_per_second) * 100

        self._last_update = current_time
        self._last_packets = self.total_packets
        self._last_bytes = self.total_bytes

    @property
    def packet_loss_rate(self) -> float:
        """Calculate packet loss rate as percentage."""
        if self.total_packets == 0:
            return 0.0
        return (self.retransmissions / self.total_packets) * 100

    @property
    def bandwidth_mbps(self) -> float:
        """Current bandwidth in Mbps."""
        return (self.bytes_per_second * 8) / 1_000_000

    def get_latency_percentile(self, p: float) -> Optional[float]:
        """Get latency percentile (e.g., p=95 for 95th percentile)."""
        if not self.latency_samples:
            return None
        samples = sorted(self.latency_samples)
        idx = int(len(samples) * p / 100)
        return samples[min(idx, len(samples) - 1)]

    def get_statistics(self) -> Dict[str, float]:
        """Get comprehensive statistics."""
        stats = {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "packets_per_second": self.packets_per_second,
            "bandwidth_mbps": self.bandwidth_mbps,
            "avg_latency_ms": self.avg_latency,
            "min_latency_ms": self.min_latency if self.min_latency != float('inf') else 0,
            "max_latency_ms": self.max_latency,
            "avg_jitter_ms": self.avg_jitter,
            "packet_loss_percent": self.packet_loss_rate,
            "retransmissions": self.retransmissions,
            "duplicate_acks": self.duplicate_acks,
        }

        # Add percentiles if we have samples
        if self.latency_samples:
            stats["latency_p95_ms"] = self.get_latency_percentile(95)
            stats["latency_p99_ms"] = self.get_latency_percentile(99)

        return stats


@dataclass
class TimeSeriesDataPoint:
    """Single data point for time-series storage."""
    timestamp: datetime
    interface: str
    metric_name: str
    value: float
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ComparisonMetrics:
    """Metrics for comparing two interfaces."""
    interface_a: str
    interface_b: str
    timestamp: datetime = field(default_factory=datetime.now)

    # Raw metrics
    metrics_a: Optional[InterfaceMetrics] = None
    metrics_b: Optional[InterfaceMetrics] = None

    # Computed deltas (positive means A is worse)
    latency_delta_ms: float = 0.0
    jitter_delta_ms: float = 0.0
    loss_delta_percent: float = 0.0
    bandwidth_delta_mbps: float = 0.0

    # Winner determination
    latency_winner: str = ""
    jitter_winner: str = ""
    loss_winner: str = ""
    bandwidth_winner: str = ""
    overall_winner: str = ""

    # Scores (0-100, higher is better)
    score_a: float = 0.0
    score_b: float = 0.0

    def calculate(self) -> None:
        """Calculate comparison metrics from interface metrics."""
        if not self.metrics_a or not self.metrics_b:
            return

        ma = self.metrics_a
        mb = self.metrics_b

        # Calculate deltas
        self.latency_delta_ms = ma.avg_latency - mb.avg_latency
        self.jitter_delta_ms = ma.avg_jitter - mb.avg_jitter
        self.loss_delta_percent = ma.packet_loss_rate - mb.packet_loss_rate
        self.bandwidth_delta_mbps = mb.bandwidth_mbps - ma.bandwidth_mbps  # Higher is better

        # Determine winners (lower is better for latency, jitter, loss; higher for bandwidth)
        self.latency_winner = self.interface_a if ma.avg_latency < mb.avg_latency else self.interface_b
        self.jitter_winner = self.interface_a if ma.avg_jitter < mb.avg_jitter else self.interface_b
        self.loss_winner = self.interface_a if ma.packet_loss_rate < mb.packet_loss_rate else self.interface_b
        self.bandwidth_winner = self.interface_a if ma.bandwidth_mbps > mb.bandwidth_mbps else self.interface_b

        # Calculate scores
        self.score_a = self._calculate_score(ma)
        self.score_b = self._calculate_score(mb)

        self.overall_winner = self.interface_a if self.score_a > self.score_b else self.interface_b

    def _calculate_score(self, metrics: InterfaceMetrics) -> float:
        """
        Calculate overall score (0-100).
        Weights: Latency 30%, Jitter 20%, Loss 40%, Bandwidth 10%
        """
        score = 100.0

        # Latency penalty (>150ms is bad)
        if metrics.avg_latency > 0:
            latency_penalty = min(30, (metrics.avg_latency / 150) * 30)
            score -= latency_penalty

        # Jitter penalty (>30ms is bad)
        if metrics.avg_jitter > 0:
            jitter_penalty = min(20, (metrics.avg_jitter / 30) * 20)
            score -= jitter_penalty

        # Loss penalty (>1% is bad)
        if metrics.packet_loss_rate > 0:
            loss_penalty = min(40, metrics.packet_loss_rate * 40)
            score -= loss_penalty

        return max(0, score)

    def get_summary(self) -> str:
        """Get human-readable comparison summary."""
        lines = [
            f"Interface Comparison: {self.interface_a} vs {self.interface_b}",
            f"",
            f"Latency:   {self.latency_winner} is better by {abs(self.latency_delta_ms):.1f}ms",
            f"Jitter:    {self.jitter_winner} is better by {abs(self.jitter_delta_ms):.1f}ms",
            f"Loss:      {self.loss_winner} is better by {abs(self.loss_delta_percent):.2f}%",
            f"Bandwidth: {self.bandwidth_winner} is better by {abs(self.bandwidth_delta_mbps):.1f}Mbps",
            f"",
            f"Overall Score: {self.interface_a}={self.score_a:.0f}, {self.interface_b}={self.score_b:.0f}",
            f"Recommendation: Use {self.overall_winner} for critical traffic",
        ]
        return "\n".join(lines)
