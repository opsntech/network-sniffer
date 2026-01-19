"""Latency (RTT) analysis."""

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Deque
from collections import deque
import statistics

from ..models.flow import FlowKey


@dataclass
class LatencyStats:
    """Latency statistics for a flow or interface."""
    current_ms: float = 0.0
    avg_ms: float = 0.0
    min_ms: float = float('inf')
    max_ms: float = 0.0
    median_ms: float = 0.0
    std_dev_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    sample_count: int = 0

    # Quality assessment
    quality: str = "unknown"  # excellent, good, acceptable, poor, critical

    def assess_quality(self) -> str:
        """Assess latency quality based on industry standards."""
        if self.avg_ms <= 50:
            self.quality = "excellent"
        elif self.avg_ms <= 100:
            self.quality = "good"
        elif self.avg_ms <= 150:
            self.quality = "acceptable"
        elif self.avg_ms <= 400:
            self.quality = "poor"
        else:
            self.quality = "critical"
        return self.quality


class LatencyAnalyzer:
    """
    Analyzes network latency (RTT) from TCP timestamps and handshakes.
    """

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size

        # Per-flow RTT samples
        self._flow_samples: Dict[FlowKey, Deque[float]] = {}

        # Per-interface aggregated samples
        self._interface_samples: Dict[str, Deque[float]] = {}

        # Pending measurements (for SYN-ACK RTT)
        self._pending_syn: Dict[FlowKey, float] = {}
        self._pending_requests: Dict[FlowKey, float] = {}

    def record_rtt(
        self, flow_key: FlowKey, interface: str, rtt_seconds: float
    ) -> None:
        """Record an RTT measurement."""
        rtt_ms = rtt_seconds * 1000

        # Flow-level tracking
        if flow_key not in self._flow_samples:
            self._flow_samples[flow_key] = deque(maxlen=self.window_size)
        self._flow_samples[flow_key].append(rtt_ms)

        # Interface-level tracking
        if interface not in self._interface_samples:
            self._interface_samples[interface] = deque(maxlen=self.window_size)
        self._interface_samples[interface].append(rtt_ms)

    def record_syn(self, flow_key: FlowKey, timestamp: float) -> None:
        """Record a SYN packet for RTT calculation."""
        self._pending_syn[flow_key] = timestamp

    def record_syn_ack(
        self, flow_key: FlowKey, interface: str, timestamp: float
    ) -> Optional[float]:
        """
        Record a SYN-ACK and calculate RTT from SYN.
        Returns RTT in milliseconds if calculated.
        """
        if flow_key in self._pending_syn:
            syn_time = self._pending_syn.pop(flow_key)
            rtt_seconds = timestamp - syn_time
            self.record_rtt(flow_key, interface, rtt_seconds)
            return rtt_seconds * 1000
        return None

    def get_flow_stats(self, flow_key: FlowKey) -> Optional[LatencyStats]:
        """Get latency statistics for a specific flow."""
        samples = self._flow_samples.get(flow_key)
        if not samples or len(samples) < 2:
            return None
        return self._calculate_stats(list(samples))

    def get_interface_stats(self, interface: str) -> Optional[LatencyStats]:
        """Get aggregated latency statistics for an interface."""
        samples = self._interface_samples.get(interface)
        if not samples or len(samples) < 2:
            return None
        return self._calculate_stats(list(samples))

    def _calculate_stats(self, samples: List[float]) -> LatencyStats:
        """Calculate latency statistics from samples."""
        if len(samples) < 1:
            return LatencyStats()

        sorted_samples = sorted(samples)
        n = len(sorted_samples)

        stats = LatencyStats(
            current_ms=samples[-1],
            avg_ms=statistics.mean(samples),
            min_ms=min(samples),
            max_ms=max(samples),
            median_ms=statistics.median(samples),
            std_dev_ms=statistics.stdev(samples) if n > 1 else 0.0,
            p95_ms=sorted_samples[int(n * 0.95)] if n > 1 else samples[0],
            p99_ms=sorted_samples[int(n * 0.99)] if n > 1 else samples[0],
            sample_count=n,
        )

        stats.assess_quality()
        return stats

    def get_comparison(self, interface_a: str, interface_b: str) -> Dict:
        """Compare latency between two interfaces."""
        stats_a = self.get_interface_stats(interface_a)
        stats_b = self.get_interface_stats(interface_b)

        if not stats_a or not stats_b:
            return {"error": "Insufficient data for comparison"}

        delta = stats_a.avg_ms - stats_b.avg_ms
        winner = interface_a if stats_a.avg_ms < stats_b.avg_ms else interface_b

        return {
            "interface_a": {
                "name": interface_a,
                "avg_ms": stats_a.avg_ms,
                "p95_ms": stats_a.p95_ms,
                "quality": stats_a.quality,
            },
            "interface_b": {
                "name": interface_b,
                "avg_ms": stats_b.avg_ms,
                "p95_ms": stats_b.p95_ms,
                "quality": stats_b.quality,
            },
            "delta_ms": abs(delta),
            "winner": winner,
            "winner_better_by_ms": abs(delta),
            "significant_difference": abs(delta) > 10,  # >10ms is significant
        }

    def get_all_interface_stats(self) -> Dict[str, LatencyStats]:
        """Get latency stats for all interfaces."""
        return {
            iface: self.get_interface_stats(iface)
            for iface in self._interface_samples
            if self.get_interface_stats(iface) is not None
        }

    def cleanup_old_flows(self, max_flows: int = 5000) -> int:
        """Remove oldest flow entries if over limit."""
        if len(self._flow_samples) <= max_flows:
            return 0

        # Remove oldest 10%
        to_remove = len(self._flow_samples) // 10
        keys = list(self._flow_samples.keys())[:to_remove]
        for key in keys:
            del self._flow_samples[key]
        return to_remove
