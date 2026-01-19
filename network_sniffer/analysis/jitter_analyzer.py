"""Jitter (packet delay variation) analysis."""

from dataclasses import dataclass
from typing import Dict, Optional, List, Deque
from collections import deque
import statistics

from ..models.flow import FlowKey


@dataclass
class JitterStats:
    """Jitter statistics."""
    current_ms: float = 0.0
    avg_ms: float = 0.0
    max_ms: float = 0.0
    min_ms: float = float('inf')
    std_dev_ms: float = 0.0
    sample_count: int = 0

    # Quality thresholds for real-time applications
    is_acceptable_voip: bool = True  # < 30ms for VoIP
    is_acceptable_video: bool = True  # < 50ms for video
    quality: str = "unknown"

    def assess_quality(self) -> str:
        """Assess jitter quality."""
        self.is_acceptable_voip = self.avg_ms < 30
        self.is_acceptable_video = self.avg_ms < 50

        if self.avg_ms <= 10:
            self.quality = "excellent"
        elif self.avg_ms <= 20:
            self.quality = "good"
        elif self.avg_ms <= 30:
            self.quality = "acceptable"
        elif self.avg_ms <= 50:
            self.quality = "poor"
        else:
            self.quality = "critical"

        return self.quality


class JitterAnalyzer:
    """
    Measures network jitter (variation in packet arrival times).

    Jitter is calculated as the mean deviation between consecutive
    packet inter-arrival times: Jitter = Mean(|IAT[i] - IAT[i-1]|)
    """

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size

        # Per-flow inter-arrival time tracking
        self._last_arrival: Dict[FlowKey, float] = {}
        self._iat_samples: Dict[FlowKey, Deque[float]] = {}

        # Per-interface aggregated jitter
        self._interface_jitter: Dict[str, Deque[float]] = {}

    def record_packet(
        self, flow_key: FlowKey, interface: str, arrival_time: float
    ) -> Optional[float]:
        """
        Record packet arrival and calculate instantaneous jitter.

        Returns the jitter value in milliseconds, or None if not enough data.
        """
        # Calculate inter-arrival time
        if flow_key in self._last_arrival:
            iat_ms = (arrival_time - self._last_arrival[flow_key]) * 1000

            # Initialize storage if needed
            if flow_key not in self._iat_samples:
                self._iat_samples[flow_key] = deque(maxlen=self.window_size)
            if interface not in self._interface_jitter:
                self._interface_jitter[interface] = deque(maxlen=self.window_size)

            # Store IAT
            self._iat_samples[flow_key].append(iat_ms)

            # Calculate instantaneous jitter (deviation from previous IAT)
            samples = self._iat_samples[flow_key]
            if len(samples) >= 2:
                jitter = abs(samples[-1] - samples[-2])
                self._interface_jitter[interface].append(jitter)
                self._last_arrival[flow_key] = arrival_time
                return jitter

        self._last_arrival[flow_key] = arrival_time
        return None

    def get_flow_jitter(self, flow_key: FlowKey) -> Optional[JitterStats]:
        """Get jitter statistics for a specific flow."""
        if flow_key not in self._iat_samples:
            return None
        return self._calculate_jitter_stats(list(self._iat_samples[flow_key]))

    def get_interface_jitter(self, interface: str) -> Optional[JitterStats]:
        """Get aggregated jitter statistics for an interface."""
        if interface not in self._interface_jitter:
            return None
        samples = list(self._interface_jitter[interface])
        if len(samples) < 2:
            return None
        return self._calculate_jitter_from_samples(samples)

    def _calculate_jitter_stats(self, iat_samples: List[float]) -> Optional[JitterStats]:
        """
        Calculate jitter statistics from inter-arrival time samples.
        Jitter is the variation in IAT.
        """
        if len(iat_samples) < 2:
            return None

        # Calculate jitter values (deviation between consecutive IATs)
        jitter_values = [
            abs(iat_samples[i] - iat_samples[i-1])
            for i in range(1, len(iat_samples))
        ]

        return self._calculate_jitter_from_samples(jitter_values)

    def _calculate_jitter_from_samples(self, jitter_values: List[float]) -> JitterStats:
        """Calculate statistics from jitter samples."""
        if not jitter_values:
            return JitterStats()

        stats = JitterStats(
            current_ms=jitter_values[-1],
            avg_ms=statistics.mean(jitter_values),
            max_ms=max(jitter_values),
            min_ms=min(jitter_values),
            std_dev_ms=statistics.stdev(jitter_values) if len(jitter_values) > 1 else 0.0,
            sample_count=len(jitter_values),
        )

        stats.assess_quality()
        return stats

    def get_comparison(self, interface_a: str, interface_b: str) -> Dict:
        """Compare jitter between two interfaces."""
        stats_a = self.get_interface_jitter(interface_a)
        stats_b = self.get_interface_jitter(interface_b)

        if not stats_a or not stats_b:
            return {"error": "Insufficient data for comparison"}

        delta = stats_a.avg_ms - stats_b.avg_ms
        winner = interface_a if stats_a.avg_ms < stats_b.avg_ms else interface_b

        return {
            "interface_a": {
                "name": interface_a,
                "avg_ms": stats_a.avg_ms,
                "quality": stats_a.quality,
                "voip_ok": stats_a.is_acceptable_voip,
            },
            "interface_b": {
                "name": interface_b,
                "avg_ms": stats_b.avg_ms,
                "quality": stats_b.quality,
                "voip_ok": stats_b.is_acceptable_voip,
            },
            "delta_ms": abs(delta),
            "winner": winner,
            "significant_difference": abs(delta) > 5,  # >5ms jitter diff is significant
        }

    def get_all_interface_stats(self) -> Dict[str, JitterStats]:
        """Get jitter stats for all interfaces."""
        return {
            iface: stats
            for iface in self._interface_jitter
            if (stats := self.get_interface_jitter(iface)) is not None
        }

    def cleanup_old_flows(self, max_flows: int = 5000) -> int:
        """Remove oldest flow entries."""
        if len(self._iat_samples) <= max_flows:
            return 0

        to_remove = len(self._iat_samples) // 10
        keys = list(self._iat_samples.keys())[:to_remove]
        for key in keys:
            del self._iat_samples[key]
            self._last_arrival.pop(key, None)
        return to_remove
