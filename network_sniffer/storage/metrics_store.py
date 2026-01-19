"""Metrics storage with ring buffers for efficient time-series data."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Generic, TypeVar, Deque
from collections import deque
from threading import Lock
import time

from ..models.packet import PacketInfo
from ..models.flow import FlowKey, Flow
from ..models.metrics import InterfaceMetrics, TimeSeriesDataPoint


T = TypeVar('T')


class RingBuffer(Generic[T]):
    """Thread-safe ring buffer for time-windowed data."""

    def __init__(self, maxlen: int):
        self.maxlen = maxlen
        self._buffer: Deque[T] = deque(maxlen=maxlen)
        self._lock = Lock()

    def append(self, item: T) -> None:
        """Add item to buffer."""
        with self._lock:
            self._buffer.append(item)

    def extend(self, items: List[T]) -> None:
        """Add multiple items."""
        with self._lock:
            self._buffer.extend(items)

    def get_all(self) -> List[T]:
        """Get all items as a list."""
        with self._lock:
            return list(self._buffer)

    def get_recent(self, n: int) -> List[T]:
        """Get last n items."""
        with self._lock:
            items = list(self._buffer)
            return items[-n:] if n < len(items) else items

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def clear(self) -> None:
        """Clear the buffer."""
        with self._lock:
            self._buffer.clear()


@dataclass
class TimeSeriesBuffer:
    """Efficient buffer for time-series metrics with O(1) updates."""
    maxlen: int = 10000

    _timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=10000))
    _values: Deque[float] = field(default_factory=lambda: deque(maxlen=10000))
    _lock: Lock = field(default_factory=Lock)

    # Running statistics
    _sum: float = 0.0
    _sum_sq: float = 0.0
    _min: float = float('inf')
    _max: float = float('-inf')
    _count: int = 0

    def __post_init__(self):
        self._timestamps = deque(maxlen=self.maxlen)
        self._values = deque(maxlen=self.maxlen)

    def append(self, value: float, timestamp: Optional[float] = None) -> None:
        """Add a value with optional timestamp."""
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            # Handle overflow - remove oldest from stats
            if len(self._values) == self.maxlen:
                old_value = self._values[0]
                self._sum -= old_value
                self._sum_sq -= old_value ** 2

            self._timestamps.append(timestamp)
            self._values.append(value)

            self._sum += value
            self._sum_sq += value ** 2
            self._count = len(self._values)

            if value < self._min:
                self._min = value
            if value > self._max:
                self._max = value

    @property
    def mean(self) -> float:
        """Get mean value."""
        with self._lock:
            if self._count == 0:
                return 0.0
            return self._sum / self._count

    @property
    def variance(self) -> float:
        """Get variance."""
        with self._lock:
            if self._count < 2:
                return 0.0
            mean = self._sum / self._count
            return max(0, (self._sum_sq / self._count) - (mean ** 2))

    @property
    def std(self) -> float:
        """Get standard deviation."""
        return self.variance ** 0.5

    @property
    def min_value(self) -> float:
        return self._min if self._min != float('inf') else 0.0

    @property
    def max_value(self) -> float:
        return self._max if self._max != float('-inf') else 0.0

    def get_values(self) -> List[float]:
        """Get all values."""
        with self._lock:
            return list(self._values)

    def get_recent(self, n: int) -> List[float]:
        """Get recent n values."""
        with self._lock:
            values = list(self._values)
            return values[-n:] if n < len(values) else values


class MetricsStore:
    """
    Central metrics storage for the network sniffer.
    Provides thread-safe access to metrics from multiple components.
    """

    def __init__(
        self,
        max_packets: int = 10000,
        max_flows: int = 5000,
        max_time_series: int = 3600,
    ):
        self.max_packets = max_packets
        self.max_flows = max_flows
        self.max_time_series = max_time_series

        # Per-interface packet buffers
        self._packets: Dict[str, RingBuffer[PacketInfo]] = {}
        self._packets_lock = Lock()

        # Per-interface metrics snapshots
        self._interface_metrics: Dict[str, InterfaceMetrics] = {}
        self._metrics_lock = Lock()

        # Time-series data for charts
        self._time_series: Dict[str, Dict[str, TimeSeriesBuffer]] = {}
        self._ts_lock = Lock()

        # Active flows
        self._flows: Dict[FlowKey, Flow] = {}
        self._flows_lock = Lock()

    def add_packet(self, packet: PacketInfo) -> None:
        """Add a packet to the store."""
        interface = packet.interface

        with self._packets_lock:
            if interface not in self._packets:
                self._packets[interface] = RingBuffer(maxlen=self.max_packets)
            self._packets[interface].append(packet)

    def get_recent_packets(
        self, interface: str, count: int = 100
    ) -> List[PacketInfo]:
        """Get recent packets for an interface."""
        with self._packets_lock:
            buffer = self._packets.get(interface)
            if buffer:
                return buffer.get_recent(count)
            return []

    def update_interface_metrics(
        self, interface: str, metrics: InterfaceMetrics
    ) -> None:
        """Update metrics snapshot for an interface."""
        with self._metrics_lock:
            self._interface_metrics[interface] = metrics

        # Also record time-series data
        self._record_time_series(interface, metrics)

    def get_interface_metrics(self, interface: str) -> Optional[InterfaceMetrics]:
        """Get current metrics for an interface."""
        with self._metrics_lock:
            return self._interface_metrics.get(interface)

    def get_all_interface_metrics(self) -> Dict[str, InterfaceMetrics]:
        """Get metrics for all interfaces."""
        with self._metrics_lock:
            return dict(self._interface_metrics)

    def _record_time_series(
        self, interface: str, metrics: InterfaceMetrics
    ) -> None:
        """Record metrics to time-series buffers."""
        timestamp = time.time()

        with self._ts_lock:
            if interface not in self._time_series:
                self._time_series[interface] = {
                    "packets_per_second": TimeSeriesBuffer(maxlen=self.max_time_series),
                    "bandwidth_mbps": TimeSeriesBuffer(maxlen=self.max_time_series),
                    "latency_ms": TimeSeriesBuffer(maxlen=self.max_time_series),
                    "jitter_ms": TimeSeriesBuffer(maxlen=self.max_time_series),
                    "loss_percent": TimeSeriesBuffer(maxlen=self.max_time_series),
                }

            ts = self._time_series[interface]
            ts["packets_per_second"].append(metrics.packets_per_second, timestamp)
            ts["bandwidth_mbps"].append(metrics.bandwidth_mbps, timestamp)
            ts["latency_ms"].append(metrics.avg_latency, timestamp)
            ts["jitter_ms"].append(metrics.avg_jitter, timestamp)
            ts["loss_percent"].append(metrics.packet_loss_rate, timestamp)

    def get_time_series(
        self, interface: str, metric: str, points: int = 60
    ) -> List[float]:
        """Get time-series data for plotting."""
        with self._ts_lock:
            if interface in self._time_series:
                ts = self._time_series[interface].get(metric)
                if ts:
                    return ts.get_recent(points)
        return []

    def add_flow(self, flow: Flow) -> None:
        """Add or update a flow."""
        with self._flows_lock:
            self._flows[flow.key] = flow

            # Cleanup if over limit
            if len(self._flows) > self.max_flows:
                self._cleanup_flows()

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        """Get a flow by key."""
        with self._flows_lock:
            return self._flows.get(key)

    def get_all_flows(self) -> List[Flow]:
        """Get all flows."""
        with self._flows_lock:
            return list(self._flows.values())

    def get_top_flows(
        self, limit: int = 10, sort_by: str = "bytes"
    ) -> List[Flow]:
        """Get top flows by bytes or packets."""
        with self._flows_lock:
            flows = list(self._flows.values())

        if sort_by == "bytes":
            flows.sort(key=lambda f: f.total_bytes, reverse=True)
        elif sort_by == "packets":
            flows.sort(key=lambda f: f.total_packets, reverse=True)
        elif sort_by == "retransmits":
            flows.sort(key=lambda f: f.retransmits, reverse=True)

        return flows[:limit]

    def _cleanup_flows(self) -> None:
        """Remove oldest flows when over limit."""
        sorted_flows = sorted(
            self._flows.items(),
            key=lambda x: x[1].last_seen
        )
        # Remove oldest 20%
        to_remove = len(sorted_flows) // 5
        for key, _ in sorted_flows[:to_remove]:
            del self._flows[key]

    def get_summary(self) -> Dict:
        """Get overall storage summary."""
        with self._packets_lock:
            total_packets = sum(len(buf) for buf in self._packets.values())

        with self._flows_lock:
            total_flows = len(self._flows)

        with self._metrics_lock:
            interfaces = list(self._interface_metrics.keys())

        return {
            "total_packets_stored": total_packets,
            "total_flows": total_flows,
            "interfaces": interfaces,
            "interface_count": len(interfaces),
        }

    def clear(self) -> None:
        """Clear all stored data."""
        with self._packets_lock:
            self._packets.clear()

        with self._metrics_lock:
            self._interface_metrics.clear()

        with self._ts_lock:
            self._time_series.clear()

        with self._flows_lock:
            self._flows.clear()
