"""Flow and connection tracking models."""

from dataclasses import dataclass, field
from typing import Optional, Deque, Set
from collections import deque


@dataclass(frozen=True)
class FlowKey:
    """
    Unique identifier for a network flow (5-tuple).
    Frozen for hashability.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def reverse(self) -> "FlowKey":
        """Return the reverse flow key."""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol})"


@dataclass
class Flow:
    """Represents a bidirectional network flow."""
    key: FlowKey
    start_time: float
    last_seen: float

    # Packet counters
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    # Loss indicators
    retransmits: int = 0
    out_of_order: int = 0
    duplicate_acks: int = 0

    # RTT tracking (circular buffer for recent samples)
    rtt_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=100))

    # Sequence tracking for retransmit detection
    seen_sequences: Set[int] = field(default_factory=set)
    highest_seq: int = 0

    # Inter-arrival time tracking for jitter
    last_packet_time: Optional[float] = None
    iat_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=100))

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return self.last_seen - self.start_time

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.packets_sent + self.packets_received

    @property
    def total_bytes(self) -> int:
        """Total bytes in both directions."""
        return self.bytes_sent + self.bytes_received

    @property
    def avg_rtt(self) -> Optional[float]:
        """Average RTT in seconds."""
        if not self.rtt_samples:
            return None
        return sum(self.rtt_samples) / len(self.rtt_samples)

    @property
    def avg_rtt_ms(self) -> Optional[float]:
        """Average RTT in milliseconds."""
        avg = self.avg_rtt
        return avg * 1000 if avg is not None else None

    @property
    def packet_loss_rate(self) -> float:
        """Estimated packet loss rate based on retransmits."""
        total = self.total_packets
        if total == 0:
            return 0.0
        return self.retransmits / total

    @property
    def jitter(self) -> Optional[float]:
        """Calculate jitter as mean deviation of inter-arrival times."""
        if len(self.iat_samples) < 2:
            return None
        samples = list(self.iat_samples)
        differences = [abs(samples[i] - samples[i-1]) for i in range(1, len(samples))]
        return sum(differences) / len(differences) if differences else None

    @property
    def jitter_ms(self) -> Optional[float]:
        """Jitter in milliseconds."""
        j = self.jitter
        return j * 1000 if j is not None else None


@dataclass
class TCPConnection(Flow):
    """Extended flow for TCP connection tracking with state machine."""

    # TCP state
    state: str = "UNKNOWN"  # SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED, etc.

    # Handshake timing
    syn_time: Optional[float] = None
    syn_ack_time: Optional[float] = None
    established_time: Optional[float] = None

    # Window tracking
    window_sizes: Deque[int] = field(default_factory=lambda: deque(maxlen=100))

    # Congestion indicators
    ecn_echo_count: int = 0
    window_reductions: int = 0

    @property
    def handshake_time(self) -> Optional[float]:
        """Time to complete TCP 3-way handshake in seconds."""
        if self.syn_time and self.established_time:
            return self.established_time - self.syn_time
        return None

    @property
    def handshake_time_ms(self) -> Optional[float]:
        """Handshake time in milliseconds."""
        ht = self.handshake_time
        return ht * 1000 if ht is not None else None

    @property
    def avg_window_size(self) -> Optional[int]:
        """Average TCP window size."""
        if not self.window_sizes:
            return None
        return int(sum(self.window_sizes) / len(self.window_sizes))
