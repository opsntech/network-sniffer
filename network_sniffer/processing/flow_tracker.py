"""TCP/UDP flow tracking."""

import time
from typing import Dict, Optional, List, Tuple
from collections import defaultdict
from threading import Lock

from ..models.packet import PacketInfo, Protocol, TCPFlags
from ..models.flow import FlowKey, Flow, TCPConnection


class FlowTracker:
    """
    Tracks network flows (TCP connections and UDP streams).
    Identifies retransmissions, out-of-order packets, and calculates RTT.
    """

    def __init__(self, flow_timeout: float = 300.0, max_flows: int = 10000):
        """
        Args:
            flow_timeout: Seconds of inactivity before flow is expired
            max_flows: Maximum number of flows to track
        """
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows

        # Flow storage
        self._flows: Dict[FlowKey, Flow] = {}
        self._tcp_connections: Dict[FlowKey, TCPConnection] = {}
        self._lock = Lock()

        # Pending SYN tracking for RTT calculation
        self._pending_syns: Dict[FlowKey, float] = {}

        # Sequence number tracking for retransmit detection
        self._seq_history: Dict[FlowKey, Dict[int, float]] = defaultdict(dict)

    def process_packet(self, packet: PacketInfo) -> Tuple[Flow, Optional[str]]:
        """
        Process a packet and update flow state.

        Returns:
            Tuple of (Flow, event_type) where event_type can be:
            - "new_flow": New flow created
            - "retransmit": TCP retransmission detected
            - "out_of_order": Out-of-order packet
            - "duplicate_ack": Duplicate ACK detected
            - "rtt_sample": RTT measurement available
            - None: Normal packet
        """
        if packet.src_port is None or packet.dst_port is None:
            # Non-TCP/UDP packet (e.g., ICMP)
            return self._handle_non_flow_packet(packet)

        flow_key = self._get_flow_key(packet)
        event = None

        with self._lock:
            # Get or create flow
            if flow_key not in self._flows:
                if len(self._flows) >= self.max_flows:
                    self._expire_oldest_flows()

                flow = self._create_flow(flow_key, packet)
                event = "new_flow"
            else:
                flow = self._flows[flow_key]

            # Update flow
            flow.last_seen = packet.timestamp

            # Determine packet direction
            is_outgoing = (packet.src_ip == flow.key.src_ip and
                          packet.src_port == flow.key.src_port)

            if is_outgoing:
                flow.packets_sent += 1
                flow.bytes_sent += packet.length
            else:
                flow.packets_received += 1
                flow.bytes_received += packet.length

            # TCP-specific processing
            if packet.is_tcp():
                tcp_event = self._process_tcp_packet(flow_key, packet, flow)
                if tcp_event:
                    event = tcp_event

            # Update inter-arrival time for jitter calculation
            if flow.last_packet_time is not None:
                iat = packet.timestamp - flow.last_packet_time
                flow.iat_samples.append(iat)
            flow.last_packet_time = packet.timestamp

            return flow, event

    def _get_flow_key(self, packet: PacketInfo) -> FlowKey:
        """Create normalized flow key (smaller IP/port first for bidirectional)."""
        # Normalize to ensure same key for both directions
        if (packet.src_ip, packet.src_port) < (packet.dst_ip, packet.dst_port):
            return FlowKey(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol.value,
            )
        else:
            return FlowKey(
                src_ip=packet.dst_ip,
                dst_ip=packet.src_ip,
                src_port=packet.dst_port,
                dst_port=packet.src_port,
                protocol=packet.protocol.value,
            )

    def _create_flow(self, key: FlowKey, packet: PacketInfo) -> Flow:
        """Create a new flow."""
        if packet.is_tcp():
            flow = TCPConnection(
                key=key,
                start_time=packet.timestamp,
                last_seen=packet.timestamp,
            )
            self._tcp_connections[key] = flow
        else:
            flow = Flow(
                key=key,
                start_time=packet.timestamp,
                last_seen=packet.timestamp,
            )

        self._flows[key] = flow
        return flow

    def _process_tcp_packet(
        self, flow_key: FlowKey, packet: PacketInfo, flow: Flow
    ) -> Optional[str]:
        """Process TCP-specific packet information."""
        event = None
        flags = packet.get_tcp_flags()
        if not flags:
            return None

        # Get TCP connection state
        tcp_conn = self._tcp_connections.get(flow_key)

        # Track TCP state machine
        if tcp_conn:
            if flags.syn and not flags.ack:
                # SYN - Connection initiation
                tcp_conn.state = "SYN_SENT"
                tcp_conn.syn_time = packet.timestamp
                self._pending_syns[flow_key] = packet.timestamp

            elif flags.syn and flags.ack:
                # SYN-ACK
                tcp_conn.state = "SYN_RECEIVED"
                tcp_conn.syn_ack_time = packet.timestamp

                # Calculate RTT from SYN to SYN-ACK
                if flow_key in self._pending_syns:
                    rtt = packet.timestamp - self._pending_syns[flow_key]
                    flow.rtt_samples.append(rtt)
                    packet.rtt = rtt
                    event = "rtt_sample"

            elif flags.ack and not flags.syn and not flags.fin:
                if tcp_conn.state in ("SYN_SENT", "SYN_RECEIVED"):
                    # Handshake complete
                    tcp_conn.state = "ESTABLISHED"
                    tcp_conn.established_time = packet.timestamp

            elif flags.fin:
                tcp_conn.state = "FIN_WAIT"

            elif flags.rst:
                tcp_conn.state = "CLOSED"

            # Track window sizes
            if packet.window_size is not None:
                tcp_conn.window_sizes.append(packet.window_size)

            # Track ECN
            if flags.ece:
                tcp_conn.ecn_echo_count += 1

        # Detect retransmission
        if packet.seq_num is not None:
            retransmit_event = self._check_retransmission(flow_key, packet, flow)
            if retransmit_event:
                event = retransmit_event

        # Detect duplicate ACKs
        if packet.ack_num is not None and flags.ack:
            dup_ack_event = self._check_duplicate_ack(flow_key, packet, flow)
            if dup_ack_event:
                event = dup_ack_event

        return event

    def _check_retransmission(
        self, flow_key: FlowKey, packet: PacketInfo, flow: Flow
    ) -> Optional[str]:
        """
        Check if packet is a retransmission.
        A retransmit is when we see the same sequence number again.
        """
        seq = packet.seq_num
        if seq is None:
            return None

        seq_history = self._seq_history[flow_key]

        if seq in seq_history:
            # This is a retransmission
            original_time = seq_history[seq]
            retransmit_delay = packet.timestamp - original_time

            flow.retransmits += 1
            packet.is_retransmit = True

            # Use retransmit delay as RTT estimate
            if retransmit_delay > 0:
                flow.rtt_samples.append(retransmit_delay)

            return "retransmit"

        # Check for out-of-order (sequence lower than highest seen, but not retransmit)
        if seq < flow.highest_seq and seq not in flow.seen_sequences:
            flow.out_of_order += 1
            return "out_of_order"

        # Track this sequence
        seq_history[seq] = packet.timestamp
        flow.seen_sequences.add(seq)
        flow.highest_seq = max(flow.highest_seq, seq)

        # Cleanup old sequences (keep last 1000)
        if len(seq_history) > 1000:
            oldest_seqs = sorted(seq_history.items(), key=lambda x: x[1])[:500]
            for old_seq, _ in oldest_seqs:
                del seq_history[old_seq]
                flow.seen_sequences.discard(old_seq)

        return None

    def _check_duplicate_ack(
        self, flow_key: FlowKey, packet: PacketInfo, flow: Flow
    ) -> Optional[str]:
        """
        Check for duplicate ACKs.
        3+ duplicate ACKs indicate packet loss.
        """
        # Simplified: track last few ACKs per flow
        # A proper implementation would track per-direction
        return None  # TODO: Implement full duplicate ACK tracking

    def _handle_non_flow_packet(self, packet: PacketInfo) -> Tuple[Flow, Optional[str]]:
        """Handle packets without ports (ICMP, etc.)."""
        # Create a pseudo-flow for tracking
        key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=0,
            dst_port=0,
            protocol=packet.protocol.value,
        )

        with self._lock:
            if key not in self._flows:
                flow = Flow(
                    key=key,
                    start_time=packet.timestamp,
                    last_seen=packet.timestamp,
                )
                self._flows[key] = flow
                return flow, "new_flow"
            else:
                flow = self._flows[key]
                flow.last_seen = packet.timestamp
                flow.packets_sent += 1
                flow.bytes_sent += packet.length
                return flow, None

    def _expire_oldest_flows(self) -> None:
        """Remove oldest flows when at capacity."""
        # Sort by last_seen and remove oldest 10%
        sorted_flows = sorted(
            self._flows.items(),
            key=lambda x: x[1].last_seen
        )
        to_remove = len(sorted_flows) // 10
        for key, _ in sorted_flows[:to_remove]:
            del self._flows[key]
            self._tcp_connections.pop(key, None)
            self._seq_history.pop(key, None)
            self._pending_syns.pop(key, None)

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        """Get flow by key."""
        with self._lock:
            return self._flows.get(key)

    def get_all_flows(self) -> List[Flow]:
        """Get all tracked flows."""
        with self._lock:
            return list(self._flows.values())

    def get_active_flows(self, max_age: float = 60.0) -> List[Flow]:
        """Get flows active within max_age seconds."""
        now = time.time()
        with self._lock:
            return [
                f for f in self._flows.values()
                if now - f.last_seen <= max_age
            ]

    def get_tcp_connections(self) -> List[TCPConnection]:
        """Get all TCP connections."""
        with self._lock:
            return list(self._tcp_connections.values())

    def get_flow_count(self) -> int:
        """Get number of tracked flows."""
        with self._lock:
            return len(self._flows)

    def cleanup_expired(self) -> int:
        """Remove expired flows. Returns count removed."""
        now = time.time()
        removed = 0

        with self._lock:
            expired_keys = [
                key for key, flow in self._flows.items()
                if now - flow.last_seen > self.flow_timeout
            ]

            for key in expired_keys:
                del self._flows[key]
                self._tcp_connections.pop(key, None)
                self._seq_history.pop(key, None)
                self._pending_syns.pop(key, None)
                removed += 1

        return removed
