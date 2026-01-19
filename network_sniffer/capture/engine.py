"""Packet capture engine using Scapy."""

import asyncio
import threading
import time
from typing import List, Callable, Optional, Dict
from dataclasses import dataclass
from queue import Queue, Full

from scapy.all import sniff, conf, IP, TCP, UDP, ICMP, DNS, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse

from ..models.packet import PacketInfo, Protocol
from .platform_adapter import PlatformAdapter, get_platform_adapter


@dataclass
class CaptureStats:
    """Statistics for packet capture."""
    packets_captured: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    start_time: float = 0.0
    interfaces: Dict[str, int] = None

    def __post_init__(self):
        if self.interfaces is None:
            self.interfaces = {}

    @property
    def duration(self) -> float:
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time

    @property
    def packets_per_second(self) -> float:
        if self.duration == 0:
            return 0.0
        return self.packets_captured / self.duration


class CaptureEngine:
    """
    Cross-platform packet capture engine using Scapy.
    Supports capturing on multiple interfaces simultaneously.
    """

    def __init__(
        self,
        interfaces: List[str],
        bpf_filter: str = "",
        platform_adapter: Optional[PlatformAdapter] = None,
        queue_size: int = 10000,
    ):
        self.interfaces = interfaces
        self.bpf_filter = bpf_filter
        self.adapter = platform_adapter or get_platform_adapter()
        self._max_queue_size = queue_size

        self._running = False
        self._capture_threads: List[threading.Thread] = []
        self._packet_queue: Queue = Queue(maxsize=queue_size)
        self._stats = CaptureStats()
        self._stats_lock = threading.Lock()

        # Configure Scapy
        self._configure_scapy()

    def _configure_scapy(self) -> None:
        """Apply platform-specific Scapy configuration."""
        config = self.adapter.get_capture_config()

        # Disable verbose output
        conf.verb = 0

        # Set promiscuous mode
        conf.promisc = config.promiscuous

    def check_ready(self) -> List[str]:
        """
        Check if capture engine is ready to start.
        Returns list of issues, empty if ready.
        """
        issues = []

        # Check dependencies
        missing_deps = self.adapter.check_dependencies()
        if missing_deps:
            issues.extend([f"Missing dependency: {dep}" for dep in missing_deps])

        # Check privileges
        if not self.adapter.check_privileges():
            issues.append("Insufficient privileges. Run with sudo/administrator rights.")

        # Validate interfaces
        from .interface_manager import InterfaceManager
        mgr = InterfaceManager()
        invalid = mgr.validate_interfaces(self.interfaces)
        if invalid:
            issues.extend([f"Invalid interface: {iface}" for iface in invalid])

        return issues

    def start(self) -> None:
        """Start packet capture on all interfaces."""
        if self._running:
            return

        # Check readiness
        issues = self.check_ready()
        if issues:
            raise RuntimeError("Cannot start capture:\n" + "\n".join(issues))

        self._running = True
        self._stats = CaptureStats(start_time=time.time())
        self._stats.interfaces = {iface: 0 for iface in self.interfaces}

        # Start capture thread for each interface
        for iface in self.interfaces:
            thread = threading.Thread(
                target=self._capture_loop,
                args=(iface,),
                daemon=True,
                name=f"capture-{iface}",
            )
            thread.start()
            self._capture_threads.append(thread)

    def stop(self) -> None:
        """Stop all capture threads."""
        self._running = False
        for thread in self._capture_threads:
            thread.join(timeout=2.0)
        self._capture_threads.clear()

    def _capture_loop(self, interface: str) -> None:
        """Capture loop for a single interface."""
        def process_packet(pkt):
            if not self._running:
                return

            # Parse packet
            packet_info = self._parse_packet(pkt, interface)
            if packet_info is None:
                return

            # Update stats
            with self._stats_lock:
                self._stats.packets_captured += 1
                self._stats.bytes_captured += packet_info.length
                self._stats.interfaces[interface] = self._stats.interfaces.get(interface, 0) + 1

            # Queue packet
            try:
                self._packet_queue.put_nowait(packet_info)
            except Full:
                with self._stats_lock:
                    self._stats.packets_dropped += 1

        try:
            sniff(
                iface=interface,
                filter=self.bpf_filter,
                prn=process_packet,
                store=False,  # Don't store packets in memory
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            # Log error but don't crash
            print(f"Capture error on {interface}: {e}")

    def _parse_packet(self, pkt, interface: str) -> Optional[PacketInfo]:
        """Parse Scapy packet into PacketInfo dataclass."""
        # Skip non-IP packets
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]

        # Determine protocol and extract relevant fields
        protocol = Protocol.OTHER
        src_port = None
        dst_port = None
        tcp_flags = None
        seq_num = None
        ack_num = None
        window_size = None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            protocol = Protocol.TCP
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = int(tcp.flags)
            seq_num = tcp.seq
            ack_num = tcp.ack
            window_size = tcp.window

            # Detect HTTP/HTTPS by port
            if dst_port == 80 or src_port == 80:
                protocol = Protocol.HTTP
            elif dst_port == 443 or src_port == 443:
                protocol = Protocol.HTTPS

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            protocol = Protocol.UDP
            src_port = udp.sport
            dst_port = udp.dport

            # Detect DNS
            if pkt.haslayer(DNS):
                protocol = Protocol.DNS

        elif pkt.haslayer(ICMP):
            protocol = Protocol.ICMP

        return PacketInfo(
            timestamp=time.time(),
            interface=interface,
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(pkt),
            ttl=ip_layer.ttl,
            tcp_flags=tcp_flags,
            seq_num=seq_num,
            ack_num=ack_num,
            window_size=window_size,
        )

    def get_packet(self, timeout: float = 1.0) -> Optional[PacketInfo]:
        """Get next packet from queue."""
        try:
            return self._packet_queue.get(timeout=timeout)
        except:
            return None

    def get_packet_nowait(self) -> Optional[PacketInfo]:
        """Get next packet without blocking."""
        try:
            return self._packet_queue.get_nowait()
        except:
            return None

    async def get_packet_async(self) -> Optional[PacketInfo]:
        """Async version of get_packet."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.get_packet, 0.1)

    def get_stats(self) -> CaptureStats:
        """Get capture statistics."""
        with self._stats_lock:
            return CaptureStats(
                packets_captured=self._stats.packets_captured,
                packets_dropped=self._stats.packets_dropped,
                bytes_captured=self._stats.bytes_captured,
                start_time=self._stats.start_time,
                interfaces=dict(self._stats.interfaces),
            )

    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._running

    @property
    def current_queue_size(self) -> int:
        """Get current queue size."""
        return self._packet_queue.qsize()
