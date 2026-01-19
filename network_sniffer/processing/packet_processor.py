"""Main packet processing pipeline."""

import asyncio
import time
from typing import Optional, Callable, List, Dict
from dataclasses import dataclass, field
from threading import Thread, Event

from ..models.packet import PacketInfo
from ..models.metrics import InterfaceMetrics
from ..capture.engine import CaptureEngine
from .flow_tracker import FlowTracker


@dataclass
class ProcessorStats:
    """Statistics for packet processor."""
    packets_processed: int = 0
    processing_errors: int = 0
    start_time: float = 0.0

    @property
    def duration(self) -> float:
        if self.start_time == 0:
            return 0.0
        return time.time() - self.start_time

    @property
    def packets_per_second(self) -> float:
        if self.duration == 0:
            return 0.0
        return self.packets_processed / self.duration


class PacketProcessor:
    """
    Main packet processing pipeline.
    Coordinates capture, flow tracking, and metrics collection.
    """

    def __init__(
        self,
        capture_engine: CaptureEngine,
        flow_tracker: Optional[FlowTracker] = None,
    ):
        self.capture = capture_engine
        self.flow_tracker = flow_tracker or FlowTracker()

        # Interface metrics
        self._interface_metrics: Dict[str, InterfaceMetrics] = {}
        for iface in capture_engine.interfaces:
            self._interface_metrics[iface] = InterfaceMetrics(interface_name=iface)

        # Processing state
        self._running = False
        self._stop_event = Event()
        self._processor_thread: Optional[Thread] = None
        self._stats = ProcessorStats()

        # Callbacks
        self._packet_callbacks: List[Callable[[PacketInfo], None]] = []
        self._event_callbacks: List[Callable[[str, PacketInfo], None]] = []

    def add_packet_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """Add callback for each processed packet."""
        self._packet_callbacks.append(callback)

    def add_event_callback(self, callback: Callable[[str, PacketInfo], None]) -> None:
        """Add callback for flow events (retransmit, etc.)."""
        self._event_callbacks.append(callback)

    def start(self) -> None:
        """Start packet processing."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._stats = ProcessorStats(start_time=time.time())

        # Start capture
        self.capture.start()

        # Start processing thread
        self._processor_thread = Thread(
            target=self._processing_loop,
            daemon=True,
            name="packet-processor",
        )
        self._processor_thread.start()

    def stop(self, drain_queue: bool = True) -> None:
        """Stop packet processing.

        Args:
            drain_queue: If True, process all remaining packets in queue before stopping
        """
        # Stop capture first to prevent new packets
        self.capture.stop()

        # Drain remaining packets from queue
        if drain_queue:
            drained = 0
            while True:
                packet = self.capture.get_packet_nowait()
                if packet is None:
                    break
                try:
                    self._process_packet(packet)
                    self._stats.packets_processed += 1
                    drained += 1
                except Exception:
                    self._stats.processing_errors += 1
            if drained > 0:
                # Do final rate calculation
                self._calculate_rates(time.time())

        self._running = False
        self._stop_event.set()

        # Wait for processor thread to finish
        if self._processor_thread:
            self._processor_thread.join(timeout=2.0)

        # Final rate calculation
        self._calculate_rates(time.time())

    def _processing_loop(self) -> None:
        """Main processing loop."""
        last_rate_calc = time.time()
        rate_interval = 1.0  # Calculate rates every second

        while self._running and not self._stop_event.is_set():
            # Get packet from capture queue
            packet = self.capture.get_packet(timeout=0.1)
            if packet is None:
                continue

            try:
                self._process_packet(packet)
                self._stats.packets_processed += 1
            except Exception as e:
                self._stats.processing_errors += 1
                # Log but don't crash
                print(f"Processing error: {e}")

            # Periodic rate calculation
            now = time.time()
            if now - last_rate_calc >= rate_interval:
                self._calculate_rates(now)
                last_rate_calc = now

    def _process_packet(self, packet: PacketInfo) -> None:
        """Process a single packet."""
        # Update interface metrics
        metrics = self._interface_metrics.get(packet.interface)
        if metrics:
            metrics.total_packets += 1
            metrics.total_bytes += packet.length

            # Update protocol counts
            proto = packet.protocol.value
            metrics.protocol_counts[proto] = metrics.protocol_counts.get(proto, 0) + 1
            metrics.protocol_bytes[proto] = metrics.protocol_bytes.get(proto, 0) + packet.length

        # Process through flow tracker
        flow, event = self.flow_tracker.process_packet(packet)

        # Update metrics based on flow events
        if metrics and event:
            if event == "retransmit":
                metrics.retransmissions += 1
            elif event == "out_of_order":
                metrics.out_of_order += 1
            elif event == "duplicate_ack":
                metrics.duplicate_acks += 1
            elif event == "rtt_sample" and packet.rtt:
                metrics.add_latency_sample(packet.rtt * 1000)  # Convert to ms

        # Calculate jitter from flow
        if flow.jitter_ms is not None and metrics:
            metrics.add_jitter_sample(flow.jitter_ms)

        # Invoke callbacks
        for callback in self._packet_callbacks:
            try:
                callback(packet)
            except Exception:
                pass

        if event:
            for callback in self._event_callbacks:
                try:
                    callback(event, packet)
                except Exception:
                    pass

    def _calculate_rates(self, now: float) -> None:
        """Calculate packet/byte rates for all interfaces."""
        for metrics in self._interface_metrics.values():
            metrics.calculate_rates(now)

    def get_interface_metrics(self, interface: str) -> Optional[InterfaceMetrics]:
        """Get metrics for a specific interface."""
        return self._interface_metrics.get(interface)

    def get_all_metrics(self) -> Dict[str, InterfaceMetrics]:
        """Get metrics for all interfaces."""
        return dict(self._interface_metrics)

    def get_stats(self) -> ProcessorStats:
        """Get processor statistics."""
        return self._stats

    def get_flow_tracker(self) -> FlowTracker:
        """Get flow tracker instance."""
        return self.flow_tracker

    def is_running(self) -> bool:
        """Check if processor is running."""
        return self._running

    def get_debug_info(self) -> Dict[str, any]:
        """Get debug information about processor state."""
        return {
            "running": self._running,
            "packets_processed": self._stats.packets_processed,
            "processing_errors": self._stats.processing_errors,
            "duration": self._stats.duration,
            "queue_size": self.capture.current_queue_size if hasattr(self.capture, 'current_queue_size') else 0,
            "interfaces": list(self._interface_metrics.keys()),
            "interface_packet_counts": {
                iface: m.total_packets
                for iface, m in self._interface_metrics.items()
            },
        }

    async def run_async(self) -> None:
        """Async version of processing loop."""
        self._running = True
        self._stats = ProcessorStats(start_time=time.time())
        self.capture.start()

        last_rate_calc = time.time()

        while self._running:
            packet = await self.capture.get_packet_async()
            if packet:
                try:
                    self._process_packet(packet)
                    self._stats.packets_processed += 1
                except Exception as e:
                    self._stats.processing_errors += 1

            now = time.time()
            if now - last_rate_calc >= 1.0:
                self._calculate_rates(now)
                last_rate_calc = now

            await asyncio.sleep(0)  # Yield to other tasks
