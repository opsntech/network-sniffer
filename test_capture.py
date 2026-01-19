#!/usr/bin/env python3
"""Simple test to verify packet capture and processing pipeline works."""
import sys
sys.path.insert(0, '/Users/ankitgupta/test/network-sniffer')

import time
from network_sniffer.capture.engine import CaptureEngine
from network_sniffer.capture.interface_manager import InterfaceManager
from network_sniffer.processing.packet_processor import PacketProcessor
from network_sniffer.processing.flow_tracker import FlowTracker

# Get active interface
mgr = InterfaceManager()
active = mgr.get_active()
if not active:
    print("No active interfaces!")
    sys.exit(1)

iface = active[0].name
print(f"Testing capture and processing on: {iface}")
print()

# Create components
engine = CaptureEngine(interfaces=[iface])
flow_tracker = FlowTracker()
processor = PacketProcessor(capture_engine=engine, flow_tracker=flow_tracker)

# Check readiness
issues = engine.check_ready()
if issues:
    print("Issues found:")
    for issue in issues:
        print(f"  - {issue}")
    sys.exit(1)

print("Starting capture and processing for 10 seconds...")
print("(Generate some network traffic if you don't see packets)")
print()

processor.start()

start = time.time()
last_print = 0
while time.time() - start < 10:
    time.sleep(0.5)
    elapsed = time.time() - start
    if int(elapsed) > last_print:
        last_print = int(elapsed)
        stats = engine.get_stats()
        metrics = processor.get_all_metrics()
        m = metrics.get(iface)
        if m:
            print(f"  [{last_print:2d}s] Captured: {stats.packets_captured:5d} | Processed: {m.total_packets:5d} | Flows: {flow_tracker.get_flow_count():3d}")
        else:
            print(f"  [{last_print:2d}s] Captured: {stats.packets_captured:5d} | Processed: (no metrics)")

processor.stop(drain_queue=True)

# Get final stats
capture_stats = engine.get_stats()
processor_stats = processor.get_stats()
all_metrics = processor.get_all_metrics()
m = all_metrics.get(iface)

print()
print("=" * 50)
print("Final Results:")
print("=" * 50)
print()
print("Capture Engine:")
print(f"  Packets captured: {capture_stats.packets_captured:,}")
print(f"  Packets dropped:  {capture_stats.packets_dropped:,}")
print(f"  Bytes captured:   {capture_stats.bytes_captured:,}")
print(f"  Duration:         {capture_stats.duration:.1f}s")
print(f"  Rate:             {capture_stats.packets_per_second:.1f} pps")
print()
print("Packet Processor:")
print(f"  Packets processed: {processor_stats.packets_processed:,}")
print(f"  Processing errors: {processor_stats.processing_errors:,}")
print()
print("Interface Metrics:")
if m:
    print(f"  Total packets:     {m.total_packets:,}")
    print(f"  Total bytes:       {m.total_bytes:,}")
    print(f"  Bandwidth:         {m.bandwidth_mbps:.2f} Mbps")
    print(f"  Packets/sec:       {m.packets_per_second:.1f}")
    print(f"  Retransmissions:   {m.retransmissions:,}")
    print(f"  Protocol counts:   {m.protocol_counts}")
else:
    print("  (No metrics available for interface)")
print()
print("Flow Tracker:")
print(f"  Total flows: {flow_tracker.get_flow_count()}")
flows = flow_tracker.get_all_flows()
if flows:
    print("  Top 5 flows by bytes:")
    for flow in sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:5]:
        print(f"    {flow.key.src_ip}:{flow.key.src_port} -> {flow.key.dst_ip}:{flow.key.dst_port} ({flow.key.protocol}) - {flow.total_bytes:,} bytes")

print()
print("=" * 50)
# Validation
if capture_stats.packets_captured == 0:
    print("[ERROR] No packets captured!")
    print("  - Check if running with sudo")
    print("  - Check if interface is correct")
    print("  - Generate some network traffic")
    sys.exit(1)
elif processor_stats.packets_processed == 0:
    print("[ERROR] Packets captured but not processed!")
    print("  - Processing pipeline may have an issue")
    sys.exit(1)
elif m is None or m.total_packets == 0:
    print("[ERROR] Packets processed but no metrics!")
    print("  - Interface name mismatch possible")
    sys.exit(1)
else:
    print("[OK] Full pipeline is working!")
    print(f"     Capture -> Processing -> Metrics: {m.total_packets:,} packets")
