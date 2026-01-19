# Network Sniffer Implementation Plan

## Executive Summary

Your infrastructure has 2 network connections with packet drops and speed issues that vendors claim aren't their problem. This plan completes the network sniffer tool to identify exactly where the bottleneck is - whether it's at the interface level, network path, or application layer.

## Current State Analysis

### What's Already Built (90% Complete)
| Module | Status | Description |
|--------|--------|-------------|
| Capture Engine | ✅ Complete | Multi-interface Scapy-based packet capture |
| Packet Processor | ✅ Complete | Real-time packet analysis with flow tracking |
| Flow Tracker | ✅ Complete | TCP/UDP flow tracking, retransmit detection |
| Packet Loss Detector | ✅ Complete | Localizes WHERE drops occur |
| Latency Analyzer | ✅ Complete | RTT analysis with percentiles |
| Jitter Analyzer | ✅ Complete | Inter-arrival time variation |
| Bottleneck Detector | ✅ Complete | Multi-metric correlation |
| Interface Comparator | ✅ Complete | Compare your 2 connections side-by-side |
| Alert Manager | ✅ Complete | Threshold-based alerting with hysteresis |
| Metrics Store | ✅ Complete | Thread-safe storage with time-series |

### What's Missing (10% Remaining)
| Module | Status | Priority |
|--------|--------|----------|
| CLI Entry Point | ❌ Missing | HIGH |
| Terminal Dashboard | ❌ Missing | HIGH |
| Export/Reporting | ❌ Missing | MEDIUM |
| Configuration | ❌ Missing | MEDIUM |

---

## Implementation Plan

### Phase 1: CLI Entry Point (Priority: HIGH)

**File**: `network_sniffer/cli.py`

Create the main CLI interface with these commands:

```
network-sniffer capture --interfaces eth0,eth1 --duration 60
network-sniffer analyze --compare eth0 eth1
network-sniffer dashboard --interfaces eth0,eth1
network-sniffer export --format json --output report.json
```

**Features**:
- Auto-detect available network interfaces
- Support for capturing on multiple interfaces simultaneously
- BPF filter support (e.g., `--filter "tcp port 443"`)
- Duration-based capture with real-time stats
- Privilege checking (requires root/admin)

**Implementation**:
1. Use `argparse` for command parsing
2. Create `SnifferApp` class to coordinate components
3. Implement graceful shutdown on Ctrl+C
4. Add progress indicators with Rich

---

### Phase 2: Terminal Dashboard (Priority: HIGH)

**Files**: `network_sniffer/ui/dashboard.py`, `network_sniffer/ui/widgets/`

Build a real-time TUI dashboard using Textual framework:

```
┌─────────────────────────────────────────────────────────────────────┐
│ NETWORK SNIFFER DASHBOARD                          [eth0] [eth1]   │
├─────────────────────────────────────────────────────────────────────┤
│ ┌─ Interface 1: eth0 ──────────┐ ┌─ Interface 2: eth1 ──────────┐  │
│ │ Status: CAPTURING            │ │ Status: CAPTURING            │  │
│ │ Packets: 145,234             │ │ Packets: 98,445              │  │
│ │ Bandwidth: 45.2 Mbps         │ │ Bandwidth: 32.1 Mbps         │  │
│ │ Packet Loss: 2.3% ⚠️          │ │ Packet Loss: 0.1% ✓          │  │
│ │ Latency: 45ms (P95: 120ms)   │ │ Latency: 23ms (P95: 45ms)    │  │
│ │ Jitter: 12ms                 │ │ Jitter: 5ms                  │  │
│ │ Health Score: 67/100         │ │ Health Score: 94/100         │  │
│ └──────────────────────────────┘ └──────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│ ┌─ Packet Loss Over Time ───────────────────────────────────────┐  │
│ │    5% │      *                                                │  │
│ │       │    * * *      eth0                                    │  │
│ │    2% │  *       *  *                                         │  │
│ │       │ *         **  *                                       │  │
│ │    0% │─────────────────*─*─*─*─ eth1 ────────────────────────│  │
│ │       └───────────────────────────────────────────────────────│  │
│ │         -60s                    -30s                    now   │  │
│ └───────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│ ┌─ ALERTS ──────────────────────────────────────────────────────┐  │
│ │ [CRITICAL] eth0: Packet loss 2.3% exceeds threshold (1.0%)   │  │
│ │ [WARNING]  eth0: Latency P95 120ms exceeds threshold (100ms) │  │
│ │ [INFO]     eth1: Operating normally                          │  │
│ └───────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│ ┌─ TOP FLOWS ───────────────────────────────────────────────────┐  │
│ │ Source              Dest                Proto  Bytes   Loss   │  │
│ │ 192.168.1.10:443    10.0.0.5:52341      TCP    45MB    3.2%  │  │
│ │ 192.168.1.10:80     10.0.0.8:49221      TCP    12MB    0.1%  │  │
│ └───────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│ [Q]uit  [P]ause  [R]eset  [E]xport  [C]ompare  [A]lerts          │
└─────────────────────────────────────────────────────────────────────┘
```

**Widgets to Implement**:
1. `InterfaceStatus` - Per-interface metrics panel
2. `TimeSeriesChart` - Real-time graphs using Plotext
3. `AlertPanel` - Live alert feed with severity colors
4. `FlowTable` - Top flows with loss indicators
5. `ComparisonView` - Side-by-side interface comparison
6. `BottleneckPanel` - Current bottleneck diagnosis

---

### Phase 3: Export & Reporting (Priority: MEDIUM)

**Files**: `network_sniffer/export/`

Implement export functionality for evidence gathering:

1. **JSON Export**: Full metrics dump for programmatic analysis
2. **CSV Export**: Time-series data for spreadsheet analysis
3. **HTML Report**: Standalone diagnostic report with embedded charts

**Report Contents**:
- Executive summary with findings
- Per-interface metrics comparison
- Time-series graphs (packet loss, latency, bandwidth)
- Alert history
- Top problematic flows
- Recommended actions
- Evidence for vendor escalation

---

### Phase 4: Configuration (Priority: MEDIUM)

**Files**: `network_sniffer/config.py`, `config.yaml`

Create configuration system:

```yaml
# config.yaml
capture:
  interfaces:
    - eth0
    - eth1
  duration: 0  # 0 = continuous
  buffer_size: 10000

alerts:
  profile: voip  # voip, video, gaming, general
  thresholds:
    packet_loss:
      warning: 0.5
      critical: 1.0
    latency:
      warning: 100
      critical: 150

export:
  auto_export: true
  interval: 300  # seconds
  format: json
  path: ./reports/
```

---

## Architecture Diagram

```
                    ┌────────────────────────────────────┐
                    │           CLI Entry Point          │
                    │         (network-sniffer)          │
                    └─────────────┬──────────────────────┘
                                  │
                    ┌─────────────▼──────────────────────┐
                    │         SnifferApp                 │
                    │    (Main Coordinator Class)        │
                    └─────────────┬──────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ CaptureEngine │       │  MetricsStore   │       │   Dashboard     │
│ (per interface)│──────▶│  (thread-safe)  │◀──────│   (Textual)     │
└───────┬───────┘       └────────┬────────┘       └─────────────────┘
        │                        │
        ▼                        ▼
┌───────────────┐       ┌─────────────────┐
│PacketProcessor│       │  AlertManager   │───▶ Callbacks
│  FlowTracker  │       │  (evaluates)    │
└───────┬───────┘       └─────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│           Analysis Layer                │
│  ┌──────────────┐ ┌──────────────────┐  │
│  │PacketLoss    │ │BottleneckDetector│  │
│  │Detector      │ │                  │  │
│  └──────────────┘ └──────────────────┘  │
│  ┌──────────────┐ ┌──────────────────┐  │
│  │Latency       │ │Interface         │  │
│  │Analyzer      │ │Comparator        │  │
│  └──────────────┘ └──────────────────┘  │
└─────────────────────────────────────────┘
```

---

## Implementation Status

### Step 1: CLI Module - COMPLETED
- [x] Create `cli.py` with argparse
- [x] Implement `SnifferApp` coordinator class
- [x] Add interface detection and validation
- [x] Implement basic capture command
- [x] Add signal handling for graceful shutdown

### Step 2: Dashboard Framework - COMPLETED
- [x] Create `ui/__init__.py` with exports
- [x] Implement base `Dashboard` class using Textual
- [x] Create `InterfacePanel` widget
- [x] Create `AlertsPanel` widget
- [x] Create `FlowTableWidget` widget

### Step 3: Real-time Charts - COMPLETED
- [x] Implement `TimeSeriesChart` using Plotext
- [x] Implement `SparklineChart` for simple inline charts
- [x] Charts integrated into dashboard

### Step 4: Comparison & Analysis - COMPLETED
- [x] Create `ComparisonPanel` widget
- [x] Integrate `InterfaceComparator` results
- [x] Create `BottleneckPanel` widget
- [x] Implement recommendation display

### Step 5: Export & Reporting - COMPLETED
- [x] Create `export/__init__.py`
- [x] Implement `JSONExporter`
- [x] Implement `CSVExporter`
- [x] Implement `HTMLReportGenerator`
- [x] Implement unified `ReportGenerator`

### Step 6: Configuration - COMPLETED
- [x] Create `config.py` with dataclasses
- [x] Add YAML loading support (optional dependency)
- [x] Implement config validation
- [x] Add CLI config override support

---

## What This Will Diagnose

Once complete, the tool will tell you:

1. **Which connection is better**: Side-by-side health scores for both interfaces
2. **Where drops occur**:
   - Interface level (NIC buffer overflow)
   - Network path (congestion, routing issues)
   - Application level (socket buffers)
3. **What's causing slowness**:
   - High latency (routing issues, distance)
   - High jitter (congestion, QoS problems)
   - Bandwidth saturation
   - TCP retransmissions
4. **Evidence for vendors**: Exportable reports with timestamps, metrics, and graphs
5. **Specific recommendations**: Actionable fixes based on detected issues

---

## Technical Requirements

- **Python**: 3.9+
- **OS**: macOS, Linux (Windows partial support)
- **Privileges**: Root/sudo required for packet capture
- **Dependencies**: Already in pyproject.toml (scapy, textual, rich, plotext, etc.)

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Requires root | Add clear privilege check and error message |
| High packet rate | Ring buffers with configurable size |
| Memory growth | LRU eviction in flow tracker |
| CPU load | Efficient packet processing, sampling option |

---

## Deliverables

1. **Fully functional CLI** with capture, analyze, dashboard, export commands
2. **Real-time dashboard** showing both interfaces with comparison
3. **Diagnostic reports** with evidence for vendor escalation
4. **Clear identification** of which connection has issues and why
