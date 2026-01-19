# Network Sniffer

Enterprise-grade network diagnostic tool for identifying packet loss, bottlenecks, and performance issues across multiple network interfaces.

## Features

- **Real-time Packet Capture**: Capture and analyze network traffic using Scapy
- **Multi-Interface Support**: Monitor and compare multiple network interfaces simultaneously
- **Performance Metrics**: Track bandwidth, latency, jitter, packet loss, and retransmissions
- **Flow Tracking**: TCP/UDP flow analysis with retransmission detection
- **Bottleneck Detection**: Automatic identification of network issues with severity scoring
- **Interface Comparison**: Side-by-side comparison of network connections
- **Alert System**: Configurable thresholds with real-time alerts
- **Report Generation**: Export to JSON, CSV, and HTML formats
- **Cross-Platform**: Works on macOS, Linux, and Windows

## Quick Start

### Automated Setup (Recommended)

```bash
# Clone the repository
git clone git@github.com:opsntech/network-sniffer.git
cd network-sniffer

# Run the setup script
./setup.sh
```

### Manual Setup

#### Prerequisites

**macOS:**
```bash
# libpcap is pre-installed
brew install python3
```

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv libpcap-dev
```

**RHEL/CentOS:**
```bash
sudo yum install python3 python3-pip libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip libpcap
```

#### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

# Or using requirements.txt
pip install -r requirements.txt
```

## Usage

### List Available Interfaces

```bash
./sniff.sh list
```

### Run Network Diagnostic

```bash
# Basic diagnostic (30 seconds)
sudo ./sniff.sh diagnose -i en0 -d 30

# Compare two interfaces (60 seconds)
sudo ./sniff.sh diagnose -i en0,eth0 -d 60

# With BPF filter
sudo ./sniff.sh diagnose -i en0 -d 30 -f "tcp port 443"
```

### Live Capture with Dashboard

```bash
sudo ./sniff.sh capture -i en0 --dashboard -d 60
```

## Output

After running a diagnostic, reports are generated in the `./reports/` directory:

- **HTML Report**: Visual summary with charts and recommendations
- **JSON Report**: Raw data for programmatic analysis
- **CSV Files**: Spreadsheet-compatible metrics and flow data

## Permissions

Packet capture requires elevated privileges:

**macOS:**
```bash
sudo ./sniff.sh diagnose -i en0
```

**Linux (Option 1 - sudo):**
```bash
sudo ./sniff.sh diagnose -i eth0
```

**Linux (Option 2 - capabilities):**
```bash
# Grant capture capability to Python
sudo setcap cap_net_raw+ep $(which python3)

# Then run without sudo
./sniff.sh diagnose -i eth0
```

## Configuration

Create a `config.yaml` file to customize settings:

```yaml
capture:
  buffer_size: 10000
  promiscuous: true

alerts:
  packet_loss_warning: 1.0
  packet_loss_critical: 5.0
  latency_warning: 100
  latency_critical: 200
  jitter_warning: 30
  jitter_critical: 50

export:
  output_dir: "./reports"
  formats:
    - json
    - html
    - csv
```

Use with: `./sniff.sh diagnose -i en0 -c config.yaml`

## Metrics Collected

| Metric | Description |
|--------|-------------|
| Packets/sec | Packet rate per interface |
| Bandwidth | Throughput in Mbps |
| Packet Loss | Percentage based on retransmissions |
| Latency | RTT measured from TCP handshakes |
| Jitter | Variation in inter-arrival times |
| Retransmissions | TCP retransmit count |
| Out-of-Order | Packets received out of sequence |

## Troubleshooting

### No packets captured

1. Verify you're running with sudo
2. Check the interface name with `./sniff.sh list`
3. Ensure there's network traffic on the interface
4. Try generating traffic: `ping google.com`

### Permission denied

```bash
# macOS: Use sudo
sudo ./sniff.sh diagnose -i en0

# Linux: Add capability or use sudo
sudo setcap cap_net_raw+ep $(which python3)
```

### Module not found

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Or use the launcher script
./sniff.sh diagnose -i en0
```

## Project Structure

```
network-sniffer/
├── network_sniffer/
│   ├── capture/          # Packet capture engine
│   ├── processing/       # Packet processor and flow tracker
│   ├── analysis/         # Bottleneck and loss detection
│   ├── alerts/           # Alert management
│   ├── storage/          # Metrics storage
│   ├── export/           # Report generation
│   ├── ui/               # Dashboard widgets
│   ├── models/           # Data models
│   ├── cli.py            # Command-line interface
│   └── config.py         # Configuration management
├── setup.sh              # Automated setup script
├── sniff.sh              # Launcher script
├── pyproject.toml        # Package configuration
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## License

MIT License
