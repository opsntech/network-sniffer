"""Command-line interface for network sniffer."""

import argparse
import signal
import sys
import time
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box

from . import __version__
from .config import SnifferConfig
from .capture.engine import CaptureEngine
from .capture.interface_manager import InterfaceManager
from .processing.packet_processor import PacketProcessor
from .processing.flow_tracker import FlowTracker
from .analysis.comparator import InterfaceComparator
from .analysis.packet_loss_detector import PacketLossDetector
from .analysis.bottleneck_detector import BottleneckDetector
from .alerts.alert_manager import AlertManager, AlertSeverity
from .storage.metrics_store import MetricsStore


console = Console()


class SnifferApp:
    """Main application coordinator."""

    def __init__(
        self,
        interfaces: List[str],
        bpf_filter: str = "",
        config: Optional[SnifferConfig] = None,
    ):
        self.interfaces = interfaces
        self.bpf_filter = bpf_filter
        self.config = config or SnifferConfig()

        # Core components
        self.capture_engine: Optional[CaptureEngine] = None
        self.processor: Optional[PacketProcessor] = None
        self.flow_tracker: Optional[FlowTracker] = None
        self.metrics_store: Optional[MetricsStore] = None
        self.alert_manager: Optional[AlertManager] = None

        # Analysis components
        self.comparator = InterfaceComparator()
        self.loss_detector = PacketLossDetector()
        self.bottleneck_detector = BottleneckDetector()

        # State
        self._running = False
        self._start_time = 0.0

    def initialize(self) -> List[str]:
        """Initialize all components. Returns list of issues."""
        issues = []

        # Create metrics store
        self.metrics_store = MetricsStore()

        # Create flow tracker
        self.flow_tracker = FlowTracker()

        # Create capture engine
        try:
            self.capture_engine = CaptureEngine(
                interfaces=self.interfaces,
                bpf_filter=self.bpf_filter,
                queue_size=self.config.capture.buffer_size,
            )
            issues.extend(self.capture_engine.check_ready())
        except Exception as e:
            issues.append(f"Failed to create capture engine: {e}")
            return issues

        # Create processor
        self.processor = PacketProcessor(
            capture_engine=self.capture_engine,
            flow_tracker=self.flow_tracker,
        )

        # Create alert manager
        self.alert_manager = AlertManager()

        # Register packet callback to update metrics store
        def on_packet(packet):
            self.metrics_store.add_packet(packet)

        self.processor.add_packet_callback(on_packet)

        return issues

    def start(self) -> None:
        """Start capture and processing."""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self.processor.start()

    def stop(self) -> None:
        """Stop capture and processing."""
        self._running = False
        if self.processor:
            self.processor.stop(drain_queue=True)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def duration(self) -> float:
        if self._start_time == 0:
            return 0.0
        return time.time() - self._start_time

    def get_stats_table(self) -> Table:
        """Create Rich table with current statistics."""
        table = Table(
            title="Network Interface Statistics",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Interface", style="bold")
        table.add_column("Packets", justify="right")
        table.add_column("Bandwidth", justify="right")
        table.add_column("Loss %", justify="right")
        table.add_column("Latency", justify="right")
        table.add_column("Jitter", justify="right")
        table.add_column("Health", justify="right")

        all_metrics = self.processor.get_all_metrics()

        for iface, metrics in all_metrics.items():
            # Calculate health score
            result = self.bottleneck_detector.get_overall_health(iface, metrics)
            health = result.get("health_score", 100)

            # Determine health color
            if health >= 90:
                health_style = "green"
            elif health >= 70:
                health_style = "yellow"
            else:
                health_style = "red"

            # Determine loss color
            loss = metrics.packet_loss_rate
            if loss < 0.5:
                loss_style = "green"
            elif loss < 2:
                loss_style = "yellow"
            else:
                loss_style = "red"

            table.add_row(
                iface,
                f"{metrics.total_packets:,}",
                f"{metrics.bandwidth_mbps:.2f} Mbps",
                Text(f"{loss:.2f}%", style=loss_style),
                f"{metrics.avg_latency:.1f} ms",
                f"{metrics.avg_jitter:.1f} ms",
                Text(f"{health:.0f}/100", style=health_style),
            )

        return table

    def get_alerts_panel(self) -> Panel:
        """Create alerts panel."""
        alerts = self.alert_manager.get_active_alerts()

        if not alerts:
            content = Text("No active alerts", style="green")
        else:
            lines = []
            for alert in alerts[:5]:  # Show top 5
                if alert.severity == AlertSeverity.CRITICAL:
                    style = "bold red"
                    prefix = "[CRITICAL]"
                else:
                    style = "yellow"
                    prefix = "[WARNING] "

                lines.append(Text(f"{prefix} {alert.message}", style=style))

            content = Text("\n").join(lines)

        return Panel(content, title="Alerts", border_style="red" if alerts else "green")

    def get_comparison_panel(self) -> Optional[Panel]:
        """Create comparison panel if 2 interfaces."""
        if len(self.interfaces) != 2:
            return None

        all_metrics = self.processor.get_all_metrics()
        if len(all_metrics) < 2:
            return None

        iface_a, iface_b = self.interfaces[:2]
        metrics_a = all_metrics.get(iface_a)
        metrics_b = all_metrics.get(iface_b)

        if not metrics_a or not metrics_b:
            return None

        result = self.comparator.compare(iface_a, iface_b, metrics_a, metrics_b)

        # Build comparison text
        lines = [
            Text(f"  {iface_a:15} vs {iface_b:15}", style="bold"),
            Text(""),
        ]

        # Latency
        winner = result.winners.get("latency", "tie")
        a_style = "green" if winner == iface_a else ("white" if winner == "tie" else "red")
        b_style = "green" if winner == iface_b else ("white" if winner == "tie" else "red")
        lines.append(Text(f"Latency:    ", style="dim") + Text(f"{result.metrics_a['latency_ms']:6.1f}ms", style=a_style) + Text("  vs  ") + Text(f"{result.metrics_b['latency_ms']:6.1f}ms", style=b_style))

        # Loss
        winner = result.winners.get("packet_loss", "tie")
        a_style = "green" if winner == iface_a else ("white" if winner == "tie" else "red")
        b_style = "green" if winner == iface_b else ("white" if winner == "tie" else "red")
        lines.append(Text(f"Loss:       ", style="dim") + Text(f"{result.metrics_a['loss_percent']:6.2f}%", style=a_style) + Text("  vs  ") + Text(f"{result.metrics_b['loss_percent']:6.2f}%", style=b_style))

        # Jitter
        winner = result.winners.get("jitter", "tie")
        a_style = "green" if winner == iface_a else ("white" if winner == "tie" else "red")
        b_style = "green" if winner == iface_b else ("white" if winner == "tie" else "red")
        lines.append(Text(f"Jitter:     ", style="dim") + Text(f"{result.metrics_a['jitter_ms']:6.1f}ms", style=a_style) + Text("  vs  ") + Text(f"{result.metrics_b['jitter_ms']:6.1f}ms", style=b_style))

        lines.append(Text(""))
        lines.append(Text(f"Score: {result.score_a:.0f} vs {result.score_b:.0f}", style="bold"))

        if result.overall_winner != "tie":
            lines.append(Text(f"Winner: {result.overall_winner}", style="bold green"))
        else:
            lines.append(Text("Result: Tie", style="bold yellow"))

        content = Text("\n").join(lines)

        return Panel(content, title="Interface Comparison", border_style="cyan")

    def evaluate_alerts(self) -> None:
        """Evaluate alerts for all interfaces."""
        all_metrics = self.processor.get_all_metrics()
        for iface, metrics in all_metrics.items():
            self.alert_manager.evaluate(iface, metrics)

    def run_live_dashboard(self, duration: int = 0) -> None:
        """Run live dashboard with Rich."""
        end_time = time.time() + duration if duration > 0 else float('inf')

        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while self._running and time.time() < end_time:
                # Evaluate alerts
                self.evaluate_alerts()

                # Build layout
                layout = Layout()

                # Header
                header = Text(
                    f"Network Sniffer v{__version__} | "
                    f"Duration: {self.duration:.0f}s | "
                    f"Interfaces: {', '.join(self.interfaces)}",
                    style="bold white on blue",
                    justify="center",
                )

                layout.split(
                    Layout(header, name="header", size=1),
                    Layout(name="body"),
                    Layout(name="footer", size=3),
                )

                # Stats table
                stats_table = self.get_stats_table()

                # Build body
                body_parts = [Layout(stats_table, name="stats")]

                # Comparison panel (if 2 interfaces)
                comparison = self.get_comparison_panel()
                if comparison:
                    layout["body"].split_row(
                        Layout(stats_table, name="stats", ratio=2),
                        Layout(comparison, name="compare", ratio=1),
                    )
                else:
                    layout["body"].update(stats_table)

                # Alerts panel
                alerts_panel = self.get_alerts_panel()
                layout["footer"].update(alerts_panel)

                live.update(layout)
                time.sleep(1)


def list_interfaces() -> None:
    """List available network interfaces."""
    mgr = InterfaceManager()
    interfaces = mgr.get_all()

    table = Table(title="Available Network Interfaces", box=box.ROUNDED)
    table.add_column("Interface", style="bold cyan")
    table.add_column("IP Address")
    table.add_column("MAC Address")
    table.add_column("Status")

    for info in interfaces:
        status = "UP" if info.is_up else "DOWN"
        status_style = "green" if info.is_up else "red"

        table.add_row(
            info.name,
            info.ipv4_address or "N/A",
            info.mac_address or "N/A",
            Text(status, style=status_style),
        )

    console.print(table)


def run_capture(args) -> None:
    """Run packet capture command."""
    # Parse interfaces
    if args.interfaces:
        interfaces = [i.strip() for i in args.interfaces.split(",")]
    else:
        # Auto-detect active interfaces
        mgr = InterfaceManager()
        interfaces = [i.name for i in mgr.get_active()][:2]

        if not interfaces:
            console.print("[red]No active interfaces found. Specify with --interfaces[/red]")
            sys.exit(1)

        console.print(f"[yellow]Auto-detected interfaces: {', '.join(interfaces)}[/yellow]")

    # Load config
    config = SnifferConfig.load(args.config)

    # Create app
    app = SnifferApp(
        interfaces=interfaces,
        bpf_filter=args.filter or "",
        config=config,
    )

    # Initialize
    issues = app.initialize()
    if issues:
        console.print("[red]Cannot start capture:[/red]")
        for issue in issues:
            console.print(f"  - {issue}")
        sys.exit(1)

    # Signal handler for graceful shutdown
    def signal_handler(sig, frame):
        console.print("\n[yellow]Stopping capture...[/yellow]")
        app.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start
    console.print(f"[green]Starting capture on: {', '.join(interfaces)}[/green]")
    app.start()

    # Run dashboard or simple output
    if args.dashboard:
        app.run_live_dashboard(duration=args.duration)
    else:
        # Simple stats output
        end_time = time.time() + args.duration if args.duration > 0 else float('inf')

        try:
            while app.is_running and time.time() < end_time:
                time.sleep(2)
                stats = app.capture_engine.get_stats()
                console.print(
                    f"[cyan]Packets: {stats.packets_captured:,} | "
                    f"Dropped: {stats.packets_dropped:,} | "
                    f"Rate: {stats.packets_per_second:.1f} pps[/cyan]"
                )
        except KeyboardInterrupt:
            pass

    # Final stats
    app.stop()

    console.print("\n[bold]Final Statistics:[/bold]")
    console.print(app.get_stats_table())

    # Show comparison if 2 interfaces
    if len(interfaces) == 2:
        comparison = app.get_comparison_panel()
        if comparison:
            console.print(comparison)


def run_analyze(args) -> None:
    """Run analysis on captured data."""
    console.print("[yellow]Analysis requires active capture. Use 'capture --dashboard' for real-time analysis.[/yellow]")


def run_diagnose(args) -> None:
    """Run a quick diagnostic capture and generate full report."""
    from .export.report import ReportGenerator
    from .export.json_exporter import JSONExporter

    # Parse interfaces
    if args.interfaces:
        interfaces = [i.strip() for i in args.interfaces.split(",")]
    else:
        mgr = InterfaceManager()
        interfaces = [i.name for i in mgr.get_active()][:2]
        if not interfaces:
            console.print("[red]No active interfaces found. Specify with --interfaces[/red]")
            sys.exit(1)
        console.print(f"[yellow]Auto-detected interfaces: {', '.join(interfaces)}[/yellow]")

    duration = args.duration or 30
    console.print(f"[cyan]Running diagnostic capture for {duration} seconds on: {', '.join(interfaces)}[/cyan]")
    console.print()

    # Load config and create app
    config = SnifferConfig.load(args.config)
    app = SnifferApp(interfaces=interfaces, bpf_filter=args.filter or "", config=config)

    issues = app.initialize()
    if issues:
        console.print("[red]Cannot start capture:[/red]")
        for issue in issues:
            console.print(f"  - {issue}")
        sys.exit(1)

    # Signal handler
    def signal_handler(sig, frame):
        console.print("\n[yellow]Stopping capture...[/yellow]")
        app.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run capture with live stats
    from rich.live import Live
    from rich.table import Table as RichTable

    app.start()

    def make_status_table():
        """Create live status table."""
        tbl = RichTable(title="Capturing...", box=box.SIMPLE)
        tbl.add_column("Interface")
        tbl.add_column("Packets", justify="right")
        tbl.add_column("Bytes", justify="right")
        tbl.add_column("pps", justify="right")

        stats = app.capture_engine.get_stats()
        all_metrics = app.processor.get_all_metrics()

        for iface in interfaces:
            m = all_metrics.get(iface)
            if m:
                tbl.add_row(
                    iface,
                    f"{m.total_packets:,}",
                    f"{m.total_bytes:,}",
                    f"{m.packets_per_second:.1f}"
                )
            else:
                iface_count = stats.interfaces.get(iface, 0)
                tbl.add_row(iface, f"{iface_count:,}", "-", "-")

        elapsed = time.time() - app._start_time
        tbl.caption = f"Elapsed: {elapsed:.0f}s / {duration}s | Total: {stats.packets_captured:,} packets"
        return tbl

    start = time.time()
    try:
        with Live(make_status_table(), console=console, refresh_per_second=2) as live:
            while app.is_running and (time.time() - start) < duration:
                time.sleep(0.5)
                live.update(make_status_table())
                app.evaluate_alerts()
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture interrupted.[/yellow]")

    # Stop capture and drain queue (processor will process remaining packets)
    app.stop()

    console.print()
    console.print("[bold green]Capture complete. Generating reports...[/bold green]")
    console.print()

    # Get all data
    all_metrics = app.processor.get_all_metrics()
    all_flows = sorted(app.flow_tracker.get_all_flows(), key=lambda f: f.total_bytes, reverse=True)[:50]
    all_alerts = app.alert_manager.get_alert_history(limit=100)

    # Debug: Show detailed pipeline information
    capture_stats = app.capture_engine.get_stats()
    processor_stats = app.processor.get_stats()
    processor_debug = app.processor.get_debug_info()

    console.print("[dim]─── Debug Information ───[/dim]")
    console.print(f"[dim]Capture Engine:[/dim]")
    console.print(f"[dim]  Packets captured: {capture_stats.packets_captured:,}[/dim]")
    console.print(f"[dim]  Packets dropped (queue full): {capture_stats.packets_dropped:,}[/dim]")
    console.print(f"[dim]  Bytes captured: {capture_stats.bytes_captured:,}[/dim]")
    console.print(f"[dim]  Duration: {capture_stats.duration:.1f}s[/dim]")
    console.print(f"[dim]  Per-interface: {capture_stats.interfaces}[/dim]")

    console.print(f"[dim]Packet Processor:[/dim]")
    console.print(f"[dim]  Packets processed: {processor_stats.packets_processed:,}[/dim]")
    console.print(f"[dim]  Processing errors: {processor_stats.processing_errors:,}[/dim]")
    console.print(f"[dim]  Interface packet counts: {processor_debug['interface_packet_counts']}[/dim]")

    console.print(f"[dim]Flow Tracker:[/dim]")
    console.print(f"[dim]  Total flows: {len(all_flows)}[/dim]")

    console.print(f"[dim]Interface Metrics:[/dim]")
    for iface, m in all_metrics.items():
        console.print(f"[dim]  {iface}: {m.total_packets:,} pkts, {m.total_bytes:,} bytes, {m.bandwidth_mbps:.2f} Mbps, {m.retransmissions} retrans[/dim]")

    # Check for issues
    if capture_stats.packets_captured == 0:
        console.print("[yellow]⚠ No packets captured! Check:[/yellow]")
        console.print("[yellow]  - Are you running with sudo?[/yellow]")
        console.print("[yellow]  - Is the interface correct?[/yellow]")
        console.print("[yellow]  - Is there network traffic?[/yellow]")
    elif processor_stats.packets_processed == 0:
        console.print("[yellow]⚠ Packets captured but not processed![/yellow]")
        console.print("[yellow]  This may indicate a processing bug.[/yellow]")
    elif all(m.total_packets == 0 for m in all_metrics.values()):
        console.print("[yellow]⚠ Packets processed but metrics empty![/yellow]")
        console.print("[yellow]  Interface mismatch possible.[/yellow]")

    console.print("[dim]────────────────────────[/dim]")
    console.print()

    # Generate comparison if 2 interfaces
    comparison = None
    if len(interfaces) == 2:
        iface_a, iface_b = interfaces[:2]
        metrics_a = all_metrics.get(iface_a)
        metrics_b = all_metrics.get(iface_b)
        if metrics_a and metrics_b:
            comparison = app.comparator.compare(iface_a, iface_b, metrics_a, metrics_b)

    # Display results
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold cyan]           NETWORK DIAGNOSTIC REPORT[/bold cyan]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print()

    # Stats table
    console.print(app.get_stats_table())
    console.print()

    # Bottleneck analysis
    console.print("[bold yellow]BOTTLENECK ANALYSIS[/bold yellow]")
    console.print()

    for iface, metrics in all_metrics.items():
        analysis = app.bottleneck_detector.get_overall_health(iface, metrics)
        status = analysis['status']
        health = analysis['health_score']

        if status == "healthy":
            status_style = "green"
        elif status in ("minor_issues", "warning"):
            status_style = "yellow"
        else:
            status_style = "red"

        health_style = "green" if health >= 90 else ("yellow" if health >= 70 else "red")

        console.print(f"[bold]{iface}[/bold]")
        console.print(f"  Status: [{status_style}]{status.upper()}[/{status_style}]")
        console.print(f"  Health Score: [{health_style}]{health}/100[/{health_style}]")

        if analysis['bottlenecks']:
            console.print("  [dim]Issues detected:[/dim]")
            for b in analysis['bottlenecks'][:3]:
                console.print(f"    - [red]{b['type']}[/red]: {b['description']}")
            if analysis.get('top_recommendation'):
                console.print(f"  [cyan]Recommendation:[/cyan] {analysis['top_recommendation']}")
        else:
            console.print("  [green]No bottlenecks detected[/green]")
        console.print()

    # Comparison
    if comparison:
        console.print("[bold cyan]INTERFACE COMPARISON[/bold cyan]")
        console.print()
        console.print(f"  {comparison.interface_a}: Score [bold]{comparison.score_a:.0f}/100[/bold]")
        console.print(f"  {comparison.interface_b}: Score [bold]{comparison.score_b:.0f}/100[/bold]")

        if comparison.overall_winner != "tie":
            console.print(f"  [bold green]Winner: {comparison.overall_winner}[/bold green] (Confidence: {comparison.confidence*100:.0f}%)")
        else:
            console.print("  [yellow]Result: Tie[/yellow]")

        console.print()
        console.print(f"  [cyan]Recommendation:[/cyan] {comparison.recommendation}")
        console.print()

    # Alerts
    active_alerts = app.alert_manager.get_active_alerts()
    if active_alerts:
        console.print("[bold red]ALERTS[/bold red]")
        console.print()
        for alert in active_alerts[:5]:
            severity_style = "red" if alert.severity.value == "critical" else "yellow"
            console.print(f"  [{severity_style}][{alert.severity.value.upper()}][/{severity_style}] {alert.message}")
        console.print()

    # Fixes and Recommendations
    console.print("[bold green]" + "=" * 60 + "[/bold green]")
    console.print("[bold green]        RECOMMENDED FIXES & ACTIONS[/bold green]")
    console.print("[bold green]" + "=" * 60 + "[/bold green]")
    console.print()

    fix_count = 1
    for iface, metrics in all_metrics.items():
        bottlenecks = app.bottleneck_detector.analyze(iface, metrics)

        if bottlenecks:
            console.print(f"[bold yellow]Issues on {iface}:[/bold yellow]")
            console.print()

            for bottleneck in bottlenecks:
                severity_color = "red" if bottleneck.severity >= 0.7 else "yellow"
                console.print(f"  [{severity_color}]{fix_count}. {bottleneck.description}[/{severity_color}]")
                console.print(f"     Severity: [{severity_color}]{bottleneck.severity_label.upper()}[/{severity_color}]")
                console.print(f"     Location: {bottleneck.location}")
                console.print()
                console.print("     [cyan]Evidence:[/cyan]")
                for evidence in bottleneck.evidence[:3]:
                    console.print(f"       - {evidence}")
                console.print()
                console.print("     [green]Recommended Fixes:[/green]")
                for rec in bottleneck.recommendations:
                    console.print(f"       [green]>[/green] {rec}")
                console.print()
                fix_count += 1

    # General recommendations based on metrics
    console.print("[bold cyan]GENERAL RECOMMENDATIONS[/bold cyan]")
    console.print()

    recommendations_given = False

    for iface, metrics in all_metrics.items():
        recs = []

        # Packet loss recommendations
        if metrics.packet_loss_rate > 2:
            recs.append(("HIGH", f"Packet loss on {iface} is {metrics.packet_loss_rate:.2f}%", [
                "Check physical cable connections",
                "Run: netstat -s | grep -i retransmit",
                "Check switch/router port errors",
                "Consider using wired connection instead of WiFi",
            ]))
        elif metrics.packet_loss_rate > 0.5:
            recs.append(("MEDIUM", f"Moderate packet loss on {iface}: {metrics.packet_loss_rate:.2f}%", [
                "Monitor for patterns during peak usage",
                "Check for network congestion",
            ]))

        # Latency recommendations
        if metrics.avg_latency > 150:
            recs.append(("HIGH", f"High latency on {iface}: {metrics.avg_latency:.1f}ms", [
                "Run: traceroute to identify slow hops",
                "Check if traffic is being routed through VPN",
                "Contact ISP if latency is on their network",
            ]))
        elif metrics.avg_latency > 50:
            recs.append(("MEDIUM", f"Elevated latency on {iface}: {metrics.avg_latency:.1f}ms", [
                "Acceptable for browsing, may affect VoIP/gaming",
                "Consider QoS settings on router",
            ]))

        # Jitter recommendations
        if metrics.avg_jitter > 30:
            recs.append(("HIGH", f"High jitter on {iface}: {metrics.avg_jitter:.1f}ms - BAD for VoIP/Video", [
                "Enable QoS on router for real-time traffic",
                "Check for bandwidth-heavy background processes",
                "WiFi interference - try changing channel",
            ]))

        # Buffer drops
        if metrics.rx_dropped > 0 or metrics.tx_dropped > 0:
            recs.append(("MEDIUM", f"Buffer drops detected on {iface}: RX={metrics.rx_dropped}, TX={metrics.tx_dropped}", [
                "Increase ring buffer: ethtool -G <iface> rx 4096 tx 4096",
                "Check for driver updates",
                "Consider NIC upgrade for high-traffic scenarios",
            ]))

        # Retransmissions
        retrans_rate = (metrics.retransmissions / max(metrics.total_packets, 1)) * 100
        if retrans_rate > 3:
            recs.append(("HIGH", f"High TCP retransmissions on {iface}: {retrans_rate:.2f}%", [
                "Indicates packet loss or congestion",
                "Check MTU settings - try: ping -M do -s 1472 <gateway>",
                "Disable TCP offloading if issues persist",
            ]))

        for priority, issue, fixes in recs:
            recommendations_given = True
            priority_color = "red" if priority == "HIGH" else "yellow"
            console.print(f"  [{priority_color}][{priority}][/{priority_color}] {issue}")
            for fix in fixes:
                console.print(f"       [green]>[/green] {fix}")
            console.print()

    if not recommendations_given:
        console.print("  [green]All interfaces are performing well. No issues detected.[/green]")
        console.print()

    # Vendor escalation info
    if any(m.packet_loss_rate > 1 or m.avg_latency > 100 for m in all_metrics.values()):
        console.print("[bold magenta]VENDOR ESCALATION INFO[/bold magenta]")
        console.print()
        console.print("  Use the generated reports as evidence when contacting your ISP/vendor:")
        console.print("  - HTML report: Visual summary with graphs")
        console.print("  - JSON report: Raw data with timestamps")
        console.print()
        console.print("  [dim]Key metrics to mention:[/dim]")
        for iface, metrics in all_metrics.items():
            console.print(f"    {iface}: Loss={metrics.packet_loss_rate:.2f}%, Latency={metrics.avg_latency:.1f}ms, Retransmits={metrics.retransmissions}")
        console.print()

    # Export reports
    output_dir = args.output or "./reports"
    report_gen = ReportGenerator(output_dir=output_dir)

    results = report_gen.generate_full_report(
        metrics=all_metrics,
        flows=all_flows,
        alerts=all_alerts,
        comparison=comparison,
        formats=["json", "html"],
    )

    console.print("[bold green]REPORTS GENERATED[/bold green]")
    console.print()
    for fmt, path in results.items():
        console.print(f"  {fmt}: [link=file://{path}]{path}[/link]")

    console.print()
    console.print("[dim]Open HTML report in browser:[/dim]")
    console.print(f"  open '{results.get('html', '')}'")
    console.print()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="network-sniffer",
        description="Network diagnostic tool for identifying packet loss, bottlenecks, and performance issues.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # List interfaces command
    list_parser = subparsers.add_parser("list", help="List available network interfaces")

    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Capture and analyze network traffic")
    capture_parser.add_argument(
        "-i", "--interfaces",
        help="Comma-separated list of interfaces to capture (e.g., eth0,eth1)",
    )
    capture_parser.add_argument(
        "-f", "--filter",
        help="BPF filter expression (e.g., 'tcp port 443')",
    )
    capture_parser.add_argument(
        "-d", "--duration",
        type=int,
        default=0,
        help="Capture duration in seconds (0 = continuous)",
    )
    capture_parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Show live dashboard",
    )
    capture_parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
    )

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze network performance")
    analyze_parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("IFACE1", "IFACE2"),
        help="Compare two interfaces",
    )

    # Diagnose command - full diagnostic with reports
    diagnose_parser = subparsers.add_parser("diagnose", help="Run full diagnostic and generate reports")
    diagnose_parser.add_argument(
        "-i", "--interfaces",
        help="Comma-separated list of interfaces (e.g., en0,en1)",
    )
    diagnose_parser.add_argument(
        "-d", "--duration",
        type=int,
        default=30,
        help="Capture duration in seconds (default: 30)",
    )
    diagnose_parser.add_argument(
        "-f", "--filter",
        help="BPF filter expression",
    )
    diagnose_parser.add_argument(
        "-o", "--output",
        default="./reports",
        help="Output directory for reports (default: ./reports)",
    )
    diagnose_parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
    )

    args = parser.parse_args()

    if args.command == "list":
        list_interfaces()
    elif args.command == "capture":
        run_capture(args)
    elif args.command == "analyze":
        run_analyze(args)
    elif args.command == "diagnose":
        run_diagnose(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
