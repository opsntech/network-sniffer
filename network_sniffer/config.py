"""Configuration management for network sniffer."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path
import os

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class CaptureConfig:
    """Capture configuration."""
    interfaces: List[str] = field(default_factory=list)
    bpf_filter: str = ""
    duration: int = 0  # 0 = continuous
    buffer_size: int = 10000
    promiscuous: bool = True


@dataclass
class AlertConfig:
    """Alert configuration."""
    profile: str = "general"  # voip, video, gaming, general
    enabled: bool = True
    thresholds: Dict[str, Dict[str, float]] = field(default_factory=dict)


@dataclass
class ExportConfig:
    """Export configuration."""
    auto_export: bool = False
    interval: int = 300  # seconds
    format: str = "json"  # json, csv, html
    output_dir: str = "./reports"


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    refresh_rate: float = 1.0  # seconds
    show_charts: bool = True
    chart_history: int = 60  # data points


@dataclass
class SnifferConfig:
    """Main configuration container."""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SnifferConfig":
        """Create config from dictionary."""
        config = cls()

        if "capture" in data:
            cap = data["capture"]
            config.capture = CaptureConfig(
                interfaces=cap.get("interfaces", []),
                bpf_filter=cap.get("bpf_filter", ""),
                duration=cap.get("duration", 0),
                buffer_size=cap.get("buffer_size", 10000),
                promiscuous=cap.get("promiscuous", True),
            )

        if "alerts" in data:
            alert = data["alerts"]
            config.alerts = AlertConfig(
                profile=alert.get("profile", "general"),
                enabled=alert.get("enabled", True),
                thresholds=alert.get("thresholds", {}),
            )

        if "export" in data:
            exp = data["export"]
            config.export = ExportConfig(
                auto_export=exp.get("auto_export", False),
                interval=exp.get("interval", 300),
                format=exp.get("format", "json"),
                output_dir=exp.get("output_dir", "./reports"),
            )

        if "dashboard" in data:
            dash = data["dashboard"]
            config.dashboard = DashboardConfig(
                refresh_rate=dash.get("refresh_rate", 1.0),
                show_charts=dash.get("show_charts", True),
                chart_history=dash.get("chart_history", 60),
            )

        return config

    @classmethod
    def from_yaml(cls, path: str) -> "SnifferConfig":
        """Load config from YAML file."""
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for YAML config. Install with: pip install pyyaml")

        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data or {})

    @classmethod
    def load(cls, path: Optional[str] = None) -> "SnifferConfig":
        """Load config from file or use defaults."""
        # Search paths
        search_paths = [
            path,
            "config.yaml",
            "config.yml",
            os.path.expanduser("~/.config/network-sniffer/config.yaml"),
            "/etc/network-sniffer/config.yaml",
        ]

        for config_path in search_paths:
            if config_path and os.path.exists(config_path):
                return cls.from_yaml(config_path)

        # Return defaults
        return cls()

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "capture": {
                "interfaces": self.capture.interfaces,
                "bpf_filter": self.capture.bpf_filter,
                "duration": self.capture.duration,
                "buffer_size": self.capture.buffer_size,
                "promiscuous": self.capture.promiscuous,
            },
            "alerts": {
                "profile": self.alerts.profile,
                "enabled": self.alerts.enabled,
                "thresholds": self.alerts.thresholds,
            },
            "export": {
                "auto_export": self.export.auto_export,
                "interval": self.export.interval,
                "format": self.export.format,
                "output_dir": self.export.output_dir,
            },
            "dashboard": {
                "refresh_rate": self.dashboard.refresh_rate,
                "show_charts": self.dashboard.show_charts,
                "chart_history": self.dashboard.chart_history,
            },
        }

    def save_yaml(self, path: str) -> None:
        """Save config to YAML file."""
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for YAML config")

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
