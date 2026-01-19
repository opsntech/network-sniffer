"""Platform-specific packet capture setup."""

import platform
import os
import subprocess
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class PlatformConfig:
    """Platform-specific capture configuration."""
    socket_type: str
    use_libpcap: bool
    promiscuous: bool
    buffer_size: int
    extra_config: Dict[str, any] = None

    def __post_init__(self):
        if self.extra_config is None:
            self.extra_config = {}


class PlatformAdapter(ABC):
    """Abstract base for platform-specific packet capture setup."""

    @abstractmethod
    def check_dependencies(self) -> List[str]:
        """Return list of missing dependencies."""
        pass

    @abstractmethod
    def check_privileges(self) -> bool:
        """Check if running with sufficient privileges for packet capture."""
        pass

    @abstractmethod
    def get_capture_config(self) -> PlatformConfig:
        """Return platform-specific capture configuration."""
        pass

    @abstractmethod
    def get_interface_stats(self, interface: str) -> Dict[str, int]:
        """Get interface-level statistics (drops, errors)."""
        pass

    def get_platform_info(self) -> Dict[str, str]:
        """Get platform information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
        }


class LinuxAdapter(PlatformAdapter):
    """Linux-specific adapter."""

    def check_dependencies(self) -> List[str]:
        missing = []
        # Check for libpcap
        if not self._check_libpcap():
            missing.append("libpcap-dev (apt install libpcap-dev) or libpcap-devel (yum install libpcap-devel)")
        return missing

    def _check_libpcap(self) -> bool:
        """Check if libpcap is installed."""
        # Check for libpcap.so
        lib_paths = [
            "/usr/lib/x86_64-linux-gnu/libpcap.so",
            "/usr/lib64/libpcap.so",
            "/usr/lib/libpcap.so",
        ]
        for path in lib_paths:
            if os.path.exists(path):
                return True
        # Try ldconfig
        try:
            result = subprocess.run(
                ["ldconfig", "-p"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "libpcap" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return False

    def check_privileges(self) -> bool:
        """Check for root or CAP_NET_RAW capability."""
        if os.geteuid() == 0:
            return True
        return self._has_cap_net_raw()

    def _has_cap_net_raw(self) -> bool:
        """Check for CAP_NET_RAW capability on Python executable."""
        try:
            import sys
            result = subprocess.run(
                ["getcap", sys.executable],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "cap_net_raw" in result.stdout.lower()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def get_capture_config(self) -> PlatformConfig:
        return PlatformConfig(
            socket_type="native",
            use_libpcap=True,
            promiscuous=True,
            buffer_size=65536,
        )

    def get_interface_stats(self, interface: str) -> Dict[str, int]:
        """Get drop stats from Linux /sys filesystem."""
        stats = {}
        base_path = f"/sys/class/net/{interface}/statistics"

        metrics = [
            "rx_dropped", "tx_dropped",
            "rx_errors", "tx_errors",
            "rx_fifo_errors", "tx_fifo_errors",
            "rx_missed_errors", "collisions",
            "rx_packets", "tx_packets",
            "rx_bytes", "tx_bytes",
        ]

        for metric in metrics:
            try:
                with open(f"{base_path}/{metric}") as f:
                    stats[metric] = int(f.read().strip())
            except (IOError, ValueError):
                stats[metric] = 0

        return stats


class MacOSAdapter(PlatformAdapter):
    """macOS-specific adapter."""

    def check_dependencies(self) -> List[str]:
        missing = []
        # macOS has libpcap by default, but check anyway
        if not self._check_libpcap():
            missing.append("libpcap (should be pre-installed on macOS)")
        return missing

    def _check_libpcap(self) -> bool:
        """Check if libpcap is available."""
        # Check common locations on macOS (Intel and Apple Silicon)
        lib_paths = [
            "/usr/lib/libpcap.dylib",
            "/usr/local/lib/libpcap.dylib",
            "/opt/homebrew/lib/libpcap.dylib",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libpcap.tbd",
        ]
        for path in lib_paths:
            if os.path.exists(path):
                return True

        # On modern macOS, libpcap is part of the system and Scapy will find it
        # Try to import scapy's pcap functionality as a final check
        try:
            from scapy.arch.bpf.supersocket import L2bpfSocket
            return True
        except ImportError:
            pass

        # If we got here on macOS, assume it's available (it's always pre-installed)
        return True

    def check_privileges(self) -> bool:
        """Check for root or BPF access."""
        if os.geteuid() == 0:
            return True
        return self._check_bpf_access()

    def _check_bpf_access(self) -> bool:
        """Check if user has access to /dev/bpf*"""
        # Check if any bpf device is readable
        for i in range(10):
            bpf_path = f"/dev/bpf{i}"
            if os.path.exists(bpf_path) and os.access(bpf_path, os.R_OK):
                return True
        return False

    def get_capture_config(self) -> PlatformConfig:
        return PlatformConfig(
            socket_type="libpcap",
            use_libpcap=True,
            promiscuous=True,
            buffer_size=65536,
            extra_config={
                "interface_prefix": "en",  # en0, en1, etc.
            },
        )

    def get_interface_stats(self, interface: str) -> Dict[str, int]:
        """Get drop stats from macOS netstat."""
        stats = {}
        try:
            result = subprocess.run(
                ["netstat", "-I", interface, "-b"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                headers = lines[0].lower().split()
                values = lines[1].split()
                for h, v in zip(headers, values):
                    try:
                        stats[h] = int(v)
                    except ValueError:
                        pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return stats


class WindowsAdapter(PlatformAdapter):
    """Windows-specific adapter."""

    def check_dependencies(self) -> List[str]:
        missing = []
        if not self._check_npcap():
            missing.append("Npcap (download from https://npcap.com/)")
        return missing

    def _check_npcap(self) -> bool:
        """Check if Npcap is installed."""
        npcap_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Npcap",
        ]
        for path in npcap_paths:
            if os.path.exists(path):
                return True
        return False

    def check_privileges(self) -> bool:
        """Check for administrator rights."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False

    def get_capture_config(self) -> PlatformConfig:
        return PlatformConfig(
            socket_type="npcap",
            use_libpcap=True,
            promiscuous=True,
            buffer_size=65536,
            extra_config={
                "npf_driver": True,
                "wlan_monitor_mode": False,  # Generally not supported on Windows
            },
        )

    def get_interface_stats(self, interface: str) -> Dict[str, int]:
        """Get stats from Windows netsh or PowerShell."""
        stats = {}
        try:
            # Try PowerShell Get-NetAdapterStatistics
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-NetAdapterStatistics -Name '{interface}' | Format-List"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    try:
                        stats[key] = int(value.strip())
                    except ValueError:
                        pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return stats


def get_platform_adapter() -> PlatformAdapter:
    """Factory function to get the appropriate platform adapter."""
    system = platform.system().lower()
    if system == "linux":
        return LinuxAdapter()
    elif system == "darwin":
        return MacOSAdapter()
    elif system == "windows":
        return WindowsAdapter()
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
