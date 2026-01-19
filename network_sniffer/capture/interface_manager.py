"""Network interface management."""

import socket
from dataclasses import dataclass
from typing import List, Optional, Dict
import psutil

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False


@dataclass
class InterfaceInfo:
    """Information about a network interface."""
    name: str
    description: str
    mac_address: Optional[str]
    ipv4_address: Optional[str]
    ipv4_netmask: Optional[str]
    ipv6_address: Optional[str]
    is_up: bool
    is_loopback: bool
    speed_mbps: Optional[int]
    mtu: Optional[int]

    def __str__(self) -> str:
        status = "UP" if self.is_up else "DOWN"
        addr = self.ipv4_address or "no address"
        return f"{self.name} ({addr}) [{status}]"


class InterfaceManager:
    """Manages network interface enumeration and information."""

    def __init__(self):
        self._interfaces: Dict[str, InterfaceInfo] = {}
        self.refresh()

    def refresh(self) -> None:
        """Refresh the list of network interfaces."""
        self._interfaces.clear()

        # Get interface stats from psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for name, stat in stats.items():
            # Get addresses
            ipv4_addr = None
            ipv4_mask = None
            ipv6_addr = None
            mac_addr = None

            if name in addrs:
                for addr in addrs[name]:
                    if addr.family == socket.AF_INET:
                        ipv4_addr = addr.address
                        ipv4_mask = addr.netmask
                    elif addr.family == socket.AF_INET6:
                        if not ipv6_addr:  # Take first IPv6
                            ipv6_addr = addr.address
                    elif addr.family == psutil.AF_LINK:
                        mac_addr = addr.address

            # Determine if loopback
            is_loopback = name.lower().startswith("lo") or ipv4_addr == "127.0.0.1"

            # Get MTU using netifaces if available
            mtu = None
            if HAS_NETIFACES and name in netifaces.interfaces():
                try:
                    # netifaces doesn't directly provide MTU, but we can try
                    pass
                except Exception:
                    pass

            info = InterfaceInfo(
                name=name,
                description=name,
                mac_address=mac_addr,
                ipv4_address=ipv4_addr,
                ipv4_netmask=ipv4_mask,
                ipv6_address=ipv6_addr,
                is_up=stat.isup,
                is_loopback=is_loopback,
                speed_mbps=stat.speed if stat.speed > 0 else None,
                mtu=stat.mtu if hasattr(stat, 'mtu') else None,
            )
            self._interfaces[name] = info

    def get_all(self) -> List[InterfaceInfo]:
        """Get all network interfaces."""
        return list(self._interfaces.values())

    def get_active(self) -> List[InterfaceInfo]:
        """Get only active (UP) interfaces with IP addresses."""
        return [
            iface for iface in self._interfaces.values()
            if iface.is_up and iface.ipv4_address and not iface.is_loopback
        ]

    def get_by_name(self, name: str) -> Optional[InterfaceInfo]:
        """Get interface by name."""
        return self._interfaces.get(name)

    def exists(self, name: str) -> bool:
        """Check if interface exists."""
        return name in self._interfaces

    def validate_interfaces(self, names: List[str]) -> List[str]:
        """
        Validate interface names and return list of invalid ones.
        """
        invalid = []
        for name in names:
            if not self.exists(name):
                invalid.append(name)
        return invalid

    def get_interface_names(self) -> List[str]:
        """Get list of all interface names."""
        return list(self._interfaces.keys())

    def print_interfaces(self) -> str:
        """Get formatted string of all interfaces."""
        lines = ["Available Network Interfaces:", "=" * 50]

        for iface in sorted(self._interfaces.values(), key=lambda x: x.name):
            status = "UP" if iface.is_up else "DOWN"
            addr = iface.ipv4_address or "no address"
            mac = iface.mac_address or "no MAC"
            speed = f"{iface.speed_mbps} Mbps" if iface.speed_mbps else "unknown speed"

            lines.append(f"\n{iface.name}:")
            lines.append(f"  Status:  {status}")
            lines.append(f"  IPv4:    {addr}")
            lines.append(f"  MAC:     {mac}")
            lines.append(f"  Speed:   {speed}")
            if iface.is_loopback:
                lines.append(f"  Type:    Loopback")

        return "\n".join(lines)
