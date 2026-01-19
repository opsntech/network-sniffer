"""Packet data structures."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Protocol(Enum):
    """Network protocol types."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    ARP = "ARP"
    OTHER = "OTHER"


@dataclass
class TCPFlags:
    """TCP flag decomposition."""
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False
    ece: bool = False
    cwr: bool = False

    @classmethod
    def from_int(cls, flags: int) -> "TCPFlags":
        """Create TCPFlags from integer flag value."""
        return cls(
            fin=bool(flags & 0x01),
            syn=bool(flags & 0x02),
            rst=bool(flags & 0x04),
            psh=bool(flags & 0x08),
            ack=bool(flags & 0x10),
            urg=bool(flags & 0x20),
            ece=bool(flags & 0x40),
            cwr=bool(flags & 0x80),
        )

    def to_string(self) -> str:
        """Return string representation of flags."""
        flags = []
        if self.syn:
            flags.append("SYN")
        if self.ack:
            flags.append("ACK")
        if self.fin:
            flags.append("FIN")
        if self.rst:
            flags.append("RST")
        if self.psh:
            flags.append("PSH")
        if self.urg:
            flags.append("URG")
        if self.ece:
            flags.append("ECE")
        if self.cwr:
            flags.append("CWR")
        return ",".join(flags) if flags else "NONE"


@dataclass
class PacketInfo:
    """
    Lightweight packet information for high-speed processing.
    """
    timestamp: float
    interface: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Protocol
    length: int
    ttl: int
    # TCP-specific fields
    tcp_flags: Optional[int] = None
    seq_num: Optional[int] = None
    ack_num: Optional[int] = None
    window_size: Optional[int] = None
    # Computed fields
    is_retransmit: bool = False
    rtt: Optional[float] = None

    def get_tcp_flags(self) -> Optional[TCPFlags]:
        """Get parsed TCP flags."""
        if self.tcp_flags is not None:
            return TCPFlags.from_int(self.tcp_flags)
        return None

    def is_tcp(self) -> bool:
        """Check if packet is TCP."""
        return self.protocol in (Protocol.TCP, Protocol.HTTP, Protocol.HTTPS)

    def is_udp(self) -> bool:
        """Check if packet is UDP."""
        return self.protocol in (Protocol.UDP, Protocol.DNS)

    def is_icmp(self) -> bool:
        """Check if packet is ICMP."""
        return self.protocol == Protocol.ICMP
