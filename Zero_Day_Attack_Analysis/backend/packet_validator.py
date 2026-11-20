"""Validate live packet records before they reach the dashboard."""

import ipaddress
import re
import threading
import time
from typing import Optional


_CONFIG = {
    "min_frame_size": 14,
    "max_frame_size": 65535,
    "max_ttl": 255,
    "max_port": 65535,
    "timestamp_max_future_sec": 5.0,
    "timestamp_max_age_sec": 300.0,
}
_MAC_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
_VALID_PROTOCOLS = frozenset({
    "TCP", "UDP", "ICMP", "DNS", "ARP", "HTTP", "UNKNOWN",
    "IGMP", "GRE", "ESP", "SCTP", "ICMPv6",
})
_VALID_FLAG_CHARS = frozenset("SAFPRUCE")


class PacketValidator:
    def __init__(self, config: dict | None = None):
        self._cfg = {**_CONFIG, **(config or {})}
        self._lock = threading.Lock()
        self._stats = {
            "total_received": 0,
            "total_accepted": 0,
            "total_rejected": 0,
            "reject_structural": 0,
            "reject_ip": 0,
            "reject_mac": 0,
            "reject_protocol": 0,
            "reject_size": 0,
            "reject_ttl": 0,
            "reject_port": 0,
            "reject_flags": 0,
            "reject_timestamp": 0,
        }

    def validate(self, pkt_info: dict) -> tuple[bool, str]:
        with self._lock:
            self._stats["total_received"] += 1

        checks = (
            self._check_structural,
            self._check_ip_addresses,
            self._check_mac_addresses,
            self._check_protocol,
            self._check_frame_size,
            self._check_ttl,
            self._check_ports,
            self._check_tcp_flags,
            self._check_timestamp,
        )
        for check in checks:
            valid, reason = check(pkt_info)
            if not valid:
                with self._lock:
                    self._stats["total_rejected"] += 1
                return False, reason

        with self._lock:
            self._stats["total_accepted"] += 1
        return True, ""

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0

    def _check_structural(self, pkt: dict) -> tuple[bool, str]:
        required_fields = {
            "timestamp": (int, float),
            "size": (int,),
            "proto": (str,),
            "is_real": (bool,),
        }
        for field, types in required_fields.items():
            value = pkt.get(field)
            if value is None:
                self._inc("reject_structural")
                return False, f"Missing required field: {field}"
            if not isinstance(value, types):
                self._inc("reject_structural")
                return False, f"Invalid type for {field}: expected {types}, got {type(value)}"
        if not pkt["is_real"]:
            self._inc("reject_structural")
            return False, "Packet not flagged as real capture"
        return True, ""

    def _check_ip_addresses(self, pkt: dict) -> tuple[bool, str]:
        src_ip = pkt.get("src_ip", "")
        dst_ip = pkt.get("dst_ip", "")
        if pkt.get("proto") in ("ARP", "UNKNOWN"):
            return True, ""
        if not src_ip and not dst_ip:
            self._inc("reject_ip")
            return False, "No IP addresses present in IP-layer packet"
        for label, address in (("src_ip", src_ip), ("dst_ip", dst_ip)):
            if address:
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    self._inc("reject_ip")
                    return False, f"Malformed {label}: {address}"
        if src_ip == dst_ip == "0.0.0.0":
            self._inc("reject_ip")
            return False, "Invalid flow: 0.0.0.0 → 0.0.0.0"
        return True, ""
    def _check_mac_addresses(self, pkt: dict) -> tuple[bool, str]:
        for label in ("src_mac", "dst_mac"):
            address = pkt.get(label, "")
            if address and not _MAC_PATTERN.match(address):
                self._inc("reject_mac")
                return False, f"Malformed {label}: {address}"
        return True, ""
    def _check_protocol(self, pkt: dict) -> tuple[bool, str]:
        protocol = pkt.get("proto", "")
        if protocol and protocol not in _VALID_PROTOCOLS:
            self._inc("reject_protocol")
            return False, f"Unrecognized protocol: {protocol}"
        return True, ""
    def _check_frame_size(self, pkt: dict) -> tuple[bool, str]:
        size = pkt.get("size", 0)
        if size < self._cfg["min_frame_size"]:
            self._inc("reject_size")
            return False, f"Frame too small: {size}B (min {self._cfg['min_frame_size']}B)"
        if size > self._cfg["max_frame_size"]:
            self._inc("reject_size")
            return False, f"Frame too large: {size}B (max {self._cfg['max_frame_size']}B)"
        return True, ""
    def _check_ttl(self, pkt: dict) -> tuple[bool, str]:
        if pkt.get("proto") in ("ARP", "UNKNOWN"):
            return True, ""
        ttl = pkt.get("ttl", 0)
        if ttl < 0 or ttl > self._cfg["max_ttl"]:
            self._inc("reject_ttl")
            return False, f"TTL out of range: {ttl}"
        return True, ""
    def _check_ports(self, pkt: dict) -> tuple[bool, str]:
        if pkt.get("proto") not in ("TCP", "UDP", "HTTP", "DNS"):
            return True, ""
        for label in ("src_port", "dst_port"):
            port = pkt.get(label, 0)
            if not isinstance(port, int):
                self._inc("reject_port")
                return False, f"Non-integer {label}: {port}"
            if not 0 <= port <= self._cfg["max_port"]:
                self._inc("reject_port")
                return False, f"{label} out of range: {port}"
        return True, ""
    def _check_tcp_flags(self, pkt: dict) -> tuple[bool, str]:
        if pkt.get("proto") not in ("TCP", "HTTP"):
            return True, ""
        invalid_chars = set(pkt.get("flags", "")) - _VALID_FLAG_CHARS
        if invalid_chars:
            self._inc("reject_flags")
            return False, f"Invalid TCP flag characters: {invalid_chars}"
        return True, ""
    def _check_timestamp(self, pkt: dict) -> tuple[bool, str]:
        timestamp = pkt.get("timestamp", 0)
        now = time.time()
        if timestamp > now + self._cfg["timestamp_max_future_sec"]:
            self._inc("reject_timestamp")
            return False, f"Timestamp is in the future: {timestamp:.2f} (now: {now:.2f})"
        if now - timestamp > self._cfg["timestamp_max_age_sec"]:
            self._inc("reject_timestamp")
            return False, f"Timestamp too old: {now - timestamp:.1f}s ago"
        return True, ""
    def _inc(self, stat_key: str) -> None:
        with self._lock:
            self._stats[stat_key] += 1
_validator: Optional[PacketValidator] = None
def get_validator() -> PacketValidator:
    global _validator
    if _validator is None:
        _validator = PacketValidator()
    return _validator
def validate_packet(pkt_info: dict) -> tuple[bool, str]:
    return get_validator().validate(pkt_info)
def get_validation_stats() -> dict:
    return get_validator().get_stats()
