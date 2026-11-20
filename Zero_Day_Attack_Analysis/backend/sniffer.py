"""
Strict live packet capture for the dashboard.

Only packets delivered by Scapy through a real capture provider are emitted.
There is deliberately no simulation, test-request injection, raw-socket
fallback, or process-flow fallback: if packet capture is unavailable, the
dashboard remains empty.
"""

import os
import socket
import sys
import threading
import time
from collections import deque
from typing import Callable


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from feature_extractor import extract
from npcap_fix import get_capture_diagnostics

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

SCAPY_AVAILABLE = False
SCAPY_IMPORT_ERROR = ""
try:
    from npcap_fix import patch_scapy_dll_path

    patch_scapy_dll_path()
    from scapy.all import AsyncSniffer, conf

    SCAPY_AVAILABLE = True
except Exception as exc:
    SCAPY_IMPORT_ERROR = str(exc)


_bps_window: deque[tuple[float, int]] = deque()
_bps_lock = threading.Lock()


def _record_bps(size: int) -> None:
    now = time.time()
    with _bps_lock:
        _bps_window.append((now, size))
        while _bps_window and now - _bps_window[0][0] > 2.0:
            _bps_window.popleft()


def get_global_bps() -> float:
    now = time.time()
    with _bps_lock:
        while _bps_window and now - _bps_window[0][0] > 2.0:
            _bps_window.popleft()
        return round(sum(size for _, size in _bps_window) / 2.0, 1)


class NetworkSniffer:
    """Capture and emit only packets that originate from a packet-capture driver."""

    def __init__(
        self,
        interface: str | None = None,
        capture_scope: str = "host",
        callback: Callable[[dict], None] | None = None,
    ):
        self.interface = interface
        self.capture_scope = capture_scope.lower()
        self.capture_device: str | None = None
        self._selected_interface: dict | None = None
        self.callback = callback
        self.running = False
        self._sniffer = None
        self.packet_queue: deque[dict] = deque(maxlen=5000)
        self.diag: dict = {}
        self.active_engine = "NO_CAPTURE"
        self.capture_error = ""
        self.capture_started_at: float | None = None
        self.last_packet_at: float | None = None
        self.total_packets = 0
        self._setup_engine()

    def _setup_engine(self) -> None:
        self.diag = get_capture_diagnostics()
        self.active_engine = "NO_CAPTURE"
        self.capture_device = None
        self._selected_interface = None

        if self.capture_scope not in {"host", "ap-mirror"}:
            self.capture_error = "Capture scope must be 'host' or 'ap-mirror'."
            return

        if not SCAPY_AVAILABLE:
            detail = f": {SCAPY_IMPORT_ERROR}" if SCAPY_IMPORT_ERROR else ""
            self.capture_error = f"Scapy packet capture is unavailable{detail}"
            return

        try:
            listener = str(conf.L2listen)
        except Exception as exc:
            self.capture_error = f"Scapy capture socket is unavailable: {exc}"
            return

        if "NotAvailableSocket" in listener:
            self.capture_error = "No libpcap/Npcap capture provider is available. Install or repair Npcap."
            return

        selected, selection_error = self._select_capture_interface()
        if selection_error:
            self.capture_error = selection_error
            return
        self._selected_interface = selected
        self.capture_device = selected.get("capture_id") if selected else self.diag.get("best_iface")

        if sys.platform.startswith("win"):
            if not self.diag.get("wpcap_dll"):
                self.capture_error = "Npcap is missing wpcap.dll. Reinstall Npcap with WinPcap API-compatible mode enabled."
                return
            if self.diag.get("npcap_service") != "RUNNING":
                self.capture_error = "Npcap service is not running. Start or repair the Npcap installation."
                return
            self.active_engine = "NPCAP_L2"
        else:
            # On Unix-like systems Scapy may use libpcap or its native L2 socket.
            self.active_engine = "PCAP_L2"

        self.capture_error = ""
        print(f"[Sniffer] Ready for {self.capture_scope} capture on {self.capture_device or 'default interface'}.")

    def _select_capture_interface(self) -> tuple[dict | None, str | None]:
        interfaces = get_interfaces()

        if self.capture_scope == "ap-mirror" and not self.interface:
            return None, "AP mirror mode requires an explicit wired Ethernet sensor interface."

        if self.interface:
            selected = next(
                (
                    item for item in interfaces
                    if self.interface in {item.get("capture_id"), item.get("name"), item.get("network_name")}
                ),
                None,
            )
            if not selected:
                return None, f"Capture interface '{self.interface}' was not found. Use GET /api/interfaces to list valid capture_id values."
        else:
            selected = next(
                (item for item in interfaces if item.get("capture_id") == self.diag.get("best_iface")),
                None,
            )

        if self.capture_scope == "ap-mirror":
            if not selected or not selected.get("ap_mirror_eligible"):
                return None, (
                    "AP mirror mode requires a physical wired Ethernet interface connected to an authorized "
                    "router, switch, or access-point mirror port. A Wi-Fi client adapter cannot capture all AP clients."
                )
        return selected, None

    def get_status(self) -> dict:
        available = self.active_engine in ("NPCAP_L2", "PCAP_L2")
        last_packet_age_ms = None
        if self.last_packet_at is not None:
            last_packet_age_ms = round(max(0, time.time() - self.last_packet_at) * 1000)
        return {
            "mode": "LIVE" if available else "UNAVAILABLE",
            "engine": self.active_engine,
            "is_admin": self.diag.get("is_admin", False),
            "interface": self.capture_device or self.interface or self.diag.get("best_iface") or self.diag.get("default_ip") or "Auto-Active",
            "packets_count": len(self.packet_queue),
            "packets_captured": self.total_packets,
            "running": self.running,
            "capture_active": self.running,
            "capture_started_at": self.capture_started_at,
            "real_traffic_seen": self.total_packets > 0,
            "last_packet_age_ms": last_packet_age_ms,
            "capture_available": available,
            "capture_error": self.capture_error,
            "capture_scope": self.capture_scope,
            "scope_label": "AP mirror sensor" if self.capture_scope == "ap-mirror" else "This computer only",
            "mirror_requirement": (
                "Configure an authorized AP, router, or managed switch to mirror traffic to this wired sensor interface."
                if self.capture_scope == "ap-mirror" else None
            ),
            "selected_interface": self._selected_interface,
        }

    def restart(self) -> None:
        """Restart the real packet-capture driver on the selected interface."""
        self.stop()
        self._setup_engine()
        self.start()

    def configure_capture(self, capture_scope: str, interface: str | None) -> dict:
        """Apply an authorized capture scope and restart the real capture driver."""
        self.stop()
        self.capture_scope = capture_scope.lower()
        self.interface = interface
        self._setup_engine()
        self.start()
        return self.get_status()

    def _start_scapy_live(self) -> None:
        if self.running:
            return
        try:
            iface = self.capture_device or self.diag.get("best_iface")
            kwargs = {
                "prn": self._on_scapy_packet,
                "store": False,
                "promisc": True,
            }
            if iface:
                kwargs["iface"] = iface

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self.running = True
            self.capture_started_at = time.time()
            self.capture_error = ""
            print("[Sniffer] Real packet capture started.")
        except Exception as exc:
            self.running = False
            self.active_engine = "NO_CAPTURE"
            self.capture_error = f"Unable to start packet capture: {exc}"
            self._sniffer = None
            print(f"[Sniffer] {self.capture_error}")

    def _on_scapy_packet(self, packet) -> None:
        """Emit exactly the packet received from the capture provider."""
        try:
            info = extract(packet)
            if not info:
                return
            info["is_real"] = True
            _record_bps(info["size"])
            self.packet_queue.append(info)
            self.total_packets += 1
            self.last_packet_at = time.time()
            if self.callback:
                self.callback(info)
        except Exception:
            # A malformed packet must not stop the capture loop.
            pass

    def start(self) -> None:
        if self.active_engine not in ("NPCAP_L2", "PCAP_L2"):
            self.running = False
            return
        self._start_scapy_live()

    def stop(self) -> None:
        self.running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None


def get_interfaces() -> list[dict]:
    """Return capture-ready interface IDs and AP-mirror eligibility."""
    system_stats = {}
    if PSUTIL_AVAILABLE:
        try:
            system_stats = psutil.net_if_stats()
        except Exception:
            pass

    if SCAPY_AVAILABLE:
        try:
            results = []
            for item in conf.ifaces.values():
                name = getattr(item, "name", "") or "Unnamed interface"
                description = getattr(item, "description", "") or name
                capture_id = getattr(item, "network_name", "") or name
                link_type = _classify_interface(name, description)
                results.append({
                    "name": name,
                    "description": description,
                    "capture_id": capture_id,
                    "network_name": capture_id,
                    "ip": getattr(item, "ip", "") or "No IPv4",
                    "is_up": system_stats.get(name).isup if name in system_stats else None,
                    "link_type": link_type,
                    "ap_mirror_eligible": link_type == "ethernet",
                })
            if results:
                return results
        except Exception:
            pass

    if PSUTIL_AVAILABLE:
        try:
            addrs = psutil.net_if_addrs()
            results = []
            for name, addr_list in addrs.items():
                ipv4 = next(
                    (
                        addr.address
                        for addr in addr_list
                        if addr.family == socket.AF_INET and not addr.address.startswith("127.")
                    ),
                    None,
                )
                link_type = _classify_interface(name, name)
                results.append({
                    "name": name,
                    "description": name,
                    "capture_id": name,
                    "network_name": name,
                    "ip": ipv4 or "No IPv4",
                    "is_up": system_stats.get(name).isup if name in system_stats else None,
                    "link_type": link_type,
                    "ap_mirror_eligible": link_type == "ethernet",
                })
            return results
        except Exception:
            pass
    return []


def _classify_interface(name: str, description: str) -> str:
    text = f"{name} {description}".lower()
    if "loopback" in text:
        return "loopback"
    if any(token in text for token in ("virtual", "hyper-v", "vbox", "vmware", "wan miniport", "bluetooth")):
        return "virtual"
    if any(token in text for token in ("wi-fi", "wifi", "wireless", "802.11")):
        return "wireless"
    if any(token in text for token in ("ethernet", "gigabit", "gbe", "lan")):
        return "ethernet"
    return "other"


