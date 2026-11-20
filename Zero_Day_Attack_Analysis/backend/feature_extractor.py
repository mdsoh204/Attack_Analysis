"""Convert Scapy packets into records for the live monitor."""

import time
import re
from collections import defaultdict, deque

_rate_window = defaultdict(deque)
_bytes_window = defaultdict(deque)
_WINDOW = 2.0


def _packet_rate(src_ip: str) -> float:
    now = time.time()
    dq  = _rate_window[src_ip]
    dq.append(now)
    while dq and now - dq[0] > _WINDOW:
        dq.popleft()
    return round(len(dq) / _WINDOW, 2)


def _bytes_rate(src_ip: str, pkt_size: int) -> float:
    """Return approximate bandwidth in bytes/sec from src_ip."""
    now = time.time()
    dq  = _bytes_window[src_ip]
    dq.append((now, pkt_size))
    while dq and now - dq[0][0] > _WINDOW:
        dq.popleft()
    total_bytes = sum(s for _, s in dq)
    return round(total_bytes / _WINDOW, 1)


FLAG_BITS = {
    0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P",
    0x10: "A", 0x20: "U", 0x40: "E", 0x80: "C",
}


def decode_flags(flag_int: int) -> str:
    """Decode integer TCP flags into standard notation string (e.g. 'SA', 'PA', 'FA')."""
    return "".join(v for k, v in FLAG_BITS.items() if flag_int & k)


def guess_os_from_ttl(ttl: int) -> str:
    """Guess operating system family based on standard initial TTL values."""
    if ttl <= 0:
        return "Unknown"
    if ttl <= 64:
        return "Linux / Unix / macOS / Android (TTL ~64)"
    if ttl <= 128:
        return "Windows NT / 10 / 11 (TTL ~128)"
    if ttl <= 255:
        return "Cisco / Network Gateway / Solaris (TTL ~255)"
    return "Unknown OS"


def bytes_to_hex(data: bytes, max_bytes: int = 128) -> str:
    """Convert raw bytes to a space-separated hex string."""
    chunk = data[:max_bytes]
    return " ".join(f"{b:02X}" for b in chunk)


def bytes_to_ascii(data: bytes, max_bytes: int = 128) -> str:
    """Convert raw bytes to printable ASCII (dots for non-printable characters)."""
    chunk = data[:max_bytes]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


HTTP_VERB_REGEX = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/(\d\.\d)", re.IGNORECASE)

def parse_http_payload(payload_str: str) -> dict | None:
    """Extract HTTP method, path, headers, and body if payload contains HTTP."""
    if not payload_str:
        return None
    match = HTTP_VERB_REGEX.match(payload_str.strip())
    if match:
        method, path, http_ver = match.groups()
        lines = payload_str.splitlines()
        headers = {}
        body = ""
        is_body = False
        for line in lines[1:]:
            if not is_body:
                if not line.strip():
                    is_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            else:
                body += line + "\n"

        return {
            "method": method.upper(),
            "path": path,
            "version": f"HTTP/{http_ver}",
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
            "content_type": headers.get("content-type", ""),
            "body": body.strip(),
        }
    return None


def build_layer_stack(packet) -> list[dict]:
    """
    Walk Scapy layers and return a list of dicts: [{ name, fields }, ...]
    """
    try:
        stack = []
        layer = packet

        while layer:
            lname = layer.__class__.__name__
            fields = {}

            try:
                if lname == "Ether":
                    fields = {
                        "src_mac": layer.src,
                        "dst_mac": layer.dst,
                        "type": hex(layer.type),
                    }
                elif lname == "IP":
                    fields = {
                        "version": layer.version,
                        "ihl": layer.ihl,
                        "tos": layer.tos,
                        "len": layer.len,
                        "id": layer.id,
                        "flags": str(layer.flags),
                        "frag": layer.frag,
                        "ttl": layer.ttl,
                        "proto": layer.proto,
                        "chksum": hex(layer.chksum) if layer.chksum else "0x0",
                        "src": layer.src,
                        "dst": layer.dst,
                    }
                elif lname == "TCP":
                    flags_str = decode_flags(int(layer.flags))
                    fields = {
                        "sport": layer.sport,
                        "dport": layer.dport,
                        "seq": layer.seq,
                        "ack": layer.ack,
                        "dataofs": layer.dataofs,
                        "flags": flags_str or "—",
                        "window": layer.window,
                        "chksum": hex(layer.chksum) if layer.chksum else "0x0",
                        "urgptr": layer.urgptr,
                    }
                elif lname == "UDP":
                    fields = {
                        "sport": layer.sport,
                        "dport": layer.dport,
                        "len": layer.len,
                        "chksum": hex(layer.chksum) if layer.chksum else "0x0",
                    }
                elif lname == "ICMP":
                    fields = {
                        "type": layer.type,
                        "code": layer.code,
                        "chksum": hex(layer.chksum) if layer.chksum else "0x0",
                        "id": getattr(layer, "id", "—"),
                        "seq": getattr(layer, "seq", "—"),
                    }
                elif lname == "ARP":
                    fields = {
                        "hwtype": layer.hwtype,
                        "ptype": hex(layer.ptype),
                        "op": layer.op,
                        "hwsrc": layer.hwsrc,
                        "psrc": layer.psrc,
                        "hwdst": layer.hwdst,
                        "pdst": layer.pdst,
                    }
                elif lname == "DNS":
                    fields = {
                        "id": layer.id,
                        "qr": layer.qr,
                        "qdcount": layer.qdcount,
                        "ancount": layer.ancount,
                    }
                elif lname == "Raw":
                    raw_bytes = bytes(layer.load)
                    fields = {
                        "length": len(raw_bytes),
                        "preview": raw_bytes[:64].hex(),
                        "ascii": bytes_to_ascii(raw_bytes, 64),
                    }
            except Exception:
                pass

            if lname not in ("NoPayload",):
                stack.append({"name": lname, "fields": fields})

            try:
                layer = layer.payload
                if layer.__class__.__name__ == "NoPayload":
                    break
            except Exception:
                break

        return stack
    except Exception:
        return []


def layer_stack_string(stack: list[dict]) -> str:
    """Return human-readable layer string, e.g. 'Ethernet > IP > TCP > HTTP'."""
    return " > ".join(s["name"] for s in stack if s["name"] not in ("NoPayload",))


def extract(packet) -> dict:
    """
    Extract a structured pkt_info dict from a Scapy packet.
    """
    try:
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
        from scapy.layers.inet6 import _ICMPv6

        raw_bytes = bytes(packet)
        pkt_size  = len(raw_bytes)

        info = {
            "timestamp":     time.time(),
            "size":          pkt_size,
            "proto":         "UNKNOWN",
            "src_ip":        "",
            "dst_ip":        "",
            "src_port":      0,
            "dst_port":      0,
            "flags":         "",
            "ttl":           0,
            "os_guess":      "",
            "src_mac":       "",
            "dst_mac":       "",
            "payload":       "",
            "http_info":     None,
            "pkt_rate":      0.0,
            "bandwidth_bps": 0.0,
            "frag":          0,
            "win_size":      0,
            "raw_hex":       bytes_to_hex(raw_bytes, 128),
            "raw_ascii":     bytes_to_ascii(raw_bytes, 128),
            "layers":        [],
            "layers_str":    "",
            "is_real":       True,
        }

        stack = build_layer_stack(packet)
        info["layers"] = stack
        info["layers_str"] = layer_stack_string(stack)

        if packet.haslayer(Ether):
            info["src_mac"] = packet[Ether].src
            info["dst_mac"] = packet[Ether].dst

        if packet.haslayer(ARP):
            info["proto"]   = "ARP"
            info["src_ip"]  = packet[ARP].psrc
            info["dst_ip"]  = packet[ARP].pdst
            info["src_mac"] = packet[ARP].hwsrc

        elif packet.haslayer(IP):
            ip = packet[IP]
            info["src_ip"]   = ip.src
            info["dst_ip"]   = ip.dst
            info["ttl"]      = ip.ttl
            info["os_guess"] = guess_os_from_ttl(ip.ttl)
            info["frag"]     = int(ip.flags.DF == 0 and ip.frag > 0)

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info["proto"]    = "TCP"
                info["src_port"] = tcp.sport
                info["dst_port"] = tcp.dport
                info["flags"]    = decode_flags(int(tcp.flags))
                info["win_size"] = tcp.window

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info["proto"]    = "UDP"
                info["src_port"] = udp.sport
                info["dst_port"] = udp.dport
                if packet.haslayer(DNS) or udp.sport == 53 or udp.dport == 53:
                    info["proto"] = "DNS"

            elif packet.haslayer(ICMP):
                info["proto"] = "ICMP"

        elif packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            info["src_ip"] = ip6.src
            info["dst_ip"] = ip6.dst
            info["ttl"] = int(ip6.hlim or 0)
            info["os_guess"] = guess_os_from_ttl(info["ttl"])
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info["proto"] = "TCP"
                info["src_port"], info["dst_port"] = tcp.sport, tcp.dport
                info["flags"] = decode_flags(int(tcp.flags))
                info["win_size"] = tcp.window
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info["proto"] = "DNS" if packet.haslayer(DNS) or udp.sport == 53 or udp.dport == 53 else "UDP"
                info["src_port"], info["dst_port"] = udp.sport, udp.dport
            elif packet.haslayer(_ICMPv6):
                info["proto"] = "ICMP"

        if packet.haslayer(Raw):
            raw_payload = bytes(packet[Raw].load)
            try:
                payload_text = raw_payload.decode("utf-8", errors="replace")[:512]
                info["payload"] = payload_text
                http_details = parse_http_payload(payload_text)
                if http_details:
                    info["http_info"] = http_details
                    if info["proto"] == "TCP":
                        info["proto"] = "HTTP"
            except Exception:
                info["payload"] = ""

        if info["src_ip"]:
            info["pkt_rate"]      = _packet_rate(info["src_ip"])
            info["bandwidth_bps"] = _bytes_rate(info["src_ip"], pkt_size)
        return info

    except Exception:
        return None
