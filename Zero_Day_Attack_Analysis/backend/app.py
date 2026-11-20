"""Live network traffic dashboard server.

The server accepts packet records only from ``NetworkSniffer``'s Scapy capture
callback. It does not load a model, score packets, create alerts, or inject
test traffic. Every record sent to the browser therefore represents a packet
seen by the selected network interface.
"""

import argparse
import csv
import io
import os
import platform
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime

from flask import Flask, Response, abort, jsonify, request, send_from_directory
from flask_socketio import SocketIO


parser = argparse.ArgumentParser(description="Live network traffic monitor")
parser.add_argument("--iface", default=None, help="Network interface to capture")
parser.add_argument("--port", type=int, default=5000)
parser.add_argument("--host", default="127.0.0.1", help="Dashboard bind address (default: 127.0.0.1)")
parser.add_argument(
    "--scope",
    choices=("host", "ap-mirror"),
    default="host",
    help="Capture this computer's adapter, or an authorized Ethernet mirror port",
)
args, _ = parser.parse_known_args()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR)
socketio = SocketIO(app, async_mode="threading")

from npcap_fix import fix_npcap, get_capture_diagnostics, is_admin

fix_npcap(verbose=False)

from packet_validator import get_validation_stats, get_validator, validate_packet
from sniffer import NetworkSniffer, get_interfaces
from ai_detector import AIDetector
from sqlite_store import store as packet_store

ai_detector = AIDetector(os.path.join(BASE_DIR, '..', '..', 'dataset', 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'))


# Keep the complete capture session in memory so history, details, and exports agree.
packet_log: list[dict] = []
packet_map: dict[int, dict] = {}
stats = {
    "total": 0,
    "start_time": time.time(),
    "session_id": uuid.uuid4().hex[:12],
    "proto_counts": defaultdict(int),
    "pps_history": deque(maxlen=60),
    "bps_history": deque(maxlen=60),
}
_pps_counter = 0
_bps_counter = 0
_lock = threading.Lock()
_sniffer_ref: NetworkSniffer | None = None
_validation_rejects = 0
_last_reject_reason = ""


def _format_endpoint(pkt_info: dict, address_key: str, port_key: str) -> str:
    """Format endpoints without appending an artificial ``:0`` port."""
    address = str(pkt_info.get(address_key, "") or "?")
    port = pkt_info.get(port_key)
    return f"{address}:{port}" if port else address


def on_packet(pkt_info: dict) -> None:
    """Store and broadcast one packet that came directly from the capture driver."""
    global _pps_counter, _bps_counter, _validation_rejects, _last_reject_reason

    # NetworkSniffer marks records only after Scapy delivers them from the NIC.
    # Nothing else is permitted to enter the dashboard.
    if pkt_info.get("is_real") is not True:
        return

    # Reject any queued/replayed capture record timestamped before this server
    # session began. The export and history are strictly session-scoped.
    if float(pkt_info.get("timestamp", 0)) < stats["start_time"]:
        with _lock:
            _validation_rejects += 1
            _last_reject_reason = "Packet predates the current capture session"
        return

    is_valid, reject_reason = validate_packet(pkt_info)
    if not is_valid:
        with _lock:
            _validation_rejects += 1
            _last_reject_reason = reject_reason
        return

    with _lock:
        packet_id = stats["total"] + 1
        record = {
            "id": packet_id,
            "session_id": stats["session_id"],
            "timestamp": float(pkt_info["timestamp"]),
            "time": datetime.fromtimestamp(pkt_info["timestamp"]).strftime("%H:%M:%S.%f")[:-3],
            "src": _format_endpoint(pkt_info, "src_ip", "src_port"),
            "dst": _format_endpoint(pkt_info, "dst_ip", "dst_port"),
            "src_ip": pkt_info.get("src_ip", ""),
            "dst_ip": pkt_info.get("dst_ip", ""),
            "src_port": pkt_info.get("src_port", 0),
            "dst_port": pkt_info.get("dst_port", 0),
            "proto": pkt_info.get("proto", "UNKNOWN"),
            "size": pkt_info.get("size", 0),
            "flags": pkt_info.get("flags", ""),
            "ttl": pkt_info.get("ttl", 0),
            "os_guess": pkt_info.get("os_guess", ""),
            "pkt_rate": round(pkt_info.get("pkt_rate", 0), 2),
            "bandwidth_bps": round(pkt_info.get("bandwidth_bps", 0), 1),
            "is_real": True,
            "raw_hex": pkt_info.get("raw_hex", ""),
            "raw_ascii": pkt_info.get("raw_ascii", ""),
            "layers": pkt_info.get("layers", []),
            "layers_str": pkt_info.get("layers_str", ""),
            "src_mac": pkt_info.get("src_mac", ""),
            "dst_mac": pkt_info.get("dst_mac", ""),
            "win_size": pkt_info.get("win_size", 0),
            "frag": pkt_info.get("frag", 0),
            "payload": pkt_info.get("payload", ""),
            "http_info": pkt_info.get("http_info"),
        }
        stats["total"] += 1
        stats["proto_counts"][record["proto"]] += 1
        _pps_counter += 1
        _bps_counter += record["size"]
        packet_log.append(record)
        packet_map[packet_id] = record

    if ai_detector.enabled:
        record.update(ai_detector.score({**record, "timestamp": pkt_info["timestamp"]}))
    # Persistence is deliberately opt-in.  Live capture and CSV export always
    # use the in-memory session, so toggling storage never drops CSV records.
    packet_store.save(record)

    light = {key: value for key, value in record.items() if key not in {"raw_hex", "raw_ascii", "layers", "payload"}}
    socketio.emit("packet", light)


def _pps_ticker() -> None:
    global _pps_counter, _bps_counter
    while True:
        time.sleep(1)
        with _lock:
            pps, bps = _pps_counter, _bps_counter
            _pps_counter = 0
            _bps_counter = 0
            stats["pps_history"].append(pps)
            stats["bps_history"].append(bps)
        socketio.emit("stats", _build_stats())


def _build_stats() -> dict:
    with _lock:
        total = stats["total"]
        elapsed = max(1, time.time() - stats["start_time"])
        pps = stats["pps_history"][-1] if stats["pps_history"] else 0
        bps = stats["bps_history"][-1] if stats["bps_history"] else 0
        proto_counts = dict(stats["proto_counts"])

    capture = {
        "mode": "UNAVAILABLE",
        "engine": "NO_CAPTURE",
        "capture_active": False,
        "real_traffic_seen": False,
        "last_packet_age_ms": None,
        "capture_error": "",
    }
    if _sniffer_ref:
        capture.update(_sniffer_ref.get_status())

    return {
        "total": total,
        "session_id": stats["session_id"],
        "session_started_at": stats["start_time"],
        "pps": pps,
        "bps": bps,
        "pps_history": list(stats["pps_history"]),
        "bps_history": list(stats["bps_history"]),
        "proto_counts": proto_counts,
        "elapsed": int(elapsed),
        "mode": capture["mode"],
        "engine": capture["engine"],
        "capture_active": capture["capture_active"],
        "real_traffic_seen": capture["real_traffic_seen"],
        "last_packet_age_ms": capture["last_packet_age_ms"],
        "capture_error": capture["capture_error"],
        "is_admin": is_admin(),
        "validation_rejects": _validation_rejects,
        "last_reject_reason": _last_reject_reason,
        "ai": ai_detector.stats(),
        "database": packet_store.status(),
    }


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/stats")
def api_stats():
    return jsonify(_build_stats())


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(get_interfaces())


@app.route("/api/capture/status")
def api_capture_status():
    return jsonify({
        "status": _sniffer_ref.get_status() if _sniffer_ref else {},
        "diagnostics": get_capture_diagnostics(),
        "is_admin": is_admin(),
    })


@app.route("/api/capture/restart", methods=["POST"])
def api_capture_restart():
    if not _sniffer_ref:
        return jsonify({"error": "Capture service is not running"}), 500
    _sniffer_ref.restart()
    status = _sniffer_ref.get_status()
    socketio.emit("capture_status", status)
    socketio.emit("stats", _build_stats())
    return jsonify({"status": "restarted", "capture": status})


@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    if _sniffer_ref:
        _sniffer_ref.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    if not _sniffer_ref:
        return jsonify({"error": "Capture service is not running"}), 500
    if not _sniffer_ref.running:
        _sniffer_ref.restart()
    return jsonify({"status": "started", "capture": _sniffer_ref.get_status()})


@app.route("/api/system/admin_info")
def api_admin_info():
    admin = is_admin()
    return jsonify({
        "is_admin": admin,
        "platform": platform.platform(),
        "message": "Running with Administrator privileges." if admin else "Standard user mode. Run run_admin.bat if your Npcap installation requires elevation.",
    })


@app.route("/api/packet/<int:pkt_id>")
def api_packet_detail(pkt_id: int):
    record = packet_map.get(pkt_id)
    if record is None:
        abort(404, description=f"Packet #{pkt_id} not found in buffer")
    return jsonify(record)


@app.route("/api/export/csv")
def api_export_csv():
    with _lock:
        packets = list(packet_log)
    fields = [
        "session_id", "id", "timestamp", "time", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "size",
        "flags", "ttl", "os_guess", "pkt_rate", "bandwidth_bps", "layers_str", "is_real",
        "ai_enabled", "threat_pct", "safe_pct", "attack_type",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(packets)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=live_packet_export_{stats['session_id']}.csv", "X-Exported-Packets": str(len(packets))},
    )


@app.route("/api/database/status")
def api_database_status():
    """Report the local persistence state and the database file location."""
    return jsonify(packet_store.status())


@app.route("/api/database/toggle", methods=["POST"])
def api_database_toggle():
    """Enable or disable persistence without interrupting packet capture."""
    body = request.get_json(silent=True) or {}
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "'enabled' must be a boolean", "database": packet_store.status()}), 400

    database = packet_store.set_enabled(enabled)
    if enabled and not database["enabled"]:
        return jsonify({"error": database["error"] or "Could not connect to local database", "database": database}), 503

    socketio.emit("stats", _build_stats())
    return jsonify({"status": "enabled" if enabled else "disabled", "database": database})


@app.route("/api/ai/status")
def api_ai_status():
    return jsonify(ai_detector.status())


@app.route("/api/ai/toggle", methods=["POST"])
def api_ai_toggle():
    enabled = bool((request.get_json(silent=True) or {}).get("enabled"))
    try:
        result = ai_detector.set_enabled(enabled)
    except Exception as exc:
        return jsonify({"error": str(exc), "status": ai_detector.status()}), 503
    socketio.emit("stats", _build_stats())
    return jsonify(result)


@app.route("/api/validation/stats")
def api_validation_stats():
    values = get_validation_stats()
    with _lock:
        values["dashboard_rejects"] = _validation_rejects
        values["last_reject_reason"] = _last_reject_reason
    return jsonify(values)


@app.route("/api/validation/reset", methods=["POST"])
def api_validation_reset():
    global _validation_rejects, _last_reject_reason
    get_validator().reset_stats()
    with _lock:
        _validation_rejects = 0
        _last_reject_reason = ""
    return jsonify({"status": "reset"})


@app.route("/api/packets/purge_invalid", methods=["POST"])
def api_purge_invalid():
    """Remove any stored item that lacks capture provenance."""
    with _lock:
        valid_records = [item for item in packet_log if item.get("is_real") is True]
        removed = len(packet_log) - len(valid_records)
        packet_log.clear()
        packet_log.extend(valid_records)
        packet_map.clear()
        packet_map.update({item["id"]: item for item in packet_log})
    return jsonify({"status": "purged", "removed": removed, "remaining": len(packet_log)})


@socketio.on("connect")
def on_connect():
    socketio.emit("stats", _build_stats())
    if _sniffer_ref:
        socketio.emit("capture_status", _sniffer_ref.get_status())
    with _lock:
        history = [
            {key: value for key, value in item.items() if key not in {"raw_hex", "raw_ascii", "layers", "payload"}}
            for item in packet_log
        ]
    socketio.emit("history", history, to=request.sid)


@socketio.on("get_packet_detail")
def on_get_packet_detail(data):
    record = packet_map.get(data.get("id"))
    if record:
        socketio.emit("packet_detail", record)


if __name__ == "__main__":
    print("=" * 68)
    print("  Zero-Day Live Network Traffic Monitor")
    print("=" * 68)
    _sniffer_ref = NetworkSniffer(interface=args.iface, capture_scope=args.scope, callback=on_packet)
    _sniffer_ref.start()
    status = _sniffer_ref.get_status()
    print(f"  Capture mode:       {status['mode']}")
    print(f"  Active engine:      {status['engine']}")
    print(f"  Interface:          {status['interface']}")
    print(f"  Dashboard port:     {args.port}")
    print("=" * 68)
    threading.Thread(target=_pps_ticker, daemon=True).start()
    print(f"\n  Open http://localhost:{args.port} in your browser\n")
    socketio.run(app, host=args.host, port=args.port, debug=False, use_reloader=False,
                 log_output=False, allow_unsafe_werkzeug=True)
