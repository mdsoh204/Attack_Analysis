import os
import sys
import ctypes
import subprocess
import platform
_NPCAP_DLL_SEARCH_PATHS = [
    r"C:\Windows\System32\Npcap",
    r"C:\Windows\SysWOW64\Npcap",
    r"C:\Program Files\Npcap",
    r"C:\Program Files (x86)\Npcap",
    r"C:\Program Files\WinPcap",
    r"C:\Program Files (x86)\WinPcap",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
]
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
def get_npcap_service_status() -> str:
    if platform.system() != "Windows":
        return "N/A"
    for svc_name in ("npcap", "npf"):
        try:
            result = subprocess.run(
                ["sc.exe", "query", svc_name],
                capture_output=True, text=True, timeout=3
            )
            if "RUNNING" in result.stdout:
                return "RUNNING"
            elif "STOPPED" in result.stdout or "STATE" in result.stdout:
                return "STOPPED"
        except Exception:
            continue
    return "NOT_INSTALLED"
def start_npcap_service() -> bool:
    if platform.system() != "Windows":
        return True
    status = get_npcap_service_status()
    if status == "RUNNING":
        return True
    if status != "STOPPED":
        return False
    for svc_name in ("npcap", "npf"):
        try:
            start = subprocess.run(
                ["sc.exe", "start", svc_name],
                capture_output=True, text=True, timeout=3
            )
            if start.returncode == 0 or "RUNNING" in start.stdout or "START_PENDING" in start.stdout:
                return True
        except Exception:
            pass
    return False
def find_wpcap_dll() -> str | None:
    """Return full path to wpcap.dll if found, else None."""
    for d in _NPCAP_DLL_SEARCH_PATHS:
        candidate = os.path.join(d, "wpcap.dll")
        if os.path.isfile(candidate):
            return candidate
    for p in os.environ.get("PATH", "").split(os.pathsep):
        if not p.strip():
            continue
        candidate = os.path.join(p.strip(), "wpcap.dll")
        if os.path.isfile(candidate):
            return candidate
    return None
def patch_scapy_dll_path() -> bool:
    dll_path = find_wpcap_dll()
    if dll_path:
        dll_dir = os.path.dirname(dll_path)
        if hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(dll_dir)
            except Exception:
                pass
        if dll_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = dll_dir + os.pathsep + os.environ.get("PATH", "")
        return True
    return False
def get_default_route_local_ip() -> str | None:
    try:
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True, stderr=subprocess.DEVNULL, timeout=3
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                ip = parts[3]
                if not ip.startswith("127.") and ip != "0.0.0.0":
                    return ip
    except Exception:
        pass
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None
def pick_best_interface() -> str | None:
    """Select the best Scapy interface name matching default route."""
    try:
        from scapy.all import get_if_list, get_if_addr
        interfaces = get_if_list()
    except Exception:
        return None
    local_ip = get_default_route_local_ip()
    best = None
    for iface in interfaces:
        try:
            addr = get_if_addr(iface)
            if addr and addr != "0.0.0.0":
                if local_ip and addr == local_ip:
                    return iface
                if best is None and not addr.startswith("127."):
                    best = iface
        except Exception:
            continue
    return best
def get_capture_diagnostics() -> dict:
    admin = is_admin()
    svc_status = get_npcap_service_status()
    wpcap = find_wpcap_dll()
    default_ip = get_default_route_local_ip()
    best_iface = pick_best_interface()
    has_npcap = bool(wpcap and svc_status == "RUNNING")
    if has_npcap:
        tier = "NPCAP_L2"
        engine_label = "Npcap Layer-2 Promiscuous Sniffer"
        can_capture_live = True
    else:
        tier = "NO_CAPTURE"
        engine_label = "Packet capture unavailable"
        can_capture_live = False

    return {
        "is_admin": admin,
        "npcap_service": svc_status,
        "wpcap_dll": wpcap,
        "default_ip": default_ip,
        "best_iface": best_iface,
        "tier": tier,
        "engine_label": engine_label,
        "can_capture_live": can_capture_live,
    }
def fix_npcap(verbose: bool = True) -> dict:
    patch_scapy_dll_path()
    start_npcap_service()
    diag = get_capture_diagnostics()
    if verbose:
        print(f"[Capture Engine] Selected Tier: {diag['tier']} ({diag['engine_label']})")
        print(f"                 Admin: {diag['is_admin']} | Default IP: {diag['default_ip']}")
        if diag['wpcap_dll']:
            print(f"                 Npcap DLL: {diag['wpcap_dll']}")
        else:
            print("                 Npcap DLL: Not found (no packets will be displayed)")
    return diag
if __name__ == "__main__":
    diag = fix_npcap(verbose=True)
    print("Diagnostics result:", diag)
