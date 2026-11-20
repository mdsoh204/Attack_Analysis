# Zero-Day Live Network Monitor

A Wireshark-inspired dashboard that displays only packets captured from the
selected network interface. An optional CICIDS-trained model analyzes rolling
flow features when enabled. The dashboard never injects or simulates packets.

## Run it

1. Install the Python dependencies:

   ```powershell
   cd backend
   pip install -r requirements.txt
   ```

2. On Windows, install [Npcap](https://npcap.com/#download) with **WinPcap API-compatible mode** selected. Run `run_admin.bat` as Administrator only if your Npcap configuration requires it.

3. Start the monitor:

   ```powershell
   python app.py
   ```

4. Open [http://localhost:5000](http://localhost:5000).

The server binds to `127.0.0.1` by default. Use `--host 0.0.0.0` only on a trusted network.

## What appears in the dashboard

- Packets delivered by Scapy from the selected interface
- Live packet and byte rates
- Protocol totals
- Decoded packet headers, raw bytes, and layer stacks
- Complete in-memory capture history and CSV export for the whole running session
- Optional ExtraTrees flow classifier trained from the supplied CICIDS DDoS dataset

Every displayed packet must carry capture provenance and pass basic integrity validation. If Npcap/Scapy is unavailable, the dashboard stays empty rather than showing sample data.

## Capture scope

```powershell
python app.py --iface "Wi-Fi"
python app.py --port 8080
python app.py --scope ap-mirror --iface "Ethernet"
```

`host` (the default) shows traffic visible to this computer's selected adapter.
For authorized broader monitoring, use a physical Ethernet sensor connected to a configured router, switch, or access-point mirror port with `--scope ap-mirror`.

## Project layout

```text
backend/
  app.py                Flask + Socket.IO live capture server
  sniffer.py            Scapy capture driver integration
  feature_extractor.py  Packet decoding and presentation metadata
  packet_validator.py   Capture-integrity validation
frontend/
  index.html            Dashboard layout
  css/style.css         Dashboard styling
  js/                   Socket, display, and chart logic
```

> Built with Python, Scapy, Flask-SocketIO, and Chart.js.

## Packet database

This project now uses **SQLite**, which is the better default for one local
live-capture dashboard: it has no server, user accounts, or network setup.

1. Start the application and click **DB OFF** in the top-right bar.
2. It changes to **DB ON**. Every newly validated live packet is then saved
   automatically.
3. Click **DB ON** to stop database writes. Live capture and the **CSV**
   download continue to work in both modes.

The database is created only after storage is enabled, at:

```text
backend/data/packet_monitor.sqlite3
```

Open that file with [DB Browser for SQLite](https://sqlitebrowser.org/) or
SQLiteStudio and browse the `captured_packets` table. The full decoded packet
record is in `details_json`; indexed fields such as `captured_at`, `src_ip`,
`dst_ip`, and `protocol` make filtering fast. Set `PACKET_DATABASE_PATH` before
starting the app if you want the file in another location.

The stored JSON can contain captured packet-inspection data, so keep the
database file private and use it only for networks you are authorized to monitor.

MySQL is only preferable if several people or separate sensors must write to a
central shared server. In that case, migrate the SQLite file to MySQL rather
than exposing this local dashboard database on the network.
