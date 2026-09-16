from __future__ import annotations

import argparse
import os
import socket
import time
from pathlib import Path

import httpx
import psutil
from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

load_dotenv()

ENGINE_URL = os.getenv("ENGINE_URL", "http://127.0.0.1:8000").rstrip("/")
ROOT = Path(__file__).resolve().parents[2]


def emit(event_type: str, fields: dict) -> None:
    payload = {"source": "windows", "type": event_type, "fields": fields}
    try:
        httpx.post(f"{ENGINE_URL}/api/v1/events", json=payload, timeout=3.0)
    except Exception:
        pass


def private_ip(addr: str | None) -> bool:
    if not addr:
        return True
    if addr.startswith("127.") or addr in {"::1", "0.0.0.0", "::"}:
        return True
    parts = addr.split(".")
    if len(parts) == 4 and parts[0] in {"10"}:
        return True
    if len(parts) == 4 and parts[0] == "192" and parts[1] == "168":
        return True
    if len(parts) == 4 and parts[0] == "172":
        try:
            n = int(parts[1])
            if 16 <= n <= 31:
                return True
        except ValueError:
            return True
    return False


class WatchHandler(FileSystemEventHandler):
    def on_any_event(self, event) -> None:  # noqa: N802
        if event.is_directory:
            return
        path = getattr(event, "src_path", "") or ""
        lowered = path.replace("/", "\\").lower()
        if any(x in lowered for x in ("\\node_modules\\", "\\__pycache__\\", "\\.git\\", "\\data\\wh.db")):
            return
        emit("file_change", {"file_path": path, "event": event.event_type})


def snapshot_processes() -> dict[int, dict]:
    found: dict[int, dict] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        try:
            info = proc.info
            parent_name = ""
            try:
                parent = psutil.Process(info.get("ppid") or 0)
                parent_name = parent.name()
            except Exception:
                parent_name = ""
            found[int(info["pid"])] = {
                "pid": int(info["pid"]),
                "process_name": info.get("name") or "",
                "process_path": info.get("exe") or "",
                "parent_name": parent_name,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


def snapshot_conns() -> set[tuple]:
    items: set[tuple] = set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        conns = []
    for c in conns:
        if not c.raddr:
            continue
        if c.status not in {"ESTABLISHED", "SYN_SENT"}:
            continue
        rip = getattr(c.raddr, "ip", None)
        rport = getattr(c.raddr, "port", None)
        if private_ip(rip):
            continue
        items.add((c.pid or 0, rip, rport))
    return items


def snapshot_listeners() -> set[tuple]:
    items: set[tuple] = set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        conns = []
        for port in (8000, 8080, 5173):
            items.add(("0.0.0.0", port, "unknown"))
        return items
    for c in conns:
        if c.status != "LISTEN" or not c.laddr:
            continue
        lip = getattr(c.laddr, "ip", "") or "0.0.0.0"
        lport = getattr(c.laddr, "port", 0)
        name = ""
        if c.pid:
            try:
                name = psutil.Process(c.pid).name()
            except Exception:
                name = ""
        items.add((lip, lport, name))
    return items


def watch_dirs(extra: str | None) -> list[Path]:
    dirs = [ROOT / "patterns", ROOT / "engine", ROOT / "data"]
    watch = extra or os.getenv("WATCH_DIRS", "")
    for part in watch.split(";"):
        part = part.strip()
        if part:
            dirs.append(Path(part))
    existing = []
    for d in dirs:
        if d.exists() and d.is_dir():
            existing.append(d)
    return existing


def run(interval: float) -> None:
    hostname = socket.gethostname()
    procs = snapshot_processes()
    conns = snapshot_conns()
    listeners = snapshot_listeners()
    for lip, lport, name in listeners:
        emit(
            "port_open",
            {
                "listen_addr": lip,
                "listen_port": lport,
                "process_name": name,
                "host": hostname,
            },
        )

    observer = Observer()
    handler = WatchHandler()
    for d in watch_dirs(None):
        observer.schedule(handler, str(d), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(interval)
            current_procs = snapshot_processes()
            for pid, info in current_procs.items():
                if pid not in procs:
                    emit("process_start", info)
            procs = current_procs

            current_conns = snapshot_conns()
            for pid, dest_ip, dest_port in current_conns - conns:
                name = ""
                try:
                    if pid:
                        name = psutil.Process(pid).name()
                except Exception:
                    name = ""
                emit(
                    "net_connect",
                    {
                        "pid": pid,
                        "process_name": name,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                    },
                )
            conns = current_conns

            current_listeners = snapshot_listeners()
            for lip, lport, name in current_listeners - listeners:
                emit(
                    "port_open",
                    {
                        "listen_addr": lip,
                        "listen_port": lport,
                        "process_name": name,
                        "host": hostname,
                    },
                )
            listeners = current_listeners
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WH Windows defensive sensor")
    parser.add_argument("--interval", type=float, default=4.0)
    args = parser.parse_args()
    run(args.interval)
