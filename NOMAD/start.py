#!/usr/bin/env python3
"""NOMAD — local-first network observation with SQLite persistence.

Passive public-network discovery uses fixed RIPEstat endpoints. Active host
sweeps are restricted to explicitly approved public IPv4 CIDRs; no arbitrary
Internet-wide scanning, port scanning, authentication or exploitation occurs.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import multiprocessing
import queue as queue_module
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import threading
import uuid
import webbrowser
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from storage import SQLiteStorage

try:
    import httpx
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse, JSONResponse
except ImportError as exc:  # friendly bootstrap error
    print("Missing dependencies. Run: python -m pip install -r requirements.txt")
    raise SystemExit(1) from exc

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
INDEX_PATH = ROOT / "index.html"
APP_VERSION = "1.0.0"
RIPE_BASE = "https://stat.ripe.net/data"
RIPE_HOST = "stat.ripe.net"
USER_AGENT = f"NOMAD/{APP_VERSION} (local public-network observation; transparent client)"
RFC1918_RANGES = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

DEFAULT_CONFIG: dict[str, Any] = {
    "bind": "127.0.0.1",
    "port": 8765,
    "auto_start": False,
    "poll_interval_seconds": 1200,  # legacy compatibility
    "discovery_interval_seconds": 30,
    "asn_refresh_interval_seconds": 3600,
    "request_spacing_seconds": 1.25,
    "observe_egress_ip": True,
    "seeds": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "traceroute": {
        "enabled": False,
        "approved_targets": [],
        "max_hops": 8,
        "interval_seconds": 3600,
        "timeout_seconds": 16,
    },
    "ping": {"enabled": False, "approved_targets": [], "interval_seconds": 30, "timeout_seconds": 8},
    "arp_scan": {"enabled": False, "approved_subnets": [], "interface": "", "interval_seconds": 3600, "timeout_seconds": 25},
    "host_scan": {"enabled": False, "approved_subnets": [], "max_hosts_per_subnet": 256, "max_total_hosts": 1000, "batch_size": 100, "concurrency": 32, "timeout_seconds": 3},
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nomad")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cfg = {**DEFAULT_CONFIG, **raw}
        cfg["traceroute"] = {**DEFAULT_CONFIG["traceroute"], **raw.get("traceroute", {})}
        cfg["ping"] = {**DEFAULT_CONFIG["ping"], **raw.get("ping", {})}
        cfg["arp_scan"] = {**DEFAULT_CONFIG["arp_scan"], **raw.get("arp_scan", {})}
        cfg["host_scan"] = {**DEFAULT_CONFIG["host_scan"], **raw.get("host_scan", {})}
        if cfg["bind"] != "127.0.0.1":
            raise ValueError("NOMAD binds only to 127.0.0.1 in this build.")
        cfg["port"] = max(1024, min(65535, int(cfg["port"])))
        cfg["poll_interval_seconds"] = max(1200, int(cfg["poll_interval_seconds"]))
        cfg["discovery_interval_seconds"] = max(5, int(cfg.get("discovery_interval_seconds", 300)))
        cfg["asn_refresh_interval_seconds"] = max(300, int(cfg.get("asn_refresh_interval_seconds", 3600)))
        cfg["request_spacing_seconds"] = max(1.0, float(cfg["request_spacing_seconds"]))
        seeds = []
        for raw_ip in cfg.get("seeds", []):
            ip = ipaddress.ip_address(str(raw_ip))
            if ip.is_global:
                seeds.append(str(ip))
        cfg["seeds"] = list(dict.fromkeys(seeds))
        approved = []
        for raw_ip in cfg["traceroute"].get("approved_targets", []):
            try:
                ip = ipaddress.ip_address(str(raw_ip))
                if ip.is_global:
                    approved.append(str(ip))
            except ValueError:
                continue
        cfg["traceroute"]["approved_targets"] = list(dict.fromkeys(approved))[:2]
        cfg["traceroute"]["enabled"] = bool(cfg["traceroute"].get("enabled"))
        cfg["traceroute"]["max_hops"] = max(3, min(8, int(cfg["traceroute"].get("max_hops", 8))))
        cfg["traceroute"]["interval_seconds"] = max(3600, int(cfg["traceroute"].get("interval_seconds", 3600)))
        cfg["traceroute"]["timeout_seconds"] = max(8, min(25, int(cfg["traceroute"].get("timeout_seconds", 16))))

        ping_targets = []
        for raw_ip in cfg["ping"].get("approved_targets", []):
            try:
                parsed = ipaddress.ip_address(str(raw_ip))
                if (parsed.is_global or parsed.is_private) and not (parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified):
                    ping_targets.append(str(parsed))
            except ValueError:
                continue
        cfg["ping"]["approved_targets"] = list(dict.fromkeys(ping_targets))[:32]
        cfg["ping"]["enabled"] = bool(cfg["ping"].get("enabled"))
        cfg["ping"]["interval_seconds"] = max(30, int(cfg["ping"].get("interval_seconds", 30)))
        cfg["ping"]["timeout_seconds"] = max(3, min(12, int(cfg["ping"].get("timeout_seconds", 8))))
        arp_networks = []
        for raw_net in cfg["arp_scan"].get("approved_subnets", []):
            try:
                network = ipaddress.ip_network(str(raw_net), strict=False)
                if isinstance(network, ipaddress.IPv4Network) and any(network.subnet_of(base) for base in RFC1918_RANGES) and network.prefixlen >= 24 and network.num_addresses <= 256:
                    arp_networks.append(str(network))
            except ValueError:
                continue
        cfg["arp_scan"]["approved_subnets"] = list(dict.fromkeys(arp_networks))[:8]
        cfg["arp_scan"]["enabled"] = bool(cfg["arp_scan"].get("enabled"))
        cfg["arp_scan"]["interval_seconds"] = max(3600, int(cfg["arp_scan"].get("interval_seconds", 3600)))
        cfg["arp_scan"]["timeout_seconds"] = max(10, min(35, int(cfg["arp_scan"].get("timeout_seconds", 25))))
        interface = str(cfg["arp_scan"].get("interface") or "")
        cfg["arp_scan"]["interface"] = interface if re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface) else ""

        # Active public sweeps are opt-in and limited to explicit, small CIDRs.
        # Existing ping/traceroute/ARP allowlists are left unchanged.
        host_networks = []
        for raw_net in cfg["host_scan"].get("approved_subnets", []):
            try:
                network = ipaddress.ip_network(str(raw_net), strict=False)
                if isinstance(network, ipaddress.IPv4Network) and network.is_global and network.num_addresses <= 256:
                    host_networks.append(str(network))
            except ValueError:
                continue
        cfg["host_scan"]["approved_subnets"] = list(dict.fromkeys(host_networks))[:8]
        cfg["host_scan"]["enabled"] = bool(cfg["host_scan"].get("enabled"))
        cfg["host_scan"]["max_hosts_per_subnet"] = 256
        cfg["host_scan"]["max_total_hosts"] = 1000
        cfg["host_scan"]["batch_size"] = 100
        cfg["host_scan"]["concurrency"] = max(1, min(32, int(cfg["host_scan"].get("concurrency", 32))))
        cfg["host_scan"]["timeout_seconds"] = max(2, min(5, int(cfg["host_scan"].get("timeout_seconds", 3))))
        return cfg
    except Exception as exc:
        log.exception("Invalid config; using safe defaults: %s", exc)
        return dict(DEFAULT_CONFIG)


CONFIG = load_config()


class EventHub:
    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()

    async def publish(self, event: dict[str, Any]) -> None:
        for queue in list(self.clients):
            try:
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass


class NomadState:
    def __init__(self) -> None:
        self.created = time.time()
        self.state = "STOPPED"
        self.safe_mode = False
        self.safe_reason: str | None = None
        self.last_heartbeat = time.time()
        self.last_cycle: str | None = None
        self.next_discovery_at: float | None = None
        self.scheduler_errors = 0
        self.probe_location: dict[str, Any] | None = None
        self.cycle_count = 0
        self.total_requests = 0
        self.total_denied = 0
        self.total_entities = 0
        self.total_routes = 0
        self.current_target: str | None = None
        self.progress = "Ожидание запуска"
        self.started_at: str | None = None
        self.stop_event: asyncio.Event | None = None
        self.work_event: asyncio.Event | None = None
        self.worker_task: asyncio.Task | None = None
        self.last_trace_at: dict[str, float] = {}
        self.last_ping_at: dict[str, float] = {}
        self.last_arp_at: dict[str, float] = {}
        self.active_results: deque[dict[str, Any]] = deque(maxlen=100)
        self.api_backoff_until = 0.0
        self.events: deque[dict[str, Any]] = deque(maxlen=350)
        self.observations: deque[dict[str, Any]] = deque(maxlen=300)
        self.entities: dict[str, dict[str, Any]] = {}
        self.routes: dict[str, dict[str, Any]] = {}
        self.asn_expanded: set[int] = set()
        self.asn_last_expanded: dict[int, float] = {}
        self.asn_queue: dict[int, dict[str, Any]] = {}
        self.ip_queue: dict[str, dict[str, Any]] = {}
        self.ip_inspected: set[str] = set()
        self.asn_expansion_count = 0
        self.source_status: dict[str, dict[str, Any]] = {
            "RIPEstat": {"status": "UNKNOWN", "checked_at": None, "message": "Ещё не проверялся"}
        }
        # Task-level counters are retained for internal analytics. The UI's
        # "probes" are separate OS processes exposed by ProbeProcessManager.
        self.workers: dict[str, dict[str, Any]] = {
            "discovery-scout": {"label": "Discovery Scout", "status": "IDLE", "task": "Ожидание новых сетевых данных", "count": 0},
            "resource-scout": {"label": "Resource Scout", "status": "IDLE", "task": "Ожидание", "count": 0},
            "route-scout": {"label": "Route Scout", "status": "IDLE", "task": "Ожидание", "count": 0},
            "geo-scout": {"label": "Geo Scout", "status": "IDLE", "task": "Ожидание", "count": 0},
        }
        self.origin: dict[str, Any] | None = None
        self.host_scan: dict[str, Any] = {
            "status": "IDLE", "stage": "idle", "active": False,
            "completed": 0, "total": 0, "alive": 0, "unreachable": 0,
            "enrichment_completed": 0, "enrichment_total": 0,
            "current": None, "message": "Ожидание активного сканирования",
            "started_at": None, "finished_at": None, "error": None,
        }
        self.host_scan_bootstrap_done = False
        self.discovery_progress: dict[str, Any] = {
            "status": "IDLE", "active": False, "completed": 0, "total": 0,
            "current": None, "message": "Ожидание IP discovery",
        }

    async def event(self, kind: str, message: str, level: str = "info", details: dict[str, Any] | None = None) -> None:
        item = {"id": str(uuid.uuid4())[:8], "time": utcnow(), "type": kind, "message": message, "level": level, "details": details or {}}
        self.events.appendleft(item)
        STORE.save_event(item)
        await HUB.publish({"type": "event", "data": item})

    async def observation(self, category: str, subject: str, summary: str, source: str, confidence: str = "medium", extra: dict[str, Any] | None = None) -> None:
        item = {"id": str(uuid.uuid4())[:8], "time": utcnow(), "category": category, "subject": subject, "summary": summary, "source": source, "confidence": confidence, "extra": extra or {}}
        self.observations.appendleft(item)
        STORE.save_observation(item)


STATE = NomadState()
HUB = EventHub()
REQUEST_LOCK = asyncio.Lock()
LAST_HTTP_AT = 0.0
ACTIVE_PROBE_LOCK = asyncio.Lock()
STORE = SQLiteStorage(ROOT / "data" / "nomad.sqlite3")
STARTUP_PROGRESS: dict[str, Any] = {
    "status": "PENDING", "stage": "waiting", "message": "Ожидание первого открытия веб-интерфейса",
    "completed": 0, "total": 1, "current": None, "unit": None, "updated_at": utcnow(),
}
STORAGE_INIT_TASK: asyncio.Task | None = None
STORAGE_INIT_LOCK = asyncio.Lock()


def report_startup_progress(payload: dict[str, Any]) -> None:
    STARTUP_PROGRESS.update(payload)
    STARTUP_PROGRESS["status"] = "RUNNING"

# A closed catalogue. Each API source is bound to one dedicated local OS process.
RIPE_ENDPOINTS = {
    "network-info": "network-info",
    "looking-glass": "looking-glass",
    "maxmind-geo-lite": "maxmind-geo-lite",
    "reverse-dns-ip": "reverse-dns-ip",
    "whois": "whois",
    "whats-my-ip": "whats-my-ip",
    "as-overview": "as-overview",
    "asn-neighbours": "asn-neighbours",
}
PROBE_ROLES = (
    ("discovery-scout-1", "discovery-scout", "Discovery Scout"),
    ("resource-scout-1", "resource-scout", "Resource Scout 1"),
    ("resource-scout-2", "resource-scout", "Resource Scout 2"),
    ("route-scout-1", "route-scout", "Route Scout 1"),
    ("route-scout-2", "route-scout", "Route Scout 2"),
    ("geo-scout-1", "geo-scout", "Geo Scout 1"),
    ("geo-scout-2", "geo-scout", "Geo Scout 2"),
)
SOURCE_ROLE = {
    "network-info": "discovery-scout",
    "as-overview": "resource-scout",
    "whois": "resource-scout",
    "looking-glass": "route-scout",
    "asn-neighbours": "route-scout",
    "maxmind-geo-lite": "geo-scout",
    "reverse-dns-ip": "geo-scout",
    "whats-my-ip": "geo-scout",
}
ROLE_SOURCES = {
    "discovery-scout": {"network-info"},
    "resource-scout": {"as-overview", "whois"},
    "route-scout": {"looking-glass", "asn-neighbours"},
    "geo-scout": {"maxmind-geo-lite", "reverse-dns-ip", "whats-my-ip"},
}


class ProbeRemoteError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, blocked: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.blocked = blocked


def _shared_text_write(shared: Any, value: str) -> None:
    raw = value.encode("utf-8", errors="replace")[:255]
    with shared.get_lock():
        shared.value = raw


def _shared_text_read(shared: Any) -> str:
    try:
        return bytes(shared[:]).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _probe_process_main(
    role: str,
    command_queue: Any,
    reply_queue: Any,
    heartbeat: Any,
    status_code: Any,
    task_text: Any,
    completed_count: Any,
) -> None:
    """Dedicated local worker process. It can call only its fixed RIPEstat subset."""
    pulse_stop = threading.Event()

    def pulse() -> None:
        while not pulse_stop.wait(0.8):
            with heartbeat.get_lock():
                heartbeat.value = time.time()

    pulse_thread = threading.Thread(target=pulse, name=f"{role}-heartbeat", daemon=True)
    pulse_thread.start()
    with heartbeat.get_lock():
        heartbeat.value = time.time()
    _shared_text_write(task_text, "Ожидание команды")
    status_code.value = 0

    try:
        with httpx.Client(
            timeout=httpx.Timeout(12.0, connect=5.0),
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            trust_env=False,
        ) as client:
            while True:
                try:
                    command = command_queue.get(timeout=0.5)
                except queue_module.Empty:
                    continue
                if not isinstance(command, dict):
                    continue
                if command.get("cmd") == "shutdown":
                    break

                command_id = str(command.get("id", ""))
                source_id = str(command.get("source_id", ""))
                params = command.get("params", {})
                status_code.value = 1
                resource_label = str(params.get("resource", "egress")) if isinstance(params, dict) else "invalid"
                _shared_text_write(task_text, f"{source_id}: {resource_label}")
                reply: dict[str, Any] = {"id": command_id, "ok": False}
                try:
                    if source_id not in ROLE_SOURCES.get(role, set()):
                        raise PermissionError("This process is not authorized for that RIPEstat endpoint")
                    if not isinstance(params, dict):
                        raise PermissionError("Invalid request parameters")
                    allowed_keys = {
                        "network-info": {"resource"},
                        "looking-glass": {"resource", "look_back_limit"},
                        "maxmind-geo-lite": {"resource"},
                        "reverse-dns-ip": {"resource"},
                        "whois": {"resource"},
                        "whats-my-ip": set(),
                        "as-overview": {"resource"},
                        "asn-neighbours": {"resource", "lod"},
                    }[source_id]
                    if set(params) - allowed_keys:
                        raise PermissionError("Unexpected request parameter")
                    resource = params.get("resource")
                    if source_id == "whats-my-ip":
                        if params:
                            raise PermissionError("whats-my-ip takes no parameters")
                    else:
                        if not isinstance(resource, str) or len(resource) > 64:
                            raise PermissionError("Invalid resource identifier")
                        if re.fullmatch(r"AS[0-9]{1,10}", resource, re.I):
                            if not (0 < int(resource[2:]) < 4_300_000_000):
                                raise PermissionError("Invalid ASN")
                        else:
                            parsed_ip = ipaddress.ip_address(resource)
                            if not parsed_ip.is_global:
                                raise PermissionError("Only global public IP literals are permitted")
                    if "look_back_limit" in params and str(params["look_back_limit"]) != "86400":
                        raise PermissionError("Unsupported looking-glass lookback")
                    if "lod" in params and str(params["lod"]) != "0":
                        raise PermissionError("Unsupported ASN-neighbours detail level")

                    endpoint = RIPE_ENDPOINTS[source_id]
                    url = f"{RIPE_BASE}/{endpoint}/data.json"
                    safe_params = {str(k): str(v) for k, v in params.items()}
                    safe_params["sourceapp"] = "nomad-local-observer"
                    with client.stream("GET", url, params=safe_params) as response:
                        if response.url.scheme != "https" or response.url.host != RIPE_HOST:
                            raise PermissionError("Request escaped the fixed HTTPS source")
                        if response.is_redirect:
                            reply.update(error="Redirect blocked by policy", blocked=True, status_code=response.status_code)
                        elif response.status_code in (403, 429):
                            reply.update(error=f"HTTP {response.status_code}; source refused or rate limited", blocked=True, status_code=response.status_code)
                        else:
                            body = bytearray()
                            for chunk in response.iter_bytes():
                                body.extend(chunk)
                                if len(body) > 2_000_000:
                                    raise ValueError("RIPEstat response exceeded 2 MB limit")
                            response.raise_for_status()
                            result = json.loads(body.decode("utf-8"))
                            if not isinstance(result, dict) or result.get("status") not in (None, "ok"):
                                raise RuntimeError("RIPEstat returned an API error")
                            reply.update(ok=True, data=result, status_code=response.status_code)
                except Exception as exc:
                    reply.setdefault("error", f"{type(exc).__name__}: {exc}")
                finally:
                    with completed_count.get_lock():
                        completed_count.value += 1
                    status_code.value = 0
                    _shared_text_write(task_text, "Ожидание команды")
                reply_queue.put(reply)
    finally:
        status_code.value = 2
        _shared_text_write(task_text, "Завершение")
        pulse_stop.set()
        pulse_thread.join(timeout=1.0)
        with heartbeat.get_lock():
            heartbeat.value = time.time()


class ProbeProcessManager:
    """Tracks seven local OS workers, including one dedicated discovery process."""
    def __init__(self) -> None:
        self.ctx = multiprocessing.get_context("spawn")
        self.total_created = 0
        self.records: deque[dict[str, Any]] = deque(maxlen=240)
        self.active: dict[str, dict[str, Any]] = {}
        self.round_robin: dict[str, int] = {group: 0 for group in ROLE_SOURCES}
        self.specs = {slot: (group, label) for slot, group, label in PROBE_ROLES}

    def has_alive(self) -> bool:
        return any(rec.get("process") is not None and rec["process"].is_alive() for rec in self.active.values())

    def _spawn(self, slot: str, group: str, label: str) -> dict[str, Any]:
        self.total_created += 1
        probe_id = f"NOMAD-P{self.total_created:04d}"
        command_queue = self.ctx.Queue()
        reply_queue = self.ctx.Queue()
        heartbeat = self.ctx.Value("d", time.time())
        status_code = self.ctx.Value("i", 0)
        task_text = self.ctx.Array("c", 256)
        completed_count = self.ctx.Value("i", 0)
        process = self.ctx.Process(
            name=f"nomad-{slot}", target=_probe_process_main,
            args=(group, command_queue, reply_queue, heartbeat, status_code, task_text, completed_count),
            daemon=True,
        )
        rec = {
            "id": probe_id, "slot": slot, "role": group, "label": label, "pid": None,
            "process": process, "commands": command_queue, "replies": reply_queue,
            "heartbeat": heartbeat, "status_code": status_code,
            "task_text": task_text, "completed_count": completed_count,
            "created_at": utcnow(), "stopped_at": None,
        }
        process.start()
        rec["pid"] = process.pid
        self.records.append(rec)
        log.info("Started probe process %s slot=%s role=%s pid=%s", probe_id, slot, group, process.pid)
        return rec

    def start(self) -> None:
        if self.active and all(
            slot in self.active and self.active[slot].get("process") is not None and self.active[slot]["process"].is_alive()
            for slot in self.specs
        ):
            return
        if self.active:
            self.stop_all()
        self.active = {}
        for slot, (group, label) in self.specs.items():
            self.active[slot] = self._spawn(slot, group, label)

    def reconcile(self) -> list[str]:
        """Restart crashed local workers; return slots that were replaced."""
        restarted = []
        for slot, (group, label) in self.specs.items():
            rec = self.active.get(slot)
            proc = rec.get("process") if rec else None
            if proc is None or not proc.is_alive():
                if rec:
                    rec["stopped_at"] = utcnow()
                self.active[slot] = self._spawn(slot, group, label)
                restarted.append(slot)
        return restarted

    async def request(self, source_id: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        group = SOURCE_ROLE.get(source_id)
        candidates = [r for r in self.active.values() if r["role"] == group and r.get("process") is not None and r["process"].is_alive()]
        if not candidates:
            raise RuntimeError(f"No live local probe process for {source_id}; supervisor will restart it")
        index = self.round_robin.get(group or "", 0) % len(candidates)
        self.round_robin[group or ""] = index + 1
        rec = candidates[index]
        command_id = str(uuid.uuid4())
        payload = {"cmd": "fetch", "id": command_id, "source_id": source_id, "params": params or {}}
        await asyncio.to_thread(rec["commands"].put, payload)
        try:
            reply = await asyncio.wait_for(asyncio.to_thread(rec["replies"].get, True, 18.0), timeout=20.0)
        except (queue_module.Empty, asyncio.TimeoutError) as exc:
            raise RuntimeError(f"Probe process {rec['id']} timed out or stopped responding") from exc
        if reply.get("id") != command_id:
            raise RuntimeError("Probe process response ID mismatch")
        if not reply.get("ok"):
            raise ProbeRemoteError(str(reply.get("error") or "Probe process request failed"), status_code=reply.get("status_code"), blocked=bool(reply.get("blocked")))
        return reply["data"]

    def stop_all(self) -> None:
        records = list(self.active.values())
        for rec in records:
            proc = rec.get("process")
            if proc is not None and proc.is_alive():
                try:
                    rec["commands"].put({"cmd": "shutdown"}, timeout=0.25)
                except Exception:
                    pass
        for rec in records:
            proc = rec.get("process")
            if proc is not None:
                proc.join(timeout=2.5)
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=1.5)
                rec["stopped_at"] = utcnow()
                rec["process"] = None
                for key in ("commands", "replies"):
                    try:
                        rec[key].close()
                        rec[key].join_thread()
                    except Exception:
                        pass
        self.active = {}

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        active_records = list(self.active.values())
        records = active_records if active_records else list(self.records)[-len(self.specs):]
        items = []
        alive_count = 0
        for rec in records:
            proc = rec.get("process")
            running = bool(proc is not None and proc.is_alive())
            heartbeat_value = rec["heartbeat"].value
            heartbeat_age = max(0.0, now - heartbeat_value)
            state_code = rec["status_code"].value if running else 2
            if running:
                alive_count += 1
                state = "STALE" if heartbeat_age > 5.0 else ("WORKING" if state_code == 1 else "IDLE")
            else:
                state = "STOPPED"
            items.append({
                "id": rec["id"], "slot": rec.get("slot"), "role": rec["role"], "label": rec["label"],
                "pid": rec["pid"], "status": state, "task": _shared_text_read(rec["task_text"]),
                "heartbeat_at": datetime.fromtimestamp(heartbeat_value, timezone.utc).isoformat(timespec="seconds"),
                "heartbeat_age_seconds": round(heartbeat_age, 1), "requests": rec["completed_count"].value,
                "created_at": rec["created_at"], "stopped_at": rec["stopped_at"],
            })
        return {"total": self.total_created, "alive": alive_count, "items": items, "configured": len(self.specs)}


PROBES = ProbeProcessManager()


async def fetch_ripestat(source_id: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    global LAST_HTTP_AT
    if source_id not in RIPE_ENDPOINTS:
        STATE.total_denied += 1
        raise PermissionError("Unknown source ID")
    async with REQUEST_LOCK:
        delay = max(
            CONFIG["request_spacing_seconds"] - (time.monotonic() - LAST_HTTP_AT),
            STATE.api_backoff_until - time.monotonic(),
        )
        if delay > 0:
            # Interruptible async rate gate. This is API protection, not an idle scan delay.
            gate = STATE.stop_event or asyncio.Event()
            try:
                await asyncio.wait_for(gate.wait(), timeout=delay)
                raise asyncio.CancelledError("NOMAD stopping during API rate gate")
            except asyncio.TimeoutError:
                pass
        LAST_HTTP_AT = time.monotonic()
        STATE.last_heartbeat = time.time()
        try:
            if not PROBES.has_alive():
                PROBES.start()
            result = await PROBES.request(source_id, params)
            STATE.total_requests += 1
        except ProbeRemoteError as exc:
            STATE.total_requests += 1
            if exc.status_code == 429:
                # Respect provider throttling: pause requests and retry on the next discovery pass.
                STATE.api_backoff_until = max(STATE.api_backoff_until, time.monotonic() + 300.0)
                STATE.source_status["RIPEstat"] = {
                    "status": "RATE LIMITED", "checked_at": utcnow(),
                    "message": "RIPEstat returned HTTP 429; requests paused for 5 minutes",
                }
                raise RuntimeError("RIPEstat rate limited NOMAD (HTTP 429); 5-minute backoff applied") from exc
            if exc.blocked:
                STATE.source_status["RIPEstat"] = {
                    "status": "BLOCKED", "checked_at": utcnow(),
                    "message": f"HTTP {exc.status_code or 'redirect'}; networking stopped",
                }
                await enter_safe_mode(str(exc))
                raise PermissionError(str(exc)) from exc
            raise RuntimeError(str(exc)) from exc
        except Exception:
            STATE.total_requests += 1
            raise
    STATE.last_heartbeat = time.time()
    STATE.source_status["RIPEstat"] = {"status": "UP", "checked_at": utcnow(), "message": "Публичный API отвечает через локальный probe process"}
    return result


async def enter_safe_mode(reason: str) -> None:
    STATE.safe_mode = True
    STATE.safe_reason = reason
    if STATE.state not in ("STOPPED", "STOPPING"):
        STATE.state = "SAFE_MODE"
    if STATE.stop_event:
        STATE.stop_event.set()
    await STATE.event("policy", reason, "critical")


def parse_asns(raw: Any) -> list[int]:
    found: list[int] = []
    def add(value: Any) -> None:
        if isinstance(value, int):
            if 0 < value < 4_300_000_000:
                found.append(value)
        elif isinstance(value, str):
            match = re.fullmatch(r"(?:AS)?(\d+)", value.strip(), re.I)
            if match:
                found.append(int(match.group(1)))
        elif isinstance(value, dict):
            for key in ("asn", "number", "value"):
                if key in value:
                    add(value[key])
    if isinstance(raw, list):
        for item in raw:
            add(item)
    else:
        add(raw)
    return list(dict.fromkeys(found))


def parse_as_path(raw: Any) -> list[int]:
    if isinstance(raw, list):
        values: list[int] = []
        for part in raw:
            if isinstance(part, list):
                values.extend(parse_as_path(part))
            elif isinstance(part, dict):
                values.extend(parse_as_path(part.get("asn") or part.get("value") or part.get("asns")))
            else:
                values.extend(parse_as_path(str(part)))
        return list(dict.fromkeys(values))
    if isinstance(raw, int):
        return [raw] if raw > 0 else []
    if isinstance(raw, str):
        return [int(x) for x in re.findall(r"(?:AS)?(\d+)", raw, re.I) if int(x) > 0]
    return []


def recursive_fields(obj: Any) -> dict[str, Any]:
    """Extract plausible geolocation fields without treating missing data as coordinates."""
    result: dict[str, Any] = {}
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                k = str(key).lower()
                if k in ("latitude", "lat") and isinstance(value, (float, int, str)):
                    try: result.setdefault("lat", float(value))
                    except (ValueError, TypeError): pass
                elif k in ("longitude", "lon", "lng") and isinstance(value, (float, int, str)):
                    try: result.setdefault("lon", float(value))
                    except (ValueError, TypeError): pass
                elif k in ("country", "country_name", "country_code") and isinstance(value, str):
                    result.setdefault("country", value)
                elif k in ("city", "city_name") and isinstance(value, str):
                    result.setdefault("city", value)
                elif k in ("continent", "region") and isinstance(value, str):
                    result.setdefault(k, value)
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(obj)
    if not (-90 <= result.get("lat", 999) <= 90 and -180 <= result.get("lon", 999) <= 180):
        result.pop("lat", None); result.pop("lon", None)
    return result


def find_first(data: dict[str, Any], key: str) -> Any:
    if key in data:
        return data[key]
    return data.get("data", {}).get(key) if isinstance(data.get("data"), dict) else None


def entity_upsert(entity_id: str, kind: str, label: str, **fields: Any) -> None:
    previous = STATE.entities.get(entity_id, {})
    stamp = utcnow()
    item = {
        **previous,
        "id": entity_id,
        "kind": kind,
        "label": label,
        "first_seen": previous.get("first_seen") or stamp,
        "last_seen": stamp,
        "updated_at": stamp,
        **fields,
    }
    STATE.entities[entity_id] = item
    STATE.total_entities = len(STATE.entities)
    STORE.save_entity(item)


def parse_whois_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract a small, non-sensitive IP registration profile from RIPEstat WHOIS data."""
    data = raw.get("data", {}) if isinstance(raw, dict) else {}
    if not isinstance(data, dict):
        data = {}
    attributes: dict[str, list[str]] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            key = node.get("key")
            value = node.get("value")
            if isinstance(key, str) and value is not None:
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if isinstance(item, (str, int, float)):
                        attributes.setdefault(key.strip().lower().replace("_", "-"), []).append(str(item).strip())
            for child in node.values():
                if isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(data.get("records", []))
    walk(data.get("irr_records", []))

    def first(*keys: str) -> str | None:
        for key in keys:
            values = attributes.get(key.lower().replace("_", "-"), [])
            for value in values:
                if value:
                    return value
        return None

    authorities = data.get("authorities", [])
    if not isinstance(authorities, list):
        authorities = [authorities] if authorities else []
    records = data.get("records", [])
    return {
        "registry_network": first("inetnum", "inet6num", "netrange", "cidr"),
        "registry_name": first("netname", "descr"),
        "registry_org": first("org-name", "organisation", "organization"),
        "registry_country": first("country"),
        "registry_status": first("status"),
        "registry_created": first("created", "reg-date"),
        "registry_updated": first("last-modified", "last-updated", "changed"),
        "registry_source": first("source"),
        "registry_authorities": [str(x) for x in authorities if x],
        "registry_query_time": data.get("query_time"),
        "registry_records_count": len(records) if isinstance(records, list) else 0,
    }


def classify_route_freshness(value: Any) -> str:
    if value is None or value == "":
        return "UNKNOWN"
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            dt = datetime.fromtimestamp(float(value), timezone.utc)
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        age = max(0.0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds())
        if age <= 3600: return "RECENT"
        if age <= 86400: return "STALE"
        return "OLD"
    except Exception:
        return "UNKNOWN"


def route_upsert(resource: str, rrc: str, peer: str, path: list[int], prefix: str | None, location: str | None, last_updated: Any) -> None:
    if not path:
        return
    rid = f"{resource}|{rrc}|{peer}|{'-'.join(map(str, path))}"
    STATE.routes[rid] = {
        "id": rid, "resource": resource, "rrc": str(rrc), "peer": str(peer),
        "as_path": path, "prefix": prefix, "collector_location": location,
        "last_updated": last_updated, "observed_at": utcnow(),
        "freshness": classify_route_freshness(last_updated),
    }
    STORE.save_route(STATE.routes[rid])
    STATE.total_routes = len(STATE.routes)
    for asn in path:
        entity_upsert(f"AS{asn}", "asn", f"AS{asn}", asn=asn)


async def geolocate(resource: str) -> dict[str, Any]:
    try:
        raw = await fetch_ripestat("maxmind-geo-lite", {"resource": resource})
        fields = recursive_fields(raw.get("data", raw))
        fields["geo_source"] = "RIPEstat MaxMind GeoLite"
        fields["geo_precision"] = "approximate"
        return fields
    except Exception as exc:
        log.debug("Geo lookup failed for %s: %s", resource, exc)
        return {"geo_source": "unavailable", "geo_precision": "unknown"}


async def enrich_ip_profile(resource: str) -> None:
    """Collect passive registry and reverse-DNS metadata for one public IP."""
    fields: dict[str, Any] = {
        "whois_status": "UNAVAILABLE",
        "rdns_status": "UNAVAILABLE",
        "port_status": "NOT_SCANNED_BY_POLICY",
        "device_status": "NOT_IDENTIFIED",
        "os_status": "NOT_IDENTIFIED",
    }
    try:
        whois_raw = await fetch_ripestat("whois", {"resource": resource})
        whois_fields = parse_whois_metadata(whois_raw)
        fields.update(whois_fields)
        fields["whois_status"] = "AVAILABLE" if whois_fields.get("registry_records_count") else "NO_REGISTRATION_RECORD"
        fields["whois_checked_at"] = utcnow()
    except Exception as exc:
        fields["whois_error"] = str(exc)[:180]
        fields["whois_checked_at"] = utcnow()
        log.debug("WHOIS lookup failed for %s: %s", resource, exc)

    try:
        rdns_raw = await fetch_ripestat("reverse-dns-ip", {"resource": resource})
        rdns_data = rdns_raw.get("data", {}) if isinstance(rdns_raw, dict) else {}
        if not isinstance(rdns_data, dict):
            rdns_data = {}
        ptr = rdns_data.get("result")
        fields["rdns"] = str(ptr).strip().rstrip(".") if isinstance(ptr, str) and ptr.strip() else None
        fields["rdns_error"] = str(rdns_data.get("error") or "")[:180] or None
        fields["rdns_status"] = "FOUND" if fields["rdns"] else "NO_PTR"
        fields["rdns_query_time"] = rdns_data.get("query_time")
        fields["rdns_checked_at"] = utcnow()
    except Exception as exc:
        fields["rdns_error"] = str(exc)[:180]
        fields["rdns_checked_at"] = utcnow()
        log.debug("Reverse DNS lookup failed for %s: %s", resource, exc)

    entity_upsert(f"IP:{resource}", "ip", resource, **fields)


def queue_asn(asn: int, priority: int, reason: str, refresh: bool = False) -> None:
    # No fixed ASN-count ceiling. Previously expanded ASNs are revisited only when due.
    if asn <= 0 or (asn in STATE.asn_expanded and not refresh):
        return
    current = STATE.asn_queue.get(asn)
    if current is None or priority > current.get("priority", 0) or (refresh and not current.get("refresh")):
        STATE.asn_queue[asn] = {
            "asn": asn, "priority": int(priority), "reason": reason,
            "queued_at": utcnow(), "refresh": bool(refresh or (current or {}).get("refresh")),
        }
        if STATE.work_event is not None:
            STATE.work_event.set()


def queue_ip(resource: str, priority: int, reason: str) -> None:
    """Queue a globally routable address for passive RIPEstat metadata lookup only."""
    try:
        parsed = ipaddress.ip_address(resource)
    except ValueError:
        return
    normalized = str(parsed)
    if not parsed.is_global or normalized in STATE.ip_inspected:
        return
    current = STATE.ip_queue.get(normalized)
    if current is None or priority > current.get("priority", 0):
        STATE.ip_queue[normalized] = {
            "ip": normalized, "priority": int(priority), "reason": reason, "queued_at": utcnow(),
        }
        if STATE.work_event is not None:
            STATE.work_event.set()


def queue_prefix_sample(prefix: Any, priority: int, reason: str) -> None:
    """Select one representative public IP from an observed BGP prefix; never enumerate it."""
    try:
        network = ipaddress.ip_network(str(prefix), strict=False)
        if not network.is_global:
            return
        sample = next(network.hosts(), network.network_address)
        queue_ip(str(sample), priority, reason)
    except (ValueError, TypeError):
        return


def queue_stale_asn_refreshes() -> int:
    """Queue known ASNs whose public neighbour graph is due for a refresh."""
    now = time.monotonic()
    interval = CONFIG["asn_refresh_interval_seconds"]
    queued = 0
    for asn, last_seen in list(STATE.asn_last_expanded.items()):
        if now - last_seen >= interval and asn not in STATE.asn_queue:
            queue_asn(asn, 1, "Periodic refresh of public ASN topology", refresh=True)
            queued += 1
    return queued


async def inspect_asn(asn: int, refresh: bool = False) -> None:
    """Expand or refresh one ASN using public RIPEstat topology metadata."""
    already_expanded = asn in STATE.asn_expanded
    if (already_expanded and not refresh) or STATE.safe_mode or (STATE.stop_event and STATE.stop_event.is_set()):
        return
    if not already_expanded:
        STATE.asn_expanded.add(asn)
    STATE.asn_expansion_count += 1
    resource = f"AS{asn}"
    STATE.current_target = resource
    try:
        STATE.workers["resource-scout"].update(status="WORKING", task=f"AS overview: {resource}")
        overview = await fetch_ripestat("as-overview", {"resource": resource})
        odata = overview.get("data", {}) if isinstance(overview, dict) else {}
        holder = odata.get("holder") if isinstance(odata, dict) else None
        announced = odata.get("announced") if isinstance(odata, dict) else None
        entity_upsert(resource, "asn", resource, holder=holder, announced=announced, source="RIPEstat as-overview")
        await STATE.observation("asn-overview", resource, f"Holder: {holder or 'не указан'}; announced: {announced if announced is not None else 'unknown'}", "RIPEstat as-overview", "high", {"holder": holder, "announced": announced})

        if STATE.safe_mode or (STATE.stop_event and STATE.stop_event.is_set()):
            return
        STATE.workers["route-scout"].update(status="WORKING", task=f"ASN neighbours: {resource}")
        neighbours_raw = await fetch_ripestat("asn-neighbours", {"resource": resource, "lod": "0"})
        ndata = neighbours_raw.get("data", {}) if isinstance(neighbours_raw, dict) else {}
        neighbours = ndata.get("neighbours", []) if isinstance(ndata, dict) else []
        parsed = []
        for item in neighbours if isinstance(neighbours, list) else []:
            if not isinstance(item, dict):
                continue
            nums = parse_asns(item.get("asn"))
            if nums:
                try: power = int(item.get("power", item.get("path_count", 0)) or 0)
                except (ValueError, TypeError): power = 0
                parsed.append({"asn": nums[0], "type": item.get("type", "unknown"), "power": power})
        parsed.sort(key=lambda item: item.get("power", 0), reverse=True)
        for item in parsed:
            neighbour = item["asn"]
            entity_upsert(f"AS{neighbour}", "asn", f"AS{neighbour}", discovered_from=resource, relation=item["type"], source="RIPEstat asn-neighbours")
            rid = f"neighbour|{asn}|{neighbour}"
            STATE.routes[rid] = {"id": rid, "kind": "asn-neighbour", "resource": resource, "rrc": "ASN neighbour data", "peer": item["type"], "as_path": [asn, neighbour], "power": item.get("power"), "observed_at": utcnow()}
            STORE.save_route(STATE.routes[rid])
            # Autonomous expansion prioritizes frequent observed neighbours; no fixed ASN count cap.
            queue_asn(neighbour, min(95, max(1, item.get("power", 1))), f"Neighbour of AS{asn}")
        STATE.total_routes = len(STATE.routes)
        STATE.workers["route-scout"].update(status="IDLE", task=f"Найдено соседей: {len(parsed)}", count=STATE.workers["route-scout"]["count"] + len(parsed))
        await STATE.observation("asn-neighbours", resource, f"Публичный RIPE RIS граф: обработано соседей {len(parsed)}", "RIPEstat asn-neighbours", "medium", {"neighbor_count": len(parsed), "refresh": refresh})
        STATE.asn_last_expanded[asn] = time.monotonic()
    except Exception:
        if not already_expanded:
            STATE.asn_expanded.discard(asn)
            STATE.asn_expansion_count = max(0, STATE.asn_expansion_count - 1)
        raise
    finally:
        if STATE.workers["resource-scout"]["status"] == "WORKING":
            STATE.workers["resource-scout"].update(status="IDLE", task="Ожидание")
        if STATE.workers["route-scout"]["status"] == "WORKING":
            STATE.workers["route-scout"].update(status="IDLE", task="Ожидание")


async def process_asn_frontier(max_items: int | None = None) -> int:
    """Process queued ASN work; max_items lets the scheduler interleave discovery."""
    processed = 0
    while not STATE.safe_mode and not (STATE.stop_event and STATE.stop_event.is_set()):
        if max_items is not None and processed >= max_items:
            break
        candidates = list(STATE.asn_queue.values())
        if not candidates:
            break
        candidates.sort(key=lambda item: (item.get("priority", 0), item.get("queued_at", "")), reverse=True)
        selected = candidates[0]
        asn = selected["asn"]
        STATE.asn_queue.pop(asn, None)
        await STATE.event("intelligence", f"Discovery frontier selected AS{asn}: {selected['reason']}", "info")
        try:
            await inspect_asn(asn, refresh=bool(selected.get("refresh")))
            processed += 1
        except PermissionError:
            raise
        except Exception as exc:
            await STATE.event("intelligence", f"ASN expansion AS{asn} failed: {exc}", "warning")
            if "rate limited" in str(exc).lower():
                queue_asn(asn, int(selected.get("priority", 1)), "Retry after RIPEstat backoff")
                break
    return processed


async def inspect_resource(resource: str, discovery_only: bool = False) -> None:
    if STATE.safe_mode or STATE.stop_event and STATE.stop_event.is_set():
        return
    STATE.current_target = resource
    STATE.workers["discovery-scout"].update(status="WORKING", task=f"RIPEstat network-info: {resource}")
    await STATE.event("movement", f"Зонд исследует публичные сведения о {resource}", "info")
    net = await fetch_ripestat("network-info", {"resource": resource})
    data = net.get("data", {})
    prefix = data.get("prefix") if isinstance(data, dict) else None
    asns = parse_asns(data.get("asns") if isinstance(data, dict) else None)
    entity_upsert(f"IP:{resource}", "ip", resource, prefix=prefix, asns=asns, source="RIPEstat network-info", status="OBSERVED")
    if prefix:
        entity_upsert(f"PREFIX:{prefix}", "prefix", prefix, asns=asns, source="RIPEstat network-info")
    for asn in asns:
        entity_upsert(f"AS{asn}", "asn", f"AS{asn}", asn=asn, prefix=prefix, source="RIPEstat network-info")
        queue_asn(asn, 100, f"Origin ASN from {resource}")
    queue_ip(resource, 100, "Seed IP candidate" if discovery_only else "IP observed during enrichment")
    if prefix:
        queue_prefix_sample(prefix, 90, f"Representative IP from network-info prefix {prefix}")
    STATE.workers["discovery-scout"].update(status="IDLE", task=f"Обработан {resource}", count=STATE.workers["discovery-scout"]["count"] + 1)
    await STATE.observation("network-info", resource, f"Префикс: {prefix or 'не найден'}; ASN: {', '.join('AS'+str(x) for x in asns) or 'нет данных'}", "RIPEstat network-info", "high", {"prefix": prefix, "asns": asns})

    if discovery_only:
        STATE.progress = f"IP discovery complete for {resource}; waiting for host reachability sweep"
        return

    if STATE.safe_mode or STATE.stop_event and STATE.stop_event.is_set():
        return
    STATE.workers["route-scout"].update(status="WORKING", task=f"BGP Looking Glass: {resource}")
    lg = await fetch_ripestat("looking-glass", {"resource": resource, "look_back_limit": "86400"})
    lg_data = lg.get("data", {})
    rrcs = lg_data.get("rrcs", []) if isinstance(lg_data, dict) else []
    route_count = 0
    for collector in rrcs:
        if not isinstance(collector, dict):
            continue
        rrc = collector.get("rrc", "unknown")
        location = collector.get("location")
        for peer in (collector.get("peers") or []):
            if not isinstance(peer, dict):
                continue
            path = parse_as_path(peer.get("as_path"))
            if path:
                observed_prefix = peer.get("prefix") or prefix
                route_upsert(resource, rrc, peer.get("peer", "unknown"), path, observed_prefix, location, peer.get("last_updated") or peer.get("latest_time") or peer.get("lastest_time"))
                if observed_prefix:
                    queue_prefix_sample(observed_prefix, 25, f"Representative address from BGP prefix {observed_prefix}")
                for path_asn in path:
                    queue_asn(path_asn, 15, f"Observed in BGP AS_PATH for {resource}")
                route_count += 1
    STATE.workers["route-scout"].update(status="IDLE", task=f"Получено BGP-путей: {route_count}", count=STATE.workers["route-scout"]["count"] + route_count)
    await STATE.observation("bgp-route", resource, f"RIPE RIS Looking Glass: {route_count} путей из {len(rrcs)} коллекторов", "RIPEstat looking-glass", "high" if route_count else "low", {"routes": route_count, "collectors": len(rrcs)})

    if STATE.safe_mode or STATE.stop_event and STATE.stop_event.is_set():
        return
    STATE.workers["geo-scout"].update(status="WORKING", task=f"Приблизительная геолокация {resource}")
    geo = await geolocate(resource)
    if any(geo.get(key) for key in ("city", "country", "continent", "region", "lat", "lon")):
        # Keep textual GeoIP metadata even when the provider supplies no coordinates.
        entity_upsert(f"IP:{resource}", "ip", resource, **geo)
        place = ", ".join(x for x in (geo.get("city"), geo.get("region"), geo.get("country")) if x)
        summary = f"Приблизительная геопривязка: {place or 'географические метаданные без названия места'}"
        if not ("lat" in geo and "lon" in geo):
            summary += " (координаты не предоставлены)"
        await STATE.observation("geolocation", resource, summary, "RIPEstat MaxMind GeoLite", "medium" if place else "low", geo)
    else:
        entity_upsert(f"IP:{resource}", "ip", resource, **geo)
        await STATE.observation("geolocation", resource, "Публичный источник не вернул ни координаты, ни страну/город", "RIPEstat MaxMind GeoLite", "low", geo)
    STATE.workers["geo-scout"].update(status="IDLE", task="GeoLite enrichment complete", count=STATE.workers["geo-scout"]["count"] + 1)
    await enrich_ip_profile(resource)
    await intelligence_analyze(resource, prefix, asns, route_count)
    STATE.ip_inspected.add(str(ipaddress.ip_address(resource)))


async def process_ip_frontier(max_items: int | None = None) -> int:
    """Inspect representative public IPs; max_items yields fairly to periodic discovery."""
    processed = 0
    while STATE.ip_queue and not STATE.safe_mode and not (STATE.stop_event and STATE.stop_event.is_set()):
        if max_items is not None and processed >= max_items:
            break
        candidates = list(STATE.ip_queue.values())
        candidates.sort(key=lambda item: (item.get("priority", 0), item.get("queued_at", "")), reverse=True)
        selected = candidates[0]
        resource = selected["ip"]
        STATE.ip_queue.pop(resource, None)
        if resource in STATE.ip_inspected:
            continue
        await STATE.event("discovery", f"New public IP candidate {resource}: {selected['reason']}", "info")
        try:
            await inspect_resource(resource)
            processed += 1
        except PermissionError:
            raise
        except Exception as exc:
            await STATE.event("discovery", f"IP metadata lookup {resource} failed: {exc}", "warning")
            if "rate limited" in str(exc).lower():
                queue_ip(resource, int(selected.get("priority", 1)), "Retry after RIPEstat backoff")
                break
    return processed


async def intelligence_analyze(resource: str, prefix: str | None, asns: list[int], route_count: int) -> None:
    """Deterministic, evidence-backed reasoning. No model can issue network calls."""
    findings = []
    if len(asns) > 1:
        findings.append(("routing", f"Для {resource} RIPEstat показывает несколько origin ASN: {asns}", "medium"))
    if route_count > 1:
        lengths = [len(x["as_path"]) for x in STATE.routes.values() if x["resource"] == resource]
        if lengths:
            findings.append(("topology", f"Для {resource} получено {route_count} BGP-путей; длина AS_PATH от {min(lengths)} до {max(lengths)}", "medium"))
    if prefix and asns:
        findings.append(("hypothesis", f"Следующее исследование: сверить объявления префикса {prefix} и origin AS{asns[0]} по независимому источнику", "low"))
    for category, message, confidence in findings:
        await STATE.observation(category, resource, message, "NOMAD Intelligence Engine", confidence)
        await STATE.event("intelligence", message, "info")


def correlate_network_evidence() -> list[dict[str, Any]]:
    """Explainable correlation; scores evidence completeness, not probability of truth."""
    entities = list(STATE.entities.values())
    routes = list(STATE.routes.values())
    active = list(STATE.active_results)
    findings: list[dict[str, Any]] = []
    for entity in entities:
        kind = entity.get("kind")
        key = str(entity.get("id") or entity.get("label") or "")
        evidence: list[str] = []
        facts: list[str] = []
        score = 0
        if kind == "asn":
            try:
                asn = int(entity.get("asn") or key.upper().removeprefix("AS"))
            except (TypeError, ValueError):
                continue
            holder = entity.get("holder")
            origins = [e for e in entities if e.get("kind") == "ip" and asn in (e.get("asns") or [])]
            neighbours = [r for r in routes if r.get("kind") == "asn-neighbour" and asn in (r.get("as_path") or [])]
            paths = [r for r in routes if asn in (r.get("as_path") or []) and r.get("kind") != "asn-neighbour"]
            if holder:
                score += 35; evidence.append("RIPEstat AS overview holder"); facts.append("Holder: " + str(holder))
            if origins:
                score += 30; evidence.append("IP network-info origin association"); facts.append(str(len(origins)) + " observed IP metadata record(s)")
            if neighbours:
                score += 20; evidence.append("RIPEstat ASN neighbour graph"); facts.append(str(len(neighbours)) + " neighbour edges")
            if paths:
                score += 15; evidence.append("RIPE RIS AS_PATH observations"); facts.append(str(len(paths)) + " BGP path(s)")
            findings.append({"id": key, "kind": "organization", "label": holder or "AS" + str(asn),
                             "score": min(100, score), "evidence": evidence or ["ASN identifier only"], "facts": facts,
                             "assessment": "Evidence completeness; not proof of asset ownership."})
        elif kind == "prefix":
            prefix = str(entity.get("prefix") or entity.get("label") or "")
            ip_records = [e for e in entities if e.get("kind") == "ip" and e.get("prefix") == prefix]
            route_records = [r for r in routes if r.get("prefix") == prefix]
            asns = entity.get("asns") or []
            if entity.get("source"):
                score += 25; evidence.append(str(entity.get("source")))
            if asns:
                score += 25; evidence.append("Origin ASN metadata"); facts.append("Origin ASN(s): " + ", ".join("AS" + str(n) for n in asns))
            if ip_records:
                score += 25; evidence.append("Observed IP-to-prefix association"); facts.append(str(len(ip_records)) + " sampled IP(s), not full enumeration")
            if route_records:
                score += 25; evidence.append("BGP route observation"); facts.append(str(len(route_records)) + " route record(s)")
            if len(set(asns)) > 1:
                facts.append("Multiple origin ASN values; verify multi-origin routing.")
            findings.append({"id": key, "kind": "prefix", "label": prefix, "score": min(100, score),
                             "evidence": evidence or ["Prefix metadata only"], "facts": facts,
                             "assessment": "Observed route prefix; not a complete host inventory."})
        elif kind in ("ip", "lan-host", "hop"):
            address = str(entity.get("ip") or entity.get("label") or "")
            asns = entity.get("asns") or []
            if "network-info" in str(entity.get("source") or ""):
                score += 40; evidence.append("RIPEstat network-info")
            if entity.get("prefix"):
                score += 20; evidence.append("Prefix association")
            if asns:
                score += 20; evidence.append("Origin ASN association")
            if entity.get("country") or entity.get("city") or entity.get("geo_source"):
                score += 10; evidence.append("Approximate GeoLite metadata")
            if entity.get("mac"):
                score += 40; evidence.append("Local ARP response / MAC address")
                facts.append("MAC: " + str(entity["mac"]) + "; vendor label is not authoritative.")
            if kind == "hop" and entity.get("target"):
                score += 30; evidence.append("User-triggered traceroute response")
                facts.append("Hop on trace to " + str(entity["target"]))
            ping_result = next((r for r in active if r.get("method") == "ping" and r.get("target") == address), None)
            if ping_result:
                score += 10; evidence.append("User-triggered ICMP ping")
                facts.append("Latest ping: " + str(ping_result.get("status")))
            findings.append({"id": key, "kind": kind, "label": address, "score": min(100, score),
                             "evidence": evidence or ["Address identifier only"], "facts": facts,
                             "assessment": "Observed address; no open-port or device-model inference."})
    return sorted(findings, key=lambda item: (item["score"], item["kind"], item["label"]), reverse=True)[:200]


async def run_traceroute(target: str) -> dict[str, Any]:
    """Optional low-rate trace to a literal IP explicitly configured by user.
    This function never accepts targets from HTTP/API requests.
    """
    trace_cfg = CONFIG["traceroute"]
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise PermissionError("Traceroute target must be an IP literal")
    if not ip.is_global or str(ip) not in trace_cfg["approved_targets"]:
        STATE.total_denied += 1
        raise PermissionError("Traceroute target is not in the approved local config")
    if not trace_cfg["enabled"]:
        raise PermissionError("Traceroute is disabled in config.json")
    now = time.monotonic()
    last = STATE.last_trace_at.get(target, 0)
    if now - last < trace_cfg["interval_seconds"]:
        raise RuntimeError("Traceroute rate limit: wait before next run")
    STATE.last_trace_at[target] = now
    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", "-d", "-h", str(trace_cfg["max_hops"]), "-w", "1000", str(ip)]
    else:
        exe = shutil.which("traceroute")
        if not exe:
            raise RuntimeError("traceroute command is not installed")
        cmd = [exe, "-n", "-m", str(trace_cfg["max_hops"]), "-q", "1", "-w", "1", str(ip)]
    STATE.workers["route-scout"].update(status="WORKING", task=f"Traceroute to approved target {ip}")
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=trace_cfg["timeout_seconds"])
    except asyncio.TimeoutError:
        proc.kill(); await proc.communicate()
        raise RuntimeError("Traceroute timed out")
    text = stdout.decode(errors="replace")[:20000]
    hops = []
    for line in text.splitlines():
        hop_match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not hop_match:
            continue
        hop_no, tail = int(hop_match.group(1)), hop_match.group(2)
        found = None
        for candidate in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}", tail):
            try:
                addr = ipaddress.ip_address(candidate)
                if not (addr.is_multicast or addr.is_unspecified or addr.is_loopback):
                    found = str(addr); break
            except ValueError:
                continue
        times = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", tail)]
        hops.append({"hop": hop_no, "ip": found, "rtt_ms": times[0] if times else None, "status": "RESPONDED" if found else "NO_RESPONSE"})
    result = {"target": str(ip), "time": utcnow(), "hops": hops, "raw_excerpt": text[-2000:], "method": "system traceroute/tracert", "scope": "manually approved IP literal"}
    STATE.routes[f"trace|{ip}"] = {"id": f"trace|{ip}", "kind": "traceroute", "target": str(ip),
                                  "resource": str(ip), "hops": hops, "freshness": "LIVE",
                                  "observed_at": utcnow(), "method": "local traceroute"}
    STORE.save_route(STATE.routes[f"trace|{ip}"])
    STATE.total_routes = len(STATE.routes)
    for hop in hops:
        if hop.get("ip"):
            entity_upsert(f"TRACE:{ip}:{hop['hop']}", "hop", f"Hop {hop['hop']} · {hop['ip']}",
                          ip=hop["ip"], target=str(ip), rtt_ms=hop.get("rtt_ms"),
                          source="local traceroute", status=hop.get("status"))
    STATE.observations.appendleft({"id": str(uuid.uuid4())[:8], "time": utcnow(), "category": "active-route", "subject": str(ip), "summary": f"Traceroute: {sum(1 for h in hops if h['ip'])}/{len(hops)} отвечающих hop", "source": "local traceroute", "confidence": "medium", "extra": result})
    _remember_active_result({"id": str(uuid.uuid4())[:8], "time": utcnow(), "method": "traceroute", **result})
    STATE.workers["route-scout"].update(status="IDLE", task=f"Traceroute завершён: {ip}", count=STATE.workers["route-scout"]["count"] + 1)
    return result


def _remember_active_result(result: dict[str, Any]) -> None:
    STATE.active_results.appendleft(result)
    STORE.save_active_result(result)


async def run_ping(target: str) -> dict[str, Any]:
    cfg = CONFIG["ping"]
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise PermissionError("Ping target must be an IP literal") from exc
    canonical = str(address)
    if not cfg["enabled"] or canonical not in cfg["approved_targets"]:
        STATE.total_denied += 1
        raise PermissionError("Ping target is not enabled and explicitly allowlisted in config.json")
    if not (address.is_global or address.is_private) or address.is_loopback or address.is_link_local:
        raise PermissionError("Ping target outside permitted public/private unicast scope")
    now = time.monotonic()
    if now - STATE.last_ping_at.get(canonical, 0) < cfg["interval_seconds"]:
        raise RuntimeError("Ping rate limit: wait before retrying this target")
    STATE.last_ping_at[canonical] = now
    exe = shutil.which("ping")
    if not exe:
        raise RuntimeError("System ping command is not installed")
    cmd = [exe, "-n", "-c", "3", "-W", "2", canonical] if platform.system().lower() != "windows" else [exe, "-n", "3", "-w", "1500", canonical]
    STATE.current_target = canonical
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=cfg["timeout_seconds"])
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RuntimeError("Ping timed out")
        raw = stdout.decode(errors="replace")[:8000]
        loss = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s*packet loss", raw, re.I)
        rtt = re.search(r"(?:rtt|round-trip).*?=\s*[\d.]+/([\d.]+)/", raw, re.I)
        if not rtt:
            rtt = re.search(r"Average\s*=\s*([\d.]+)\s*ms", raw, re.I)
        result = {"id": str(uuid.uuid4())[:8], "time": utcnow(), "method": "ping", "target": canonical,
                  "status": "REACHABLE" if proc.returncode == 0 else "NO_REPLY",
                  "packet_loss_percent": float(loss.group(1)) if loss else (0.0 if proc.returncode == 0 else None),
                  "average_rtt_ms": float(rtt.group(1)) if rtt else None, "return_code": proc.returncode,
                  "raw_excerpt": raw[-1500:], "scope": "allowlisted IP; three ICMP echo requests"}
        _remember_active_result(result)
        entity_upsert("IP:" + canonical, "ip", canonical, ip=canonical, active_ping=result["status"])
        await STATE.observation("active-ping", canonical, "ICMP result: " + result["status"], "local ping", "medium", result)
        await STATE.event("active-probe", "Ping " + canonical + ": " + result["status"], "info" if proc.returncode == 0 else "warning")
        return result
    finally:
        STATE.current_target = None


async def run_authorized_host_scan() -> dict[str, Any]:
    """Ping approved public IPv4 targets in 100-address batches; enrich live hosts serially."""
    cfg = CONFIG["host_scan"]
    networks = [ipaddress.ip_network(value, strict=False) for value in cfg["approved_subnets"]]
    if not cfg["enabled"] or not networks:
        STATE.host_scan.update(
            status="SKIPPED", stage="idle", active=False,
            message="Host sweep disabled or no approved public CIDR configured",
            current=None, finished_at=utcnow(),
        )
        return dict(STATE.host_scan)

    targets: list[str] = []
    for network in networks:
        if not isinstance(network, ipaddress.IPv4Network) or not network.is_global or network.num_addresses > 256:
            raise PermissionError(f"Host sweep refused unsafe range: {network}")
        targets.extend(str(address) for address in network.hosts())
    targets = list(dict.fromkeys(targets))[:1000]
    if not targets:
        raise RuntimeError("Approved host sweep ranges contain no usable addresses")

    batch_size = 100
    batch_total = (len(targets) + batch_size - 1) // batch_size
    semaphore_limit = max(1, min(32, int(cfg["concurrency"])))
    alive_hosts: list[str] = []
    enriched_total = 0
    STATE.host_scan = {
        "status": "RUNNING", "stage": "batch_queue", "active": True,
        "queue_completed": 0, "queue_total": len(targets),
        "batch_index": 0, "batch_total": batch_total, "batch_size": batch_size,
        "completed": 0, "total": 0, "alive": 0, "unreachable": 0,
        "enrichment_completed": 0, "enrichment_total": 0, "enriched_total": 0,
        "current": "ICMP target queue · " + ", ".join(str(n) for n in networks),
        "message": f"Очередь: {len(targets)} разрешённых IP; обработка пакетами по 100",
        "started_at": utcnow(), "finished_at": None, "error": None,
        "concurrency": semaphore_limit, "ranges": [str(n) for n in networks],
    }
    await STATE.event("host-scan", f"Пакетный ICMP sweep: {len(targets)} разрешённых адресов, пакетов: {batch_total}", "info")
    exe = shutil.which("ping")
    if not exe:
        STATE.host_scan.update(status="ERROR", stage="error", active=False, error="System ping command is not installed", finished_at=utcnow())
        raise RuntimeError("System ping command is not installed")

    try:
        for batch_index, offset in enumerate(range(0, len(targets), batch_size), 1):
            if STATE.stop_event and STATE.stop_event.is_set():
                break
            batch_targets = targets[offset:offset + batch_size]
            batch_alive: list[str] = []
            STATE.host_scan.update(
                stage="ping_sweep", batch_index=batch_index,
                completed=0, total=len(batch_targets),
                enrichment_completed=0, enrichment_total=0,
                current=f"ICMP · batch {batch_index}/{batch_total}",
                message=f"Пакет {batch_index}/{batch_total}: ping {len(batch_targets)} IP",
            )
            await HUB.publish({"type": "snapshot", "data": snapshot()})
            semaphore = asyncio.Semaphore(semaphore_limit)

            async def probe_one(address: str) -> None:
                async with semaphore:
                    if STATE.stop_event and STATE.stop_event.is_set():
                        return
                    system_name = platform.system().lower()
                    if system_name == "windows":
                        command = [exe, "-n", "1", "-w", str(int(cfg["timeout_seconds"] * 1000)), address]
                    elif system_name == "darwin":
                        command = [exe, "-n", "-c", "1", "-W", "1000", address]
                    else:
                        command = [exe, "-n", "-c", "1", "-W", "1", address]
                    reachable = False
                    raw = ""
                    STATE.current_target = address
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *command, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.STDOUT,
                        )
                        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=cfg["timeout_seconds"])
                        raw = stdout.decode(errors="replace")[-600:]
                        reachable = proc.returncode == 0
                    except asyncio.TimeoutError:
                        try:
                            proc.kill()
                            await proc.communicate()
                        except Exception:
                            pass
                    except Exception as exc:
                        raw = f"{type(exc).__name__}: {exc}"

                    stamp = utcnow()
                    result = {
                        "id": str(uuid.uuid4())[:8], "time": stamp,
                        "method": "host-sweep-ping", "target": address,
                        "status": "REACHABLE" if reachable else "NO_REPLY",
                        "return_code": 0 if reachable else None,
                        "scope": "explicitly approved public IPv4 CIDR; one ICMP echo request",
                        "raw_excerpt": raw,
                    }
                    _remember_active_result(result)
                    if reachable:
                        batch_alive.append(address)
                        alive_hosts.append(address)
                        entity_upsert("IP:" + address, "ip", address, ip=address, active_ping="REACHABLE",
                                      host_sweep_seen_at=stamp, host_sweep_source="allowlisted ICMP sweep")
                    STATE.host_scan["completed"] += 1
                    STATE.host_scan["queue_completed"] = min(
                        len(targets), offset + STATE.host_scan["completed"]
                    )
                    STATE.host_scan["alive"] = len(alive_hosts)
                    STATE.host_scan["unreachable"] = STATE.host_scan["queue_completed"] - len(alive_hosts)
                    STATE.host_scan["current"] = address
                    if (STATE.host_scan["completed"] == len(batch_targets)
                            or STATE.host_scan["completed"] % 4 == 0):
                        await HUB.publish({"type": "snapshot", "data": snapshot()})

            await asyncio.gather(*(probe_one(address) for address in batch_targets))
            if STATE.stop_event and STATE.stop_event.is_set():
                break

            batch_alive.sort(key=lambda value: int(ipaddress.ip_address(value)))
            STATE.host_scan.update(
                stage="enrichment", enrichment_completed=0,
                enrichment_total=len(batch_alive),
                current=batch_alive[0] if batch_alive else None,
                message=f"Пакет {batch_index}/{batch_total}: ping завершён; живых IP {len(batch_alive)}; последовательное обогащение",
            )
            await HUB.publish({"type": "snapshot", "data": snapshot()})

            # Deliberately serial: one live target is completed before the next.
            for index, address in enumerate(batch_alive, 1):
                if STATE.stop_event and STATE.stop_event.is_set():
                    break
                STATE.current_target = address
                STATE.host_scan["current"] = address
                STATE.host_scan["message"] = f"Пакет {batch_index}/{batch_total}: обработка живого IP {index}/{len(batch_alive)}"
                try:
                    if address not in STATE.ip_inspected:
                        await inspect_resource(address)
                except Exception as exc:
                    await STATE.event("host-scan", f"Enrichment failed for {address}: {exc}", "warning")
                STATE.host_scan["enrichment_completed"] = index
                enriched_total += 1
                STATE.host_scan["enriched_total"] = enriched_total
                await HUB.publish({"type": "snapshot", "data": snapshot()})

            if STATE.stop_event and STATE.stop_event.is_set():
                break
            STATE.current_target = None
            STATE.host_scan.update(
                stage="batch_complete", current=None,
                message=f"Пакет {batch_index}/{batch_total} завершён: проверено {len(batch_targets)}, живых {len(batch_alive)}",
            )
            await HUB.publish({"type": "snapshot", "data": snapshot()})

        stopped = bool(STATE.stop_event and STATE.stop_event.is_set())
        live_set = set(alive_hosts)
        # Keep only responsive addresses from approved ranges in the subsequent IP frontier.
        STATE.ip_queue = {
            address: item for address, item in STATE.ip_queue.items()
            if address in live_set and address not in STATE.ip_inspected
        }
        STATE.current_target = None
        if stopped:
            STATE.host_scan.update(
                status="STOPPED", stage="stopped", active=False, current=None,
                message=f"Остановлено: проверено {STATE.host_scan['queue_completed']}/{len(targets)} IP; живых {len(alive_hosts)}",
                finished_at=utcnow(),
            )
        else:
            STATE.host_scan.update(
                status="COMPLETE", stage="complete", active=False, current=None,
                queue_completed=len(targets),
                message=f"Готово: проверено {len(targets)} IP пакетами по 100; живых {len(alive_hosts)}, обогащено {enriched_total}",
                finished_at=utcnow(),
            )
        await STATE.event("host-scan", STATE.host_scan["message"], "info")
        await HUB.publish({"type": "snapshot", "data": snapshot()})
        return dict(STATE.host_scan)
    except Exception as exc:
        STATE.current_target = None
        STATE.host_scan.update(status="ERROR", stage="error", active=False,
                               error=f"{type(exc).__name__}: {exc}", message="Host sweep failed",
                               finished_at=utcnow())
        await STATE.event("host-scan", f"Host sweep failed: {exc}", "warning")
        raise

async def run_arp_scan(subnet: str) -> dict[str, Any]:
    cfg = CONFIG["arp_scan"]
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise PermissionError("ARP target must be a CIDR literal") from exc
    if not cfg["enabled"] or str(network) not in cfg["approved_subnets"]:
        STATE.total_denied += 1
        raise PermissionError("ARP subnet is not enabled and explicitly allowlisted in config.json")
    if not isinstance(network, ipaddress.IPv4Network) or not any(network.subnet_of(base) for base in RFC1918_RANGES) or network.prefixlen < 24 or network.num_addresses > 256:
        raise PermissionError("ARP is restricted to approved private IPv4 /24 or smaller subnets")
    interface = cfg.get("interface") or ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise PermissionError("Set arp_scan.interface to a local interface before ARP scanning")
    now = time.monotonic()
    if now - STATE.last_arp_at.get(str(network), 0) < cfg["interval_seconds"]:
        raise RuntimeError("ARP scan rate limit: wait before retrying this subnet")
    STATE.last_arp_at[str(network)] = now
    exe = shutil.which("arp-scan")
    if not exe:
        raise RuntimeError("arp-scan is not installed; install the arp-scan package on Linux")
    cmd = [exe, "--interface", interface, "--plain", "--retry=1", "--timeout=500", str(network)]
    STATE.current_target = str(network)
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=cfg["timeout_seconds"])
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RuntimeError("ARP scan timed out")
        raw = stdout.decode(errors="replace")[:16000]
        if proc.returncode != 0:
            raise RuntimeError("arp-scan failed; check interface, permissions and local link: " + raw[-500:])
        hosts = []
        for line in raw.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) < 2 or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", parts[1]):
                continue
            try:
                address = ipaddress.IPv4Address(parts[0])
            except ValueError:
                continue
            if address not in network:
                continue
            host = {"ip": str(address), "mac": parts[1].lower(), "vendor": parts[2] if len(parts) > 2 else "Unknown"}
            hosts.append(host)
            entity_upsert("LAN:" + str(address), "lan-host", str(address), ip=str(address), mac=host["mac"],
                          vendor=host["vendor"], prefix=str(network), source="local arp-scan",
                          scope="explicitly approved local LAN")
        result = {"id": str(uuid.uuid4())[:8], "time": utcnow(), "method": "arp-scan", "target": str(network),
                  "interface": interface, "status": "COMPLETE", "hosts_found": len(hosts), "hosts": hosts,
                  "raw_excerpt": raw[-2000:], "scope": "approved private IPv4 local subnet"}
        _remember_active_result(result)
        await STATE.observation("active-arp", str(network), "ARP discovered " + str(len(hosts)) + " local IP/MAC pairs", "local arp-scan", "high", result)
        await STATE.event("active-probe", "ARP " + str(network) + ": " + str(len(hosts)) + " hosts", "info")
        return result
    finally:
        STATE.current_target = None


async def optional_trace_cycle() -> None:
    cfg = CONFIG["traceroute"]
    if not cfg["enabled"] or not cfg["approved_targets"]:
        return
    for target in cfg["approved_targets"]:
        if STATE.stop_event and STATE.stop_event.is_set():
            break
        if time.monotonic() - STATE.last_trace_at.get(target, 0) < cfg["interval_seconds"]:
            continue
        try:
            result = await run_traceroute(target)
            STATE.routes[f"trace|{target}"] = {"id": f"trace|{target}", "kind": "traceroute", "freshness": "LIVE", **result}
            STORE.save_route(STATE.routes[f"trace|{target}"])
            STATE.total_routes = len(STATE.routes)
            await STATE.event("route", f"Traceroute завершён для {target}", "info")
            # Geo lookup each responding public hop within the explicitly approved trace.
            count = 0
            for hop in result["hops"]:
                if STATE.safe_mode:
                    break
                if hop.get("ip"):
                    geo = await geolocate(hop["ip"])
                    if "lat" in geo:
                        entity_upsert(f"TRACE:{target}:{hop['hop']}", "hop", f"Hop {hop['hop']} · {hop['ip']}", ip=hop["ip"], **geo)
                    count += 1
        except Exception as exc:
            await STATE.event("route", f"Traceroute {target}: {exc}", "warning")


async def scan_cycle(drain_frontiers: bool = True, discovery_only: bool = False) -> None:
    """Discover seed IPs first; optional later phases enrich or drain the frontier."""
    if STATE.safe_mode:
        return
    if not CONFIG["seeds"]:
        await STATE.event("system", "В config.json нет публичных seed-адресов.", "warning")
        return
    STATE.state = "RUNNING"
    STATE.last_heartbeat = time.time()
    STATE.progress = "Discovery Scout: обновление публичных сетевых данных"
    STATE.discovery_progress = {
        "status": "RUNNING", "active": True, "completed": 0, "total": len(CONFIG["seeds"]),
        "current": None, "message": "Fast IP discovery: RIPEstat network-info",
    }
    await STATE.event("discovery", "Начат проход discovery по seed-адресам", "info")
    errors = 0
    for index, resource in enumerate(CONFIG["seeds"], 1):
        if STATE.safe_mode or STATE.stop_event and STATE.stop_event.is_set():
            break
        STATE.discovery_progress["current"] = resource
        STATE.current_target = resource
        try:
            await inspect_resource(resource, discovery_only=discovery_only)
        except PermissionError as exc:
            errors += 1
            await STATE.event("policy", str(exc), "warning")
            if STATE.safe_mode:
                break
        except Exception as exc:
            errors += 1
            STATE.source_status["RIPEstat"] = {"status": "DEGRADED", "checked_at": utcnow(), "message": str(exc)[:240]}
            await STATE.event("source", f"Ошибка источника для {resource}: {exc}", "warning")
            if "rate limited" in str(exc).lower():
                break
        STATE.discovery_progress["completed"] = index
        STATE.discovery_progress["message"] = f"IP discovery {index}/{len(CONFIG['seeds'])}"
        await HUB.publish({"type": "snapshot", "data": snapshot()})
        STATE.last_heartbeat = time.time()
    STATE.discovery_progress.update(
        status="STOPPED" if STATE.stop_event and STATE.stop_event.is_set() else "COMPLETE",
        active=False, current=None,
        message=f"IP discovery complete: {STATE.discovery_progress['completed']}/{STATE.discovery_progress['total']} seed IPs",
    )
    if drain_frontiers and not STATE.safe_mode and not (STATE.stop_event and STATE.stop_event.is_set()):
        try:
            await process_ip_frontier()
        except PermissionError as exc:
            errors += 1
            await STATE.event("policy", str(exc), "warning")
        queue_stale_asn_refreshes()
        try:
            await process_asn_frontier()
        except PermissionError as exc:
            errors += 1
            await STATE.event("policy", str(exc), "warning")
    # Traceroute is deliberately not part of the continuous discovery loop.
    # It is invoked only by the explicit local /api/active/traceroute action.
    STATE.cycle_count += 1
    STATE.last_cycle = utcnow()
    STATE.current_target = None
    STATE.progress = ("Проход discovery завершён; непрерывный мониторинг продолжается"
                      if not errors else f"Проход discovery завершён с ошибками: {errors}; мониторинг продолжается")
    for worker in STATE.workers.values():
        if worker["status"] == "WORKING":
            worker["status"] = "IDLE"
            worker["task"] = "Ожидание новых данных"
    await STATE.event("discovery", f"Проход завершён; ошибок: {errors}. Следующий проход будет выполнен автоматически.", "info" if errors == 0 else "warning")
    await HUB.publish({"type": "snapshot", "data": snapshot()})


async def worker_loop() -> None:
    """Resilient fair scheduler: periodic discovery interleaved with small frontier batches."""
    STATE.state = "RUNNING"
    STATE.started_at = utcnow()
    STATE.stop_event = STATE.stop_event or asyncio.Event()
    STATE.work_event = asyncio.Event()
    next_discovery_at = time.monotonic()
    STATE.next_discovery_at = next_discovery_at
    await STATE.event("system", "NOMAD started: continuous discovery scheduler active", "success")
    try:
        while not STATE.safe_mode and not STATE.stop_event.is_set():
            try:
                STATE.last_heartbeat = time.time()
                now = time.monotonic()

                # A 429 backoff is handled without blocking the coordinator in a long await.
                if STATE.api_backoff_until > now:
                    next_discovery_at = max(next_discovery_at, STATE.api_backoff_until)
                    remaining_backoff = max(0, int(STATE.api_backoff_until - now))
                    STATE.state = "MONITORING"
                    STATE.progress = f"RIPEstat rate-limit backoff · {remaining_backoff} с; локальные процессы контролируются"
                else:
                    # Refresh seed observations independently of backlog size.
                    if now >= next_discovery_at:
                        await scan_cycle(drain_frontiers=False, discovery_only=True)
                        if not STATE.host_scan_bootstrap_done:
                            try:
                                await run_authorized_host_scan()
                            except Exception as exc:
                                await STATE.event("host-scan", f"Initial host sweep could not complete: {exc}", "warning")
                            finally:
                                STATE.host_scan_bootstrap_done = True
                        next_discovery_at = time.monotonic() + CONFIG["discovery_interval_seconds"]
                        if STATE.api_backoff_until > time.monotonic():
                            next_discovery_at = max(next_discovery_at, STATE.api_backoff_until)
                        STATE.next_discovery_at = next_discovery_at

                    if STATE.safe_mode or STATE.stop_event.is_set():
                        break

                    queue_stale_asn_refreshes()
                    did_work = False
                    # IP candidates take priority; ASN graph expansion yields when IP work is queued.
                    did_work = (await process_ip_frontier(max_items=4)) > 0 or did_work
                    if not STATE.ip_queue:
                        did_work = (await process_asn_frontier(max_items=1)) > 0 or did_work
                    STATE.state = "RUNNING" if did_work else "MONITORING"
                    remaining = max(0, int(next_discovery_at - time.monotonic()))
                    STATE.progress = (
                        f"Обработка очереди · IP {len(STATE.ip_queue)} · ASN {len(STATE.asn_queue)} · discovery через {remaining} с"
                        if did_work or STATE.ip_queue or STATE.asn_queue
                        else f"MONITORING · следующий discovery через {remaining} с · зонды живы"
                    )

                restarted = await asyncio.to_thread(PROBES.reconcile)
                if restarted:
                    await STATE.event("supervisor", f"Перезапущены аварийно завершившиеся процессы: {', '.join(restarted)}", "warning")
                STATE.next_discovery_at = next_discovery_at
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                STATE.scheduler_errors += 1
                STATE.state = "MONITORING"
                STATE.progress = f"Ошибка задания; supervisor продолжает работу: {str(exc)[:140]}"
                await STATE.event("supervisor", f"Ошибка одного оборота scheduler; работа продолжается: {exc}", "warning")
                log.exception("NOMAD scheduler iteration failed; continuing")
                # Retry a discovery pass soon, but do not spin at 100% CPU on a persistent fault.
                next_discovery_at = min(next_discovery_at, time.monotonic() + 5.0)
                STATE.next_discovery_at = next_discovery_at

            if STATE.safe_mode or STATE.stop_event.is_set():
                break
            timeout = min(1.0, max(0.05, next_discovery_at - time.monotonic()))
            try:
                await asyncio.wait_for(STATE.stop_event.wait(), timeout=timeout)
                break
            except asyncio.TimeoutError:
                continue
    finally:
        STATE.next_discovery_at = None
        if STATE.safe_mode:
            STATE.state = "SAFE_MODE"
        else:
            STATE.state = "STOPPED"
        STATE.progress = STATE.safe_reason or "Остановлен пользователем"
        for worker in STATE.workers.values():
            worker["status"] = "IDLE"
        await asyncio.to_thread(PROBES.stop_all)
        await STATE.event("system", f"NOMAD остановлен: {STATE.state}; локальные дочерние процессы завершены", "warning" if STATE.safe_mode else "info")


async def start_probe() -> None:
    if STARTUP_PROGRESS.get("status") != "READY":
        raise HTTPException(503, "SQLite storage is not ready; check the startup panel")
    if STATE.safe_mode:
        raise HTTPException(409, f"SAFE_MODE: {STATE.safe_reason}")
    if STATE.worker_task and not STATE.worker_task.done():
        return
    try:
        PROBES.start()
    except Exception as exc:
        PROBES.stop_all()
        raise HTTPException(500, f"Could not start local probe processes: {exc}") from exc
    STATE.stop_event = asyncio.Event()
    STATE.work_event = asyncio.Event()
    STATE.host_scan_bootstrap_done = False
    STATE.worker_task = asyncio.create_task(worker_loop(), name="nomad-coordinator")
    await STATE.event("system", "Запрошен запуск NOMAD: создано семь локальных probe-процессов: один Discovery Scout и шесть аналитических", "success")


async def stop_probe() -> None:
    if STATE.stop_event:
        STATE.stop_event.set()
    if STATE.worker_task and not STATE.worker_task.done():
        try:
            await asyncio.wait_for(STATE.worker_task, timeout=18)
        except asyncio.TimeoutError:
            STATE.worker_task.cancel()
            try:
                await STATE.worker_task
            except asyncio.CancelledError:
                pass
    await asyncio.to_thread(PROBES.stop_all)
    STATE.state = "STOPPED" if not STATE.safe_mode else "SAFE_MODE"
    await STATE.event("system", "Зонд остановлен пользователем", "warning")


def safe_snapshot() -> dict[str, Any]:
    return snapshot()


def snapshot() -> dict[str, Any]:
    uptime = max(0, int(time.time() - STATE.created))
    process_info = PROBES.snapshot()
    alive = bool(STATE.state in ("RUNNING", "MONITORING") and process_info["alive"] > 0)
    entities = list(STATE.entities.values())
    routes = list(STATE.routes.values())
    observations = list(STATE.observations)
    events = list(STATE.events)
    return {
        "app": {"name": "NOMAD", "version": APP_VERSION, "time": utcnow()},
        "storage": {"startup": dict(STARTUP_PROGRESS), "database": STORE.summary()},
        "host_scan": dict(STATE.host_scan),
        "discovery_progress": dict(STATE.discovery_progress),
        "status": {"state": STATE.state, "alive": alive, "safe_mode": STATE.safe_mode, "safe_reason": STATE.safe_reason,
                   "pid": os.getpid(), "uptime_seconds": uptime, "last_heartbeat": datetime.fromtimestamp(STATE.last_heartbeat, timezone.utc).isoformat(timespec="seconds"),
                   "started_at": STATE.started_at, "last_cycle": STATE.last_cycle, "current_target": STATE.current_target, "progress": STATE.progress,
                   "next_discovery_in_seconds": (max(0, int(STATE.next_discovery_at - time.monotonic())) if STATE.next_discovery_at is not None else None),
                   "scheduler_errors": STATE.scheduler_errors},
        "metrics": {"requests": STATE.total_requests, "denied": STATE.total_denied, "entities": len(entities), "routes": len(routes),
                    "observations": len(observations), "cycles": STATE.cycle_count, "ip_queue": len(STATE.ip_queue), "ip_inspected": len(STATE.ip_inspected),
                    "asn_queue": len(STATE.asn_queue), "asn_expansions": STATE.asn_expansion_count,
                    "probes_total": process_info["total"], "probes_alive": process_info["alive"]},
        "workers": process_info["items"],
        "probe_processes": process_info,
        "sources": STATE.source_status,
        "entities": entities,
        "routes": routes,
        "observations": observations,
        "intelligence": correlate_network_evidence(),
        "active_results": list(STATE.active_results),
        "events": events,
        "origin": STATE.origin,
        "probe_location": STATE.probe_location,
        "config_summary": {"discovery_interval_seconds": CONFIG["discovery_interval_seconds"], "asn_refresh_interval_seconds": CONFIG["asn_refresh_interval_seconds"], "seeds": CONFIG["seeds"], "probe_processes_configured": len(PROBE_ROLES),
                           "traceroute_enabled": CONFIG["traceroute"]["enabled"], "approved_trace_targets": len(CONFIG["traceroute"]["approved_targets"]),
                           "ip_frontier": len(STATE.ip_queue), "ip_inspected": len(STATE.ip_inspected),
                           "asn_frontier": len(STATE.asn_queue), "asn_expansions": STATE.asn_expansion_count,
                           "egress_ip_observation": CONFIG["observe_egress_ip"],
                           "active_probes": {
                               "host_scan_enabled": CONFIG["host_scan"]["enabled"],
                               "host_scan_ranges": CONFIG["host_scan"]["approved_subnets"],
                               "host_scan_concurrency": CONFIG["host_scan"]["concurrency"],
                               "ping_enabled": CONFIG["ping"]["enabled"],
                               "ping_targets": CONFIG["ping"]["approved_targets"],
                               "traceroute_enabled": CONFIG["traceroute"]["enabled"],
                               "traceroute_targets": CONFIG["traceroute"]["approved_targets"],
                               "arp_enabled": CONFIG["arp_scan"]["enabled"],
                               "arp_subnets": CONFIG["arp_scan"]["approved_subnets"],
                               "arp_interface_configured": bool(CONFIG["arp_scan"]["interface"]),
                           }},
    }


def request_is_local(request: Request) -> bool:
    raw_host = request.headers.get("host", "")
    try:
        parsed_host = urlsplit("//" + raw_host)
        host = (parsed_host.hostname or "").lower()
        port = parsed_host.port
    except ValueError:
        return False
    client = request.client.host if request.client else ""
    origin = request.headers.get("origin")
    local_clients = {"127.0.0.1", "::1", "localhost", "testclient"}
    if client not in local_clients or host not in ("127.0.0.1", "localhost", "::1") or port != CONFIG["port"]:
        return False
    if origin:
        try:
            parsed_origin = urlsplit(origin)
            return (parsed_origin.scheme == "http" and parsed_origin.hostname in ("127.0.0.1", "localhost", "::1") and parsed_origin.port == CONFIG["port"])
        except ValueError:
            return False
    return True


async def initialize_storage() -> None:
    STARTUP_PROGRESS.update(status="RUNNING", stage="starting", message="Инициализация SQLite после открытия веб-интерфейса", completed=0, total=1)
    try:
        restored = await asyncio.to_thread(STORE.initialize, ROOT, report_startup_progress)
        STATE.entities.update(restored["entities"])
        STATE.routes.update(restored["routes"])
        STATE.observations.extend(restored["observations"])
        STATE.events.extend(restored["events"])
        STATE.active_results.extend(restored["active_results"])
        STATE.total_entities = len(STATE.entities)
        STATE.total_routes = len(STATE.routes)
        STARTUP_PROGRESS.update(
            status="READY", stage="ready", message="Проверки завершены; база данных загружена",
            completed=1, total=1, current=None, unit=None,
            result={
                "integrity": restored["integrity"], "content_check": restored["content_check"],
                "hashes": restored["hashes"], "counts": restored["counts"], "db_path": restored["db_path"],
                "db_size_bytes": restored["db_size_bytes"],
            },
            updated_at=utcnow(),
        )
        await STATE.event("system", "SQLite storage initialized; saved state restored", "success")
        if CONFIG.get("auto_start"):
            await start_probe()
    except Exception as exc:
        STARTUP_PROGRESS.update(
            status="ERROR", stage="error", message=f"Ошибка подготовки БД: {type(exc).__name__}: {exc}",
            completed=0, total=1, current=None, unit=None, updated_at=utcnow(),
        )
        log.exception("NOMAD storage initialization failed")


async def ensure_storage_initialization() -> None:
    global STORAGE_INIT_TASK
    async with STORAGE_INIT_LOCK:
        if STARTUP_PROGRESS.get("status") == "READY":
            return
        if STORAGE_INIT_TASK is None or STORAGE_INIT_TASK.done():
            STORAGE_INIT_TASK = asyncio.create_task(initialize_storage(), name="nomad-storage-initialization")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The server may start without touching the DB. The first browser GET / triggers checks.
    yield
    if STORAGE_INIT_TASK is not None and not STORAGE_INIT_TASK.done():
        await STORAGE_INIT_TASK
    await stop_probe()
    await asyncio.to_thread(PROBES.stop_all)
    await asyncio.to_thread(STORE.close)


app = FastAPI(title="NOMAD Local", version=APP_VERSION, docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/")
async def index() -> FileResponse:
    await ensure_storage_initialization()
    return FileResponse(INDEX_PATH, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"})


@app.get("/api/status")
async def api_status():
    return safe_snapshot()


@app.post("/api/storage/backup")
async def api_storage_backup(request: Request):
    if not request_is_local(request):
        raise HTTPException(403, "Local origin required")
    if STARTUP_PROGRESS.get("status") != "READY":
        raise HTTPException(503, "SQLite storage is not ready")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = ROOT / "data" / "backups" / f"NOMAD-backup-{stamp}.sqlite3"
    try:
        backup_path = await asyncio.to_thread(STORE.backup, destination)
        return FileResponse(backup_path, filename=backup_path.name, media_type="application/vnd.sqlite3")
    except Exception as exc:
        raise HTTPException(500, f"SQLite backup failed: {exc}") from exc


@app.post("/api/start")
async def api_start(request: Request):
    if not request_is_local(request): raise HTTPException(403, "Local origin required")
    await start_probe()
    return {"ok": True, "status": STATE.state}


@app.post("/api/stop")
async def api_stop(request: Request):
    if not request_is_local(request): raise HTTPException(403, "Local origin required")
    await stop_probe()
    return {"ok": True, "status": STATE.state}


@app.post("/api/scan-once")
async def api_scan_once(request: Request):
    if not request_is_local(request): raise HTTPException(403, "Local origin required")
    if STATE.safe_mode: raise HTTPException(409, STATE.safe_reason or "SAFE_MODE")
    if STATE.worker_task and not STATE.worker_task.done():
        raise HTTPException(409, "Probe is already running; stop it before a manual scan")
    PROBES.start()
    STATE.stop_event = asyncio.Event()
    try:
        task = asyncio.create_task(scan_cycle(drain_frontiers=False, discovery_only=True))
        await task
        await run_authorized_host_scan()
        STATE.host_scan_bootstrap_done = True
        while STATE.ip_queue and not STATE.safe_mode:
            if await process_ip_frontier(max_items=1) == 0:
                break
    finally:
        await asyncio.to_thread(PROBES.stop_all)
    STATE.state = "SAFE_MODE" if STATE.safe_mode else "STOPPED"
    return {"ok": True, "snapshot": snapshot()}


@app.post("/api/active/ping")
async def api_active_ping(request: Request):
    if not request_is_local(request):
        raise HTTPException(403, "Local origin required")
    try:
        payload = await request.json()
        target = str(payload.get("target", "")) if isinstance(payload, dict) else ""
        async with ACTIVE_PROBE_LOCK:
            result = await run_ping(target)
        return {"ok": True, "result": result}
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/active/traceroute")
async def api_active_traceroute(request: Request):
    if not request_is_local(request):
        raise HTTPException(403, "Local origin required")
    try:
        payload = await request.json()
        target = str(payload.get("target", "")) if isinstance(payload, dict) else ""
        async with ACTIVE_PROBE_LOCK:
            result = await run_traceroute(target)
        return {"ok": True, "result": result}
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/active/arp")
async def api_active_arp(request: Request):
    if not request_is_local(request):
        raise HTTPException(403, "Local origin required")
    try:
        payload = await request.json()
        subnet = str(payload.get("subnet", "")) if isinstance(payload, dict) else ""
        async with ACTIVE_PROBE_LOCK:
            result = await run_arp_scan(subnet)
        return {"ok": True, "result": result}
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/observe-origin")
async def api_observe_origin(request: Request):
    if not request_is_local(request): raise HTTPException(403, "Local origin required")
    if not CONFIG.get("observe_egress_ip"):
        raise HTTPException(403, "Set observe_egress_ip=true in config.json first")
    started_processes_here = not PROBES.has_alive()
    try:
        if started_processes_here:
            PROBES.start()
        raw = await fetch_ripestat("whats-my-ip")
        ip = raw.get("data", {}).get("ip")
        parsed = ipaddress.ip_address(ip)
        if not parsed.is_global: raise ValueError("RIPEstat returned a non-global address")
        geo = await geolocate(str(parsed))
        STATE.origin = {"ip": str(parsed), **geo, "observed_at": utcnow(), "note": "Approximate egress IP geolocation; not precise device location."}
        await STATE.event("origin", f"Получены сведения о публичном egress IP ({parsed.version})", "info")
        place = ", ".join(x for x in (geo.get("city"), geo.get("region"), geo.get("country")) if x)
        await STATE.observation("geolocation", str(parsed), f"Геоданные исходящего IP: {place or 'место не определено'}" + (" (координаты отсутствуют)" if not ("lat" in geo and "lon" in geo) else ""), "RIPEstat MaxMind GeoLite", "medium" if place else "low", geo)
        return {"ok": True, "origin": STATE.origin}
    except Exception as exc:
        await STATE.event("origin", f"Не удалось определить egress IP: {exc}", "warning")
        raise HTTPException(502, str(exc))
    finally:
        if started_processes_here:
            await asyncio.to_thread(PROBES.stop_all)


@app.post("/api/probe-location")
async def api_probe_location(request: Request):
    if not request_is_local(request):
        raise HTTPException(403, "Local origin required")
    try:
        payload = await request.json()
        lat = float(payload.get("lat"))
        lon = float(payload.get("lon"))
        accuracy = float(payload.get("accuracy", 0) or 0)
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            raise ValueError("Coordinates out of range")
        STATE.probe_location = {
            "lat": lat, "lon": lon, "accuracy_m": max(0, min(100000, accuracy)),
            "source": "Browser geolocation (user-approved)", "observed_at": utcnow(),
        }
        await STATE.event("map", "Положение локальных зондов задано разрешённой геолокацией браузера; координаты хранятся только в RAM", "info")
        return {"ok": True, "probe_location": STATE.probe_location}
    except (TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(400, f"Invalid location payload: {exc}") from exc


@app.delete("/api/probe-location")
async def api_clear_probe_location(request: Request):
    if not request_is_local(request):
        raise HTTPException(403, "Local origin required")
    STATE.probe_location = None
    await STATE.event("map", "Координаты локальных зондов очищены", "info")
    return {"ok": True}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    client = ws.client.host if ws.client else ""
    try:
        parsed_host = urlsplit("//" + ws.headers.get("host", ""))
        parsed_origin = urlsplit(ws.headers.get("origin", ""))
        local_host = parsed_host.hostname in {"127.0.0.1", "localhost", "::1"} and parsed_host.port == CONFIG["port"]
        local_origin = parsed_origin.scheme == "http" and parsed_origin.hostname in {"127.0.0.1", "localhost", "::1"} and parsed_origin.port == CONFIG["port"]
    except ValueError:
        local_host = local_origin = False
    if client not in {"127.0.0.1", "::1"} or not local_host or not local_origin:
        await ws.close(code=1008); return
    await ws.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    HUB.clients.add(queue)
    try:
        await ws.send_json({"type": "snapshot", "data": snapshot()})
        while True:
            event = await queue.get()
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        HUB.clients.discard(queue)


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    log.exception("Unhandled API error", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def main() -> None:
    if not INDEX_PATH.exists():
        print(f"index.html not found: {INDEX_PATH}"); raise SystemExit(2)
    host = CONFIG["bind"]
    port = CONFIG["port"]
    url = f"http://127.0.0.1:{port}/"
    print("\nNOMAD — Network Intelligence")
    print(f"UI: {url}")
    print("Probe model: 7 separate local OS processes (Discovery / Resource / Route / Geo)")
    print("Network scope: fixed RIPEstat public data endpoints")
    print(f"Database: SQLite ({STORE.path})")
    print("Traceroute: disabled by default; configured approved IPs only")
    print("Press Ctrl+C to stop.\n")
    if os.environ.get("NOMAD_NO_BROWSER") != "1":
        try: threading.Timer(1.25, webbrowser.open, args=(url,), daemon=True).start()
        except Exception: pass
    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False)


if __name__ == "__main__":
    main()
