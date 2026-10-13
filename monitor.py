#!/usr/bin/env python3
"""Parallel ICMP/TCP/UDP monitor for Hypershield failure tests.

The monitor deliberately does not operate the Smart Switch.  It generates
traffic, records evidence, and exposes a local read-only dashboard plus marker
buttons for human-performed fault and recovery operations.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import locale
import math
import os
import platform
import random
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


VERSION = "0.2.0"
ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
BITRATE_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)?[KMGT]?$", re.IGNORECASE)
PING_TIME_PATTERN = re.compile(
    r"(?:time|時間)\s*[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE
)
PING_REPLY_IP_PATTERNS = (
    re.compile(r"Reply from\s+([0-9A-Fa-f:.]+)", re.IGNORECASE),
    re.compile(r"([0-9A-Fa-f:.]+)\s+からの応答", re.IGNORECASE),
)


def utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with millisecond precision."""

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return safe or "run"


@dataclass(frozen=True)
class ProbeConfig:
    probe_id: str
    name: str
    kind: str
    host: str
    port: Optional[int]
    interval_seconds: float
    timeout_seconds: float
    iperf3_executable: str
    duration_seconds: int
    connect_timeout_ms: int
    tcp_bitrate: str
    udp_bitrate: str
    reverse: bool

    @property
    def target(self) -> str:
        if self.port is None:
            return self.host
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class ProbeResult:
    timestamp_utc: str
    epoch: float
    elapsed_seconds: float
    probe_id: str
    observed: str
    success: bool
    latency_ms: Optional[float]
    throughput_bps: Optional[float]
    loss_percent: Optional[float]
    transferred_bytes: Optional[int]
    received_packets: Optional[int]
    resolved_ip: str
    detail: str


@dataclass(frozen=True)
class ProbeOutcome:
    success: bool
    latency_ms: Optional[float] = None
    throughput_bps: Optional[float] = None
    loss_percent: Optional[float] = None
    transferred_bytes: Optional[int] = None
    received_packets: Optional[int] = None
    resolved_ip: str = ""
    detail: str = ""


def _number(
    value: Any, name: str, minimum: float, *, integer: bool = False
) -> float | int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    try:
        converted = int(value) if integer else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if converted < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return converted


def load_config(path: Path) -> Tuple[Dict[str, Any], List[ProbeConfig]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Configuration file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON at line {exc.lineno}: {exc.msg}") from exc

    if not isinstance(raw, dict):
        raise ValueError("The configuration root must be a JSON object")

    defaults = raw.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError("defaults must be a JSON object")

    default_interval = _number(
        defaults.get("interval_seconds", 3.0),
        "defaults.interval_seconds",
        0.2,
    )
    default_timeout = _number(
        defaults.get("timeout_seconds", 0.8),
        "defaults.timeout_seconds",
        0.1,
    )
    iperf_defaults = raw.get("iperf3", {})
    if not isinstance(iperf_defaults, dict):
        raise ValueError("iperf3 must be a JSON object")
    default_executable = str(
        iperf_defaults.get(
            "executable", "iperf3.exe" if platform.system().lower() == "windows" else "iperf3"
        )
    ).strip()
    if not default_executable:
        raise ValueError("iperf3.executable cannot be empty")
    default_duration = int(
        _number(
            iperf_defaults.get("duration_seconds", 2),
            "iperf3.duration_seconds",
            1,
            integer=True,
        )
    )
    default_connect_timeout = int(
        _number(
            iperf_defaults.get("connect_timeout_ms", 800),
            "iperf3.connect_timeout_ms",
            100,
            integer=True,
        )
    )
    default_udp_bitrate = str(iperf_defaults.get("udp_bitrate", "1M")).strip()
    if not BITRATE_PATTERN.fullmatch(default_udp_bitrate):
        raise ValueError("iperf3.udp_bitrate must look like 1M or 500K")
    default_tcp_bitrate = str(iperf_defaults.get("tcp_bitrate", "1M")).strip()
    if not BITRATE_PATTERN.fullmatch(default_tcp_bitrate):
        raise ValueError("iperf3.tcp_bitrate must look like 1M or 500K")
    default_reverse = iperf_defaults.get("reverse", False)
    if not isinstance(default_reverse, bool):
        raise ValueError("iperf3.reverse must be true or false")

    items = raw.get("probes")
    if not isinstance(items, list) or not items:
        raise ValueError("probes must contain at least one entry")

    probes: List[ProbeConfig] = []
    seen_ids = set()
    seen_iperf_servers: Dict[Tuple[str, int], str] = {}
    for index, item in enumerate(items, start=1):
        scope = f"probes[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{scope} must be a JSON object")
        if item.get("enabled", True) is False:
            continue

        obsolete_keys = {
            "expect",
            "failure_threshold",
            "recovery_threshold",
            "udp_mode",
            "udp_payload",
            "udp_response",
            "udp_response_contains",
        }.intersection(item)
        if obsolete_keys:
            shown = ", ".join(sorted(obsolete_keys))
            raise ValueError(
                f"{scope} contains obsolete setting(s): {shown}; "
                "this version displays actual connectivity only"
            )

        probe_id = str(item.get("id", "")).strip()
        if not probe_id or not ID_PATTERN.fullmatch(probe_id):
            raise ValueError(
                f"{scope}.id is required and may contain letters, digits, '.', '_' and '-'"
            )
        if probe_id in seen_ids:
            raise ValueError(f"Duplicate probe id: {probe_id}")
        seen_ids.add(probe_id)

        name = str(item.get("name", probe_id)).strip() or probe_id
        kind = str(item.get("type", "")).strip().lower()
        if kind == "icmp":
            kind = "ping"
        if kind not in {"ping", "tcp", "udp"}:
            raise ValueError(f"{scope}.type must be ping, tcp, or udp")

        host = str(item.get("host", "")).strip()
        if not host or any(char.isspace() for char in host):
            raise ValueError(f"{scope}.host is required and cannot contain whitespace")

        port: Optional[int] = None
        if kind in {"tcp", "udp"}:
            port = int(_number(item.get("port"), f"{scope}.port", 1, integer=True))
            if port > 65535:
                raise ValueError(f"{scope}.port must be 1 through 65535")

        duration_seconds = int(
            _number(
                item.get("duration_seconds", default_duration),
                f"{scope}.duration_seconds",
                1,
                integer=True,
            )
        )
        connect_timeout_ms = int(
            _number(
                item.get("connect_timeout_ms", default_connect_timeout),
                f"{scope}.connect_timeout_ms",
                100,
                integer=True,
            )
        )
        udp_bitrate = str(item.get("bitrate", default_udp_bitrate)).strip()
        if not BITRATE_PATTERN.fullmatch(udp_bitrate):
            raise ValueError(f"{scope}.bitrate must look like 1M or 500K")
        tcp_bitrate = str(item.get("bitrate", default_tcp_bitrate)).strip()
        if not BITRATE_PATTERN.fullmatch(tcp_bitrate):
            raise ValueError(f"{scope}.bitrate must look like 1M or 500K")
        reverse = item.get("reverse", default_reverse)
        if not isinstance(reverse, bool):
            raise ValueError(f"{scope}.reverse must be true or false")

        probe_executable = str(
            item.get("iperf3_executable", default_executable)
        ).strip()
        if kind in {"tcp", "udp"} and not probe_executable:
            raise ValueError(f"{scope}.iperf3_executable cannot be empty")

        if kind in {"tcp", "udp"}:
            assert port is not None
            server_key = (host.lower(), port)
            if server_key in seen_iperf_servers:
                other = seen_iperf_servers[server_key]
                raise ValueError(
                    f"{scope} and {other} use the same iperf3 server {host}:{port}; "
                    "parallel probes require separate server ports"
                )
            seen_iperf_servers[server_key] = scope

        probes.append(
            ProbeConfig(
                probe_id=probe_id,
                name=name,
                kind=kind,
                host=host,
                port=port,
                interval_seconds=float(
                    _number(
                        item.get("interval_seconds", default_interval),
                        f"{scope}.interval_seconds",
                        0.2,
                    )
                ),
                timeout_seconds=float(
                    _number(
                        item.get("timeout_seconds", default_timeout),
                        f"{scope}.timeout_seconds",
                        0.1,
                    )
                ),
                iperf3_executable=probe_executable,
                duration_seconds=duration_seconds,
                connect_timeout_ms=connect_timeout_ms,
                tcp_bitrate=tcp_bitrate,
                udp_bitrate=udp_bitrate,
                reverse=reverse,
            )
        )

    if not probes:
        raise ValueError("No enabled probes were found")
    return raw, probes


class EvidenceWriter:
    """Write every sample and operator marker immediately to local storage."""

    FIELDNAMES = [
        "run_id",
        "timestamp_utc",
        "elapsed_seconds",
        "phase",
        "probe_id",
        "name",
        "protocol",
        "host",
        "resolved_ip",
        "port",
        "observed",
        "evaluation",
        "latency_ms",
        "throughput_bps",
        "loss_percent",
        "transferred_bytes",
        "received_packets",
        "consecutive_up",
        "consecutive_down",
        "down_seconds",
        "detail",
    ]

    def __init__(
        self, config_path: Path, raw_config: Dict[str, Any], run_id: str
    ) -> None:
        logging_config = raw_config.get("logging", {})
        if not isinstance(logging_config, dict):
            raise ValueError("logging must be a JSON object")
        directory_value = str(logging_config.get("directory", "logs"))
        base_directory = Path(directory_value)
        if not base_directory.is_absolute():
            base_directory = config_path.parent / base_directory
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.run_directory = base_directory / f"{stamp}_{safe_filename(run_id)}"
        self.run_directory.mkdir(parents=True, exist_ok=False)
        self._lock = threading.RLock()

        self._results_file = (self.run_directory / "probe_results.csv").open(
            "w", newline="", encoding="utf-8-sig"
        )
        self._results_writer = csv.DictWriter(
            self._results_file, fieldnames=self.FIELDNAMES, extrasaction="ignore"
        )
        self._results_writer.writeheader()
        self._results_file.flush()

        self._events_file = (self.run_directory / "events.jsonl").open(
            "w", encoding="utf-8"
        )
        manifest = {
            "application": "Hypershield Failure Test Monitor",
            "version": VERSION,
            "run_id": run_id,
            "started_at_utc": utc_now(),
            "config_path": str(config_path.resolve()),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "config": raw_config,
        }
        (self.run_directory / "run.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def write_result(self, row: Dict[str, Any]) -> None:
        with self._lock:
            self._results_writer.writerow(row)
            self._results_file.flush()

    def write_event(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._events_file.write(
                json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
            self._events_file.flush()

    def close(self) -> None:
        with self._lock:
            if not self._results_file.closed:
                self._results_file.flush()
                self._results_file.close()
            if not self._events_file.closed:
                self._events_file.flush()
                self._events_file.close()


class MonitorState:
    def __init__(
        self,
        probes: Iterable[ProbeConfig],
        run_id: str,
        history_size: int,
        writer: EvidenceWriter,
        started_monotonic: Optional[float] = None,
    ) -> None:
        self.run_id = run_id
        self.started_at = utc_now()
        self.started_monotonic = started_monotonic or time.monotonic()
        self.phase = "baseline"
        self._writer = writer
        self._lock = threading.RLock()
        self._history_size = history_size
        self._markers: Deque[Dict[str, Any]] = deque(maxlen=30)
        self._items: Dict[str, Dict[str, Any]] = {}
        for config in probes:
            self._items[config.probe_id] = {
                "config": config,
                "observed": "unknown",
                "evaluation": "pending",
                "latency_ms": None,
                "throughput_bps": None,
                "loss_percent": None,
                "transferred_bytes": None,
                "received_packets": None,
                "resolved_ip": "",
                "detail": "Waiting for first result",
                "last_checked_at": None,
                "last_change_at": None,
                "last_actual_up_at": None,
                "consecutive_up": 0,
                "consecutive_down": 0,
                "total_checks": 0,
                "successful_checks": 0,
                "down_since_elapsed": None,
                "last_down_seconds": 0.0,
                "max_down_seconds": 0.0,
                "history": deque(maxlen=history_size),
            }
        self.add_marker("baseline", "Monitoring started")

    def add_marker(self, kind: str, note: str = "") -> Dict[str, Any]:
        phase_by_kind = {
            "baseline": "baseline",
            "fault_start": "fault",
            "recovery_start": "recovery",
            "test_end": "complete",
        }
        now = utc_now()
        with self._lock:
            if kind in phase_by_kind:
                self.phase = phase_by_kind[kind]
            event = {
                "event": "operator_marker",
                "run_id": self.run_id,
                "timestamp_utc": now,
                "elapsed_seconds": round(
                    time.monotonic() - self.started_monotonic, 3
                ),
                "kind": kind,
                "phase": self.phase,
                "note": note[:500],
            }
            self._markers.appendleft(event)
            self._writer.write_event(event)
            return dict(event)

    def record_result(self, result: ProbeResult) -> None:
        with self._lock:
            item = self._items[result.probe_id]
            config: ProbeConfig = item["config"]
            old_observed = item["observed"]
            old_evaluation = item["evaluation"]

            item["total_checks"] += 1
            item["observed"] = result.observed
            item["latency_ms"] = result.latency_ms
            item["throughput_bps"] = result.throughput_bps
            item["loss_percent"] = result.loss_percent
            item["transferred_bytes"] = result.transferred_bytes
            item["received_packets"] = result.received_packets
            item["resolved_ip"] = result.resolved_ip
            item["detail"] = result.detail
            item["last_checked_at"] = result.timestamp_utc

            if result.success:
                item["successful_checks"] += 1
                item["last_actual_up_at"] = result.timestamp_utc
                item["consecutive_up"] += 1
                item["consecutive_down"] = 0
                if item["down_since_elapsed"] is not None:
                    down_duration = max(
                        0.0,
                        result.elapsed_seconds - item["down_since_elapsed"],
                    )
                    item["last_down_seconds"] = down_duration
                    item["max_down_seconds"] = max(
                        item["max_down_seconds"], down_duration
                    )
                    item["down_since_elapsed"] = None
                evaluation = "pass"
            else:
                item["consecutive_up"] = 0
                item["consecutive_down"] += 1
                if item["down_since_elapsed"] is None:
                    item["down_since_elapsed"] = result.elapsed_seconds
                evaluation = "fail"

            item["evaluation"] = evaluation
            if old_observed != result.observed or old_evaluation != evaluation:
                item["last_change_at"] = result.timestamp_utc
                self._writer.write_event(
                    {
                        "event": "state_change",
                        "run_id": self.run_id,
                        "timestamp_utc": result.timestamp_utc,
                        "elapsed_seconds": result.elapsed_seconds,
                        "phase": self.phase,
                        "probe_id": result.probe_id,
                        "from_observed": old_observed,
                        "to_observed": result.observed,
                        "from_evaluation": old_evaluation,
                        "to_evaluation": evaluation,
                        "detail": result.detail,
                    }
                )

            down_seconds = self._down_seconds(item, result.elapsed_seconds)
            item["history"].append(
                {
                    "timestamp_utc": result.timestamp_utc,
                    "observed": result.observed,
                    "evaluation": evaluation,
                    "latency_ms": result.latency_ms,
                }
            )
            self._writer.write_result(
                {
                    "run_id": self.run_id,
                    "timestamp_utc": result.timestamp_utc,
                    "elapsed_seconds": f"{result.elapsed_seconds:.3f}",
                    "phase": self.phase,
                    "probe_id": config.probe_id,
                    "name": config.name,
                    "protocol": config.kind,
                    "host": config.host,
                    "resolved_ip": result.resolved_ip,
                    "port": config.port if config.port is not None else "",
                    "observed": result.observed,
                    "evaluation": evaluation,
                    "latency_ms": (
                        "" if result.latency_ms is None else f"{result.latency_ms:.3f}"
                    ),
                    "throughput_bps": (
                        ""
                        if result.throughput_bps is None
                        else f"{result.throughput_bps:.3f}"
                    ),
                    "loss_percent": (
                        ""
                        if result.loss_percent is None
                        else f"{result.loss_percent:.6f}"
                    ),
                    "transferred_bytes": (
                        "" if result.transferred_bytes is None else result.transferred_bytes
                    ),
                    "received_packets": (
                        "" if result.received_packets is None else result.received_packets
                    ),
                    "consecutive_up": item["consecutive_up"],
                    "consecutive_down": item["consecutive_down"],
                    "down_seconds": f"{down_seconds:.3f}",
                    "detail": result.detail,
                }
            )

    @staticmethod
    def _down_seconds(item: Dict[str, Any], current_elapsed: float) -> float:
        start = item["down_since_elapsed"]
        if start is None:
            return 0.0
        return max(0.0, current_elapsed - start)

    def snapshot(self) -> Dict[str, Any]:
        current_elapsed = time.monotonic() - self.started_monotonic
        with self._lock:
            probes = []
            counts = {
                "pass": 0,
                "fail": 0,
                "pending": 0,
            }
            for item in self._items.values():
                config: ProbeConfig = item["config"]
                evaluation = item["evaluation"]
                counts[evaluation] = counts.get(evaluation, 0) + 1
                total_checks = item["total_checks"]
                pass_rate = (
                    100.0 * item["successful_checks"] / total_checks
                    if total_checks
                    else None
                )
                probes.append(
                    {
                        "id": config.probe_id,
                        "name": config.name,
                        "protocol": config.kind,
                        "target": config.target,
                        "observed": item["observed"],
                        "evaluation": evaluation,
                        "latency_ms": item["latency_ms"],
                        "throughput_bps": item["throughput_bps"],
                        "loss_percent": item["loss_percent"],
                        "transferred_bytes": item["transferred_bytes"],
                        "received_packets": item["received_packets"],
                        "resolved_ip": item["resolved_ip"],
                        "detail": item["detail"],
                        "last_checked_at": item["last_checked_at"],
                        "last_change_at": item["last_change_at"],
                        "last_actual_up_at": item["last_actual_up_at"],
                        "consecutive_up": item["consecutive_up"],
                        "consecutive_down": item["consecutive_down"],
                        "total_checks": total_checks,
                        "pass_rate": pass_rate,
                        "down_seconds": self._down_seconds(item, current_elapsed),
                        "last_down_seconds": item["last_down_seconds"],
                        "max_down_seconds": item["max_down_seconds"],
                        "history": list(item["history"]),
                    }
                )

            if counts["fail"]:
                overall = "fail"
            elif counts["pending"]:
                overall = "pending"
            else:
                overall = "pass"

            return {
                "application": "Hypershield Failure Test Monitor",
                "version": VERSION,
                "run_id": self.run_id,
                "started_at": self.started_at,
                "elapsed_seconds": current_elapsed,
                "phase": self.phase,
                "overall": overall,
                "counts": counts,
                "probes": probes,
                "markers": list(self._markers),
            }


def _decode_output(data: bytes) -> str:
    encodings = [locale.getpreferredencoding(False), "utf-8", "cp932"]
    for encoding in dict.fromkeys(encodings):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


async def ping_probe(config: ProbeConfig) -> ProbeOutcome:
    system = platform.system().lower()
    timeout_ms = max(100, int(config.timeout_seconds * 1000))
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), config.host]
    elif system == "darwin":
        command = ["ping", "-n", "-c", "1", "-W", str(timeout_ms), config.host]
    else:
        timeout_seconds = max(1, int(math.ceil(config.timeout_seconds)))
        command = [
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            str(timeout_seconds),
            config.host,
        ]

    subprocess_options: Dict[str, Any] = {}
    if system == "windows":
        subprocess_options["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **subprocess_options,
        )
    except FileNotFoundError:
        return ProbeOutcome(False, detail="ping command was not found")

    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=config.timeout_seconds + 2.0
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return ProbeOutcome(False, detail="ping process timed out")
    except asyncio.CancelledError:
        process.kill()
        await process.communicate()
        raise

    text = _decode_output(stdout)
    match = PING_TIME_PATTERN.search(text)
    latency_ms = float(match.group(1)) if match else None
    resolved_ip = config.host
    for reply_pattern in PING_REPLY_IP_PATTERNS:
        reply_match = reply_pattern.search(text)
        if reply_match:
            resolved_ip = reply_match.group(1)
            break
    if process.returncode == 0:
        return ProbeOutcome(
            True,
            latency_ms=latency_ms,
            resolved_ip=resolved_ip,
            detail="ICMP reply received",
        )
    detail_lines = [line.strip() for line in text.splitlines() if line.strip()]
    detail = detail_lines[-1][:300] if detail_lines else "No ICMP reply"
    return ProbeOutcome(False, detail=detail)


def _number_from(mapping: Any, key: str) -> Optional[float]:
    if not isinstance(mapping, dict):
        return None
    value = mapping.get(key)
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _format_rate(bits_per_second: Optional[float]) -> str:
    if bits_per_second is None:
        return "rate unavailable"
    units = [(1_000_000_000, "Gbps"), (1_000_000, "Mbps"), (1_000, "Kbps")]
    for divisor, suffix in units:
        if bits_per_second >= divisor:
            return f"{bits_per_second / divisor:.2f} {suffix}"
    return f"{bits_per_second:.0f} bps"


def _format_bytes(byte_count: Optional[int]) -> str:
    if byte_count is None:
        return "size unavailable"
    for divisor, suffix in (
        (1024**3, "GiB"),
        (1024**2, "MiB"),
        (1024, "KiB"),
    ):
        if byte_count >= divisor:
            return f"{byte_count / divisor:.2f} {suffix}"
    return f"{byte_count} B"


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = text.lstrip("\ufeff\r\n ")
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        payload = json.loads(cleaned[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("iperf3 output is not a JSON object")
    return payload


def _udp_receiver_summary(end: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    sum_received = end.get("sum_received")
    if isinstance(sum_received, dict) and sum_received.get("sender") is not True:
        candidates.append(sum_received)
    sum_value = end.get("sum")
    if isinstance(sum_value, dict) and sum_value.get("sender") is False:
        candidates.append(sum_value)
    streams = end.get("streams", [])
    if isinstance(streams, list):
        for stream in streams:
            if not isinstance(stream, dict):
                continue
            udp = stream.get("udp")
            if isinstance(udp, dict) and udp.get("sender") is False:
                candidates.append(udp)
    return next((item for item in candidates if "packets" in item), None)


def parse_iperf_json(config: ProbeConfig, payload: Dict[str, Any]) -> ProbeOutcome:
    error = payload.get("error")
    if error:
        return ProbeOutcome(False, detail=f"iperf3 error: {str(error)[:300]}")

    start = payload.get("start")
    end = payload.get("end")
    if not isinstance(start, dict) or not isinstance(end, dict):
        return ProbeOutcome(False, detail="iperf3 JSON is missing start/end data")

    connected = start.get("connected")
    if not isinstance(connected, list) or not connected:
        return ProbeOutcome(False, detail="iperf3 control connection was not established")
    first_connection = connected[0] if isinstance(connected[0], dict) else {}
    resolved_ip = str(first_connection.get("remote_host", config.host))

    test_start = start.get("test_start")
    protocol = (
        str(test_start.get("protocol", "")).upper()
        if isinstance(test_start, dict)
        else ""
    )
    expected_protocol = config.kind.upper()
    if protocol != expected_protocol:
        shown = protocol or "missing"
        return ProbeOutcome(
            False,
            resolved_ip=resolved_ip,
            detail=f"iperf3 protocol mismatch: expected {expected_protocol}, got {shown}",
        )

    if config.kind == "tcp":
        receiver = end.get("sum_received")
        if not isinstance(receiver, dict):
            return ProbeOutcome(
                False,
                resolved_ip=resolved_ip,
                detail="iperf3 TCP receiver summary is missing",
            )
        byte_value = _number_from(receiver, "bytes")
        rate_value = _number_from(receiver, "bits_per_second")
        byte_count = int(byte_value) if byte_value is not None else None
        if byte_count is None or byte_count <= 0:
            return ProbeOutcome(
                False,
                throughput_bps=rate_value,
                transferred_bytes=byte_count,
                resolved_ip=resolved_ip,
                detail="iperf3 TCP completed but the receiver got no data",
            )

        zero_intervals = 0
        intervals = payload.get("intervals", [])
        if isinstance(intervals, list):
            for interval in intervals:
                if not isinstance(interval, dict):
                    continue
                interval_sum = interval.get("sum")
                seconds = _number_from(interval_sum, "seconds")
                interval_bytes = _number_from(interval_sum, "bytes")
                omitted = (
                    bool(interval_sum.get("omitted", False))
                    if isinstance(interval_sum, dict)
                    else False
                )
                if (
                    not omitted
                    and seconds is not None
                    and seconds >= 0.5
                    and interval_bytes is not None
                    and interval_bytes <= 0
                ):
                    zero_intervals += 1
        if zero_intervals:
            return ProbeOutcome(
                False,
                throughput_bps=rate_value,
                transferred_bytes=byte_count,
                resolved_ip=resolved_ip,
                detail=f"iperf3 TCP detected {zero_intervals} zero-throughput interval(s)",
            )

        return ProbeOutcome(
            True,
            throughput_bps=rate_value,
            transferred_bytes=byte_count,
            resolved_ip=resolved_ip,
            detail=f"TCP {_format_rate(rate_value)} / {_format_bytes(byte_count)} received",
        )

    receiver = _udp_receiver_summary(end)
    if receiver is None:
        return ProbeOutcome(
            False,
            resolved_ip=resolved_ip,
            detail="iperf3 UDP receiver summary is missing",
        )
    packet_value = _number_from(receiver, "packets")
    lost_value = _number_from(receiver, "lost_packets")
    rate_value = _number_from(receiver, "bits_per_second")
    loss_value = _number_from(receiver, "lost_percent")
    byte_value = _number_from(receiver, "bytes")
    if packet_value is None or lost_value is None or byte_value is None:
        return ProbeOutcome(
            False,
            resolved_ip=resolved_ip,
            detail="iperf3 UDP receiver summary is incomplete",
        )
    packet_count = int(packet_value) if packet_value is not None else None
    lost_count = int(lost_value)
    received_packets = (
        max(0, packet_count - lost_count) if packet_count is not None else None
    )
    byte_count = int(byte_value) if byte_value is not None else None
    if received_packets is None or received_packets <= 0 or byte_count is None or byte_count <= 0:
        return ProbeOutcome(
            False,
            throughput_bps=rate_value,
            loss_percent=loss_value,
            transferred_bytes=byte_count,
            received_packets=received_packets,
            resolved_ip=resolved_ip,
            detail="iperf3 UDP completed but the receiver got no packets",
        )
    return ProbeOutcome(
        True,
        throughput_bps=rate_value,
        loss_percent=loss_value,
        transferred_bytes=byte_count,
        received_packets=received_packets,
        resolved_ip=resolved_ip,
        detail=(
            f"UDP {_format_rate(rate_value)} / loss "
            f"{loss_value:.2f}% / {received_packets} packet(s) received"
            if loss_value is not None
            else f"UDP {_format_rate(rate_value)} / {received_packets} packet(s) received"
        ),
    )


async def iperf3_probe(config: ProbeConfig) -> ProbeOutcome:
    assert config.port is not None
    bitrate = config.udp_bitrate if config.kind == "udp" else config.tcp_bitrate
    command = [
        config.iperf3_executable,
        "-c",
        config.host,
        "-p",
        str(config.port),
        "-t",
        str(config.duration_seconds),
        "-i",
        "1",
        "-P",
        "1",
        "-b",
        bitrate,
        "--connect-timeout",
        str(config.connect_timeout_ms),
        "-J",
    ]
    if config.kind == "udp":
        command.append("-u")
    if config.reverse:
        command.append("-R")

    subprocess_options: Dict[str, Any] = {}
    if platform.system().lower() == "windows":
        subprocess_options["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **subprocess_options,
        )
    except FileNotFoundError:
        return ProbeOutcome(
            False,
            detail=f"iperf3 executable was not found: {config.iperf3_executable}",
        )
    except OSError as exc:
        return ProbeOutcome(False, detail=f"iperf3 could not start: {exc}")

    process_timeout = (
        config.duration_seconds + config.connect_timeout_ms / 1000.0 + 5.0
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=process_timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return ProbeOutcome(False, detail="iperf3 process timed out")
    except asyncio.CancelledError:
        process.kill()
        await process.communicate()
        raise

    stdout_text = _decode_output(stdout)
    stderr_text = _decode_output(stderr).strip()
    try:
        payload = _extract_json_object(stdout_text)
    except (json.JSONDecodeError, ValueError):
        detail = stderr_text or stdout_text.strip() or "no output"
        return ProbeOutcome(
            False,
            detail=f"iperf3 returned invalid JSON: {detail[:300]}",
        )
    if process.returncode != 0:
        error = payload.get("error") or stderr_text or f"exit code {process.returncode}"
        return ProbeOutcome(False, detail=f"iperf3 failed: {str(error)[:300]}")
    return parse_iperf_json(config, payload)


async def execute_probe(
    config: ProbeConfig, started_monotonic: float
) -> ProbeResult:
    try:
        if config.kind == "ping":
            outcome = await ping_probe(config)
        else:
            outcome = await iperf3_probe(config)
    except Exception as exc:  # Keep one broken probe from stopping the test run.
        outcome = ProbeOutcome(
            False, detail=f"Probe error: {type(exc).__name__}: {exc}"
        )
    timestamp = utc_now()
    epoch = time.time()
    observed = "up" if outcome.success else "down"
    return ProbeResult(
        timestamp_utc=timestamp,
        epoch=epoch,
        elapsed_seconds=time.monotonic() - started_monotonic,
        probe_id=config.probe_id,
        observed=observed,
        success=outcome.success,
        latency_ms=outcome.latency_ms,
        throughput_bps=outcome.throughput_bps,
        loss_percent=outcome.loss_percent,
        transferred_bytes=outcome.transferred_bytes,
        received_packets=outcome.received_packets,
        resolved_ip=outcome.resolved_ip,
        detail=outcome.detail,
    )


async def probe_loop(
    config: ProbeConfig,
    state: MonitorState,
    semaphore: asyncio.Semaphore,
    started_monotonic: float,
    jitter_seconds: float,
) -> None:
    while True:
        iteration_started = time.monotonic()
        async with semaphore:
            result = await execute_probe(config, started_monotonic)
        state.record_result(result)
        duration = time.monotonic() - iteration_started
        jitter = random.uniform(0.0, jitter_seconds) if jitter_seconds else 0.0
        await asyncio.sleep(max(0.05, config.interval_seconds - duration + jitter))


def make_http_handler(
    state: MonitorState, dashboard_path: Path
) -> type[BaseHTTPRequestHandler]:
    dashboard = dashboard_path.read_bytes()
    allowed_markers = {"baseline", "fault_start", "recovery_start", "note", "test_end"}

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = f"HypershieldMonitor/{VERSION}"

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/index.html"}:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(dashboard)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
                self.end_headers()
                self.wfile.write(dashboard)
            elif parsed.path == "/api/status":
                self._send_json(200, state.snapshot())
            elif parsed.path == "/healthz":
                self._send_json(200, {"ok": True, "run_id": state.run_id})
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path != "/api/marker":
                self._send_json(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 8192:
                    raise ValueError("request body is too large")
                body = self.rfile.read(length)
                payload = json.loads(body.decode("utf-8"))
                kind = str(payload.get("kind", "")).strip()
                note = str(payload.get("note", "")).strip()
                if kind not in allowed_markers:
                    raise ValueError("invalid marker kind")
                event = state.add_marker(kind, note)
                self._send_json(200, {"ok": True, "event": event})
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self._send_json(400, {"error": str(exc)})

        def log_message(self, format_string: str, *args: Any) -> None:
            return

    return DashboardHandler


async def run_monitor(config_path: Path) -> None:
    raw_config, probes = load_config(config_path)
    run_id = str(raw_config.get("run_id", "")).strip()
    if not run_id:
        run_id = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    dashboard_config = raw_config.get("dashboard", {})
    if not isinstance(dashboard_config, dict):
        raise ValueError("dashboard must be a JSON object")
    listen = str(dashboard_config.get("listen", "127.0.0.1"))
    port = int(_number(dashboard_config.get("port", 8765), "dashboard.port", 1, integer=True))
    if port > 65535:
        raise ValueError("dashboard.port must be 1 through 65535")
    history_size = int(
        _number(
            dashboard_config.get("history_size", 60),
            "dashboard.history_size",
            10,
            integer=True,
        )
    )
    history_size = min(history_size, 600)

    monitor_config = raw_config.get("monitor", {})
    if not isinstance(monitor_config, dict):
        raise ValueError("monitor must be a JSON object")
    max_concurrency = int(
        _number(
            monitor_config.get("max_concurrency", 50),
            "monitor.max_concurrency",
            1,
            integer=True,
        )
    )
    jitter_seconds = float(
        _number(
            monitor_config.get("jitter_seconds", 0.05),
            "monitor.jitter_seconds",
            0,
        )
    )

    started_monotonic = time.monotonic()
    writer = EvidenceWriter(config_path, raw_config, run_id)
    state = MonitorState(
        probes,
        run_id,
        history_size,
        writer,
        started_monotonic=started_monotonic,
    )
    dashboard_path = Path(__file__).with_name("dashboard.html")
    handler = make_http_handler(state, dashboard_path)
    http_server = ThreadingHTTPServer((listen, port), handler)
    server_thread = threading.Thread(
        target=http_server.serve_forever,
        name="dashboard-server",
        daemon=True,
    )
    server_thread.start()

    display_host = "localhost" if listen in {"127.0.0.1", "::1"} else listen
    print(f"Hypershield Failure Test Monitor {VERSION}")
    print(f"Dashboard: http://{display_host}:{port}")
    print(f"Run ID:    {run_id}")
    print(f"Evidence:  {writer.run_directory.resolve()}")
    print("Press Ctrl+C to stop. Smart Switch operations are not performed by this tool.")

    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [
        asyncio.create_task(
            probe_loop(
                probe,
                state,
                semaphore,
                started_monotonic,
                jitter_seconds,
            ),
            name=f"probe-{probe.probe_id}",
        )
        for probe in probes
    ]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        state.add_marker("test_end", "Monitor stopped")
        http_server.shutdown()
        http_server.server_close()
        writer.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parallel ICMP/TCP/UDP monitor for Hypershield failure tests"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.json"),
        help="JSON configuration path (default: config.json)",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = args.config.expanduser().resolve()
    try:
        asyncio.run(run_monitor(config_path))
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
