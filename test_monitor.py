import json
import tempfile
import time
import unittest
from pathlib import Path

from monitor import (
    EvidenceWriter,
    MonitorState,
    ProbeConfig,
    ProbeResult,
    execute_probe,
    load_config,
    parse_iperf_json,
)


def probe_config(**overrides):
    values = {
        "probe_id": "probe-1",
        "name": "Probe 1",
        "kind": "tcp",
        "host": "192.0.2.20",
        "port": 5201,
        "interval_seconds": 3.0,
        "timeout_seconds": 0.8,
        "iperf3_executable": "iperf3",
        "duration_seconds": 2,
        "connect_timeout_ms": 800,
        "tcp_bitrate": "1M",
        "udp_bitrate": "1M",
        "reverse": False,
    }
    values.update(overrides)
    return ProbeConfig(**values)


def iperf_start(protocol):
    return {
        "connected": [{"remote_host": "192.0.2.20"}],
        "test_start": {"protocol": protocol},
    }


class ConfigTests(unittest.TestCase):
    def _load(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            return load_config(path)

    def test_loads_enabled_probes_and_skips_disabled(self):
        config = {
            "probes": [
                {"id": "p1", "type": "icmp", "host": "127.0.0.1"},
                {
                    "id": "p2",
                    "type": "tcp",
                    "host": "127.0.0.1",
                    "port": 5201,
                    "enabled": False,
                },
            ]
        }
        _, probes = self._load(config)
        self.assertEqual([probe.probe_id for probe in probes], ["p1"])
        self.assertEqual(probes[0].kind, "ping")

    def test_rejects_duplicate_ids(self):
        config = {
            "probes": [
                {"id": "same", "type": "ping", "host": "127.0.0.1"},
                {"id": "same", "type": "ping", "host": "127.0.0.1"},
            ]
        }
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self._load(config)

    def test_rejects_parallel_iperf_tests_on_same_server_port(self):
        config = {
            "probes": [
                {
                    "id": "tcp",
                    "type": "tcp",
                    "host": "192.0.2.20",
                    "port": 5201,
                },
                {
                    "id": "udp",
                    "type": "udp",
                    "host": "192.0.2.20",
                    "port": 5201,
                },
            ]
        }
        with self.assertRaisesRegex(ValueError, "separate server ports"):
            self._load(config)

    def test_accepts_parallel_iperf_tests_on_separate_ports(self):
        config = {
            "probes": [
                {
                    "id": "tcp",
                    "type": "tcp",
                    "host": "192.0.2.20",
                    "port": 5201,
                },
                {
                    "id": "udp",
                    "type": "udp",
                    "host": "192.0.2.20",
                    "port": 5202,
                },
            ]
        }
        _, probes = self._load(config)
        self.assertEqual(len(probes), 2)

    def test_rejects_obsolete_expect_setting(self):
        config = {
            "probes": [
                {
                    "id": "old",
                    "type": "ping",
                    "host": "127.0.0.1",
                    "expect": "up",
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "obsolete"):
            self._load(config)


class IperfJsonTests(unittest.TestCase):
    def test_tcp_requires_receiver_data(self):
        payload = {
            "start": iperf_start("TCP"),
            "intervals": [
                {"sum": {"seconds": 1.0, "bytes": 125000, "omitted": False}}
            ],
            "end": {
                "sum_received": {
                    "bytes": 250000,
                    "bits_per_second": 1000000,
                }
            },
        }
        outcome = parse_iperf_json(probe_config(), payload)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.transferred_bytes, 250000)
        self.assertEqual(outcome.throughput_bps, 1000000)

        payload["end"]["sum_received"]["bytes"] = 0
        outcome = parse_iperf_json(probe_config(), payload)
        self.assertFalse(outcome.success)

    def test_tcp_zero_throughput_interval_is_failure(self):
        payload = {
            "start": iperf_start("TCP"),
            "intervals": [
                {"sum": {"seconds": 1.0, "bytes": 0, "omitted": False}}
            ],
            "end": {
                "sum_received": {
                    "bytes": 1000,
                    "bits_per_second": 4000,
                }
            },
        }
        outcome = parse_iperf_json(probe_config(), payload)
        self.assertFalse(outcome.success)
        self.assertIn("zero-throughput", outcome.detail)

    def test_udp_uses_receiver_packet_count_and_loss(self):
        payload = {
            "start": iperf_start("UDP"),
            "intervals": [],
            "end": {
                "sum": {
                    "sender": False,
                    "packets": 100,
                    "lost_packets": 2,
                    "lost_percent": 2.0,
                    "bytes": 122500,
                    "bits_per_second": 490000,
                }
            },
        }
        config = probe_config(kind="udp", port=5202)
        outcome = parse_iperf_json(config, payload)
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.received_packets, 98)
        self.assertEqual(outcome.loss_percent, 2.0)

        payload["end"]["sum"]["packets"] = 2
        payload["end"]["sum"]["lost_packets"] = 2
        payload["end"]["sum"]["lost_percent"] = 100.0
        outcome = parse_iperf_json(config, payload)
        self.assertFalse(outcome.success)

    def test_top_level_iperf_error_is_failure(self):
        outcome = parse_iperf_json(
            probe_config(), {"error": "unable to connect to server"}
        )
        self.assertFalse(outcome.success)
        self.assertIn("unable to connect", outcome.detail)

    def test_udp_sender_only_summary_is_not_receiver_success(self):
        payload = {
            "start": iperf_start("UDP"),
            "intervals": [],
            "end": {
                "sum": {
                    "sender": True,
                    "packets": 100,
                    "lost_packets": 0,
                    "lost_percent": 0.0,
                    "bytes": 122500,
                    "bits_per_second": 490000,
                }
            },
        }
        outcome = parse_iperf_json(probe_config(kind="udp", port=5202), payload)
        self.assertFalse(outcome.success)
        self.assertIn("receiver summary is missing", outcome.detail)


class ProbeProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_iperf_executable_is_down(self):
        config = probe_config(
            iperf3_executable="definitely-not-a-real-iperf3-command"
        )
        result = await execute_probe(config, time.monotonic())
        self.assertFalse(result.success)
        self.assertEqual(result.observed, "down")
        self.assertIn("not found", result.detail)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        directory = Path(self.temp_directory.name)
        config_path = directory / "config.json"
        config_path.write_text("{}", encoding="utf-8")
        self.writer = EvidenceWriter(
            config_path,
            {"logging": {"directory": str(directory / "logs")}},
            "test-run",
        )

    def tearDown(self):
        self.writer.close()
        self.temp_directory.cleanup()

    @staticmethod
    def _result(success, elapsed):
        return ProbeResult(
            timestamp_utc="2026-10-13T00:00:00.000Z",
            epoch=time.time(),
            elapsed_seconds=elapsed,
            probe_id="probe-1",
            observed="up" if success else "down",
            success=success,
            latency_ms=None,
            throughput_bps=1000000 if success else None,
            loss_percent=None,
            transferred_bytes=1000 if success else None,
            received_packets=None,
            resolved_ip="192.0.2.20",
            detail="test",
        )

    def test_failure_is_immediately_red(self):
        state = MonitorState([probe_config()], "test-run", 10, self.writer)
        state.record_result(self._result(False, 0.0))
        snapshot = state.snapshot()
        self.assertEqual(snapshot["overall"], "fail")
        self.assertEqual(snapshot["probes"][0]["evaluation"], "fail")
        self.assertEqual(snapshot["counts"]["fail"], 1)

    def test_recovery_is_immediately_green_and_records_downtime(self):
        state = MonitorState([probe_config()], "test-run", 10, self.writer)
        state.record_result(self._result(False, 2.0))
        state.record_result(self._result(True, 5.5))
        probe = state.snapshot()["probes"][0]
        self.assertEqual(probe["evaluation"], "pass")
        self.assertEqual(probe["last_down_seconds"], 3.5)
        self.assertEqual(probe["pass_rate"], 50.0)


if __name__ == "__main__":
    unittest.main()
