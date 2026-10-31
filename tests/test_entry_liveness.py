"""Vendored byte copy of Blockfield/blockfield-server scripts/entry_liveness.py (canonical). Sync rule: copy it again in the same PR that changes the canonical script.
Entry-liveness gate against fakes: no prod, no real network beyond localhost."""

import argparse
import importlib.util
import json
import socket
import struct
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "entry_liveness", Path(__file__).parents[1] / "scripts/entry_liveness.py"
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

TAG = "v2.79.2"
OPEN = {"text": "BLOCKFIELD", "color": "gold"}
CLOSED = {"text": "На сервере проводятся технические работы", "color": "gold"}


def status_bytes(description):
    payload = json.dumps(
        {"version": {"name": "1.21", "protocol": 767}, "description": description}
    ).encode()
    return probe.frame(0, probe.varint(len(payload)) + payload)


class TcpFake(threading.Thread):
    """Answers one Java status exchange per connection with a canned description."""

    def __init__(self, descriptions):
        super().__init__(daemon=True)
        self.descriptions = descriptions
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.port = self.socket.getsockname()[1]

    def run(self):
        while True:
            conn, _ = self.socket.accept()
            with conn:
                conn.settimeout(5)
                try:
                    conn.recv(4096)
                    conn.sendall(status_bytes(self.descriptions))
                except OSError:
                    pass


class UdpFake(threading.Thread):
    """Answers one RakNet unconnected ping with a canned MOTD."""

    def __init__(self, motd="MCPE;BLOCKFIELD"):
        super().__init__(daemon=True)
        self.motd = motd.encode()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]

    def run(self):
        while True:
            try:
                data, addr = self.socket.recvfrom(2048)
            except OSError:
                return
            if data[:1] == b"\x01" and probe.RAKNET_MAGIC in data:
                reply = (
                    bytes((probe.RAKNET_PONG_ID,))
                    + data[1:9]
                    + struct.pack(">q", 0x42)
                    + probe.RAKNET_MAGIC
                    + struct.pack(">H", len(self.motd))
                    + self.motd
                )
                self.socket.sendto(reply, addr)


class RoomsFake:
    def __init__(self, payload):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(outer.payload).encode()

                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.payload = payload
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/api/rooms"

    def close(self):
        self.server.shutdown()


class EntryLivenessTest(unittest.TestCase):
    def setUp(self):
        self.tcp = TcpFake(OPEN)
        self.tcp.start()
        self.udp = UdpFake()
        self.udp.start()
        self.rooms = RoomsFake({"build": TAG, "available": True})
        self.addCleanup(self.rooms.close)
        gate = {
            "backend": "game",
            "gate": "public",
            "backends": {
                "game": {"gate": "public"},
                "workshop": {"gate": "builders"},
            },
        }
        self.gate_file = Path(tempfile.mkdtemp()) / "gate.json"
        self.gate_file.write_text(json.dumps(gate), encoding="utf-8")

    def args(self, **overrides):
        values = dict(
            tag=TAG,
            proxy_host="127.0.0.1",
            tcp_port=self.tcp.port,
            udp_port=self.udp.port,
            rooms_url=self.rooms.url,
            gate_file=str(self.gate_file),
            workshop_host="workshop.test",
            expect_game="public",
            expect_workshop="builders",
        )
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_open_entry_passes(self):
        results = probe.check(self.args())
        self.assertTrue(all(ok for ok, _, _ in results), results)
        self.assertEqual(
            len(results), 5
        )  # rooms, tcp_game, tcp_workshop, raknet, gate_file

    def test_missing_workshop_host_fails_not_skips(self):
        # proxy#48: an unverified Workshop leg must fail the gate, never slip
        # through as a silent SKIP.
        with patch.object(probe, "workshop_host_from_container", return_value=None):
            results = probe.check(self.args(workshop_host=None))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertFalse(by_name["tcp_workshop"][0], results)
        self.assertIn("proxy#48", by_name["tcp_workshop"][1])
        self.assertTrue(
            all(ok for name, (ok, _) in by_name.items() if name != "tcp_workshop"),
            results,
        )

    def test_closed_game_fails_and_names_the_gate(self):
        tcp = TcpFake(CLOSED)
        tcp.start()
        results = probe.check(self.args(tcp_port=tcp.port))
        failed = [name for ok, name, _ in results if not ok]
        self.assertIn("tcp_game", failed)
        detail = next(d for ok, name, d in results if name == "tcp_game")
        self.assertIn("CP", detail)

    def test_intended_maintenance_passes_when_proxy_agrees(self):
        tcp = TcpFake(CLOSED)
        tcp.start()
        gate = {
            "backend": "game",
            "gate": "closed",
            "backends": {
                "game": {"gate": "closed"},
                "workshop": {"gate": "builders"},
            },
        }
        self.gate_file.write_text(json.dumps(gate), encoding="utf-8")
        results = probe.check(self.args(expect_game="closed", tcp_port=tcp.port))
        self.assertTrue(all(ok for ok, _, _ in results), results)

    def test_rooms_build_mismatch_fails(self):
        rooms = RoomsFake({"build": "v0.0.1", "available": True})
        self.addCleanup(rooms.close)
        results = probe.check(self.args(rooms_url=rooms.url))
        self.assertIn("rooms", [name for ok, name, _ in results if not ok])

    def test_dead_raknet_fails(self):
        closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        with self.assertRaises(SystemExit):
            probe.main(
                [
                    "--tag",
                    TAG,
                    "--tcp-port",
                    str(self.tcp.port),
                    "--udp-port",
                    str(port),
                    "--rooms-url",
                    self.rooms.url,
                    "--gate-file",
                    str(self.gate_file),
                ]
            )

    def test_bad_tag_is_usage_error(self):
        with self.assertRaises(SystemExit):
            probe.main(["--tag", "not-a-tag"])

    def test_no_tag_checks_entry_shape_only(self):
        results = probe.check(self.args(tag=None))
        by_name = {item[1]: item[0] for item in results}
        self.assertTrue(by_name["rooms"], results)


if __name__ == "__main__":
    unittest.main()
