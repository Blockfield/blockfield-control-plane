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
# Recorded read-only from the prod workshop vhost (workshop.blockfield.pro)
# 2026-10-31 while the controller held the builders gate on healthy prod:
# the proxy serves the gate message itself, so builders shows this text.
CLOSED = {
    "text": "На сервере проводятся технические работы. Обычный вход временно недоступен.",
    "color": "gold",
}


def status_bytes(description):
    payload = json.dumps(
        {"version": {"name": "1.21", "protocol": 767}, "description": description}
    ).encode()
    return probe.frame(0, probe.varint(len(payload)) + payload)


class TcpFake(threading.Thread):
    """Answers one Java status exchange per connection, per requested vhost.

    The proxy serves a different MOTD per vhost on the same port, so the fake
    parses the handshake host: anything containing "workshop" gets the
    workshop description, the rest the game one.
    """

    def __init__(self, game=OPEN, workshop=CLOSED):
        super().__init__(daemon=True)
        self.game = game
        self.workshop = workshop
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
                    data = conn.recv(4096)
                    conn.sendall(status_bytes(self.pick(data)))
                except OSError:
                    pass

    def pick(self, data):
        try:
            length, offset = probe.read_varint(data)
            body = data[offset : offset + length]
            _, offset = probe.read_varint(body)
            _, offset = probe.read_varint(body, offset)
            size, offset = probe.read_varint(body, offset)
            host = body[offset : offset + size].decode("utf-8", "replace")
        except (IndexError, ValueError, struct.error):
            host = ""
        return self.workshop if "workshop" in host else self.game


class UdpFake(threading.Thread):
    """Answers RakNet Open Connection Request 1 like raknetify.

    Unconnected pings and wrong-protocol requests get silence or 0x19,
    exactly like prod: the probe must use the 0x05 handshake to pass.
    """

    def __init__(self, answer_protocol=None, incompatible=False):
        super().__init__(daemon=True)
        self.answer_protocol = (
            probe.RAKNET_PROTOCOL if answer_protocol is None else answer_protocol
        )
        self.incompatible = incompatible
        self.seen = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]

    def run(self):
        while True:
            try:
                data, addr = self.socket.recvfrom(2048)
            except OSError:
                return
            self.seen.append(data[:1])
            if data[:1] != bytes((probe.RAKNET_OPEN_REQUEST_1,)):
                continue  # raknetify never answers unconnected ping
            if (
                data[1:17] != probe.RAKNET_MAGIC
                or len(data) != probe.RAKNET_PADDED_SIZE
            ):
                continue
            if data[17] != self.answer_protocol or self.incompatible:
                self.socket.sendto(b"\x19" + probe.RAKNET_MAGIC, addr)
                continue
            reply = (
                bytes((probe.RAKNET_OPEN_REPLY_1,))
                + probe.RAKNET_MAGIC
                + struct.pack(">q", 0x42)
                + bytes(3)
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
        self.tcp = TcpFake()
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
            game_only=False,
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

    def test_handshake_uses_open_request_not_unconnected_ping(self):
        # Raknetify never answers 0x01 (prod times out): the probe must send
        # the 0x05 Open Connection Request 1 to pass.
        results = probe.check(self.args())
        self.assertTrue(all(ok for ok, _, _ in results), results)
        self.assertTrue(self.udp.seen, results)
        self.assertTrue(
            all(
                first == bytes((probe.RAKNET_OPEN_REQUEST_1,))
                for first in self.udp.seen
            ),
            self.udp.seen,
        )

    def test_wrong_protocol_fails_like_prod_incompatible(self):
        # Prod answers protocol 11 with 0x19: only the 0x06 reply passes.
        udp = UdpFake(answer_protocol=99)
        udp.start()
        results = probe.check(self.args(udp_port=udp.port))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertFalse(by_name["raknet"][0], results)
        self.assertTrue(
            all(ok for name, (ok, _) in by_name.items() if name != "raknet"),
            results,
        )

    def test_builders_maintenance_motd_passes(self):
        # The prod false negative: builders gate serves the maintenance text
        # on the workshop vhost, and that is the healthy state.
        results = probe.check(self.args(expect_workshop="builders"))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertTrue(by_name["tcp_workshop"][0], results)

    def test_builders_misroute_to_game_motd_fails(self):
        # Workshop vhost serving the game MOTD means routing is broken.
        tcp = TcpFake(game=OPEN, workshop=OPEN)
        tcp.start()
        results = probe.check(self.args(tcp_port=tcp.port))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertFalse(by_name["tcp_workshop"][0], results)
        self.assertTrue(by_name["tcp_game"][0], results)

    def test_builders_empty_motd_fails(self):
        # A dead backend serves no gate marker: must not pass as builders.
        tcp = TcpFake(workshop={"text": ""})
        tcp.start()
        results = probe.check(self.args(tcp_port=tcp.port))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertFalse(by_name["tcp_workshop"][0], results)

    def test_dead_workshop_port_fails(self):
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        results = probe.check(self.args(tcp_port=port))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertFalse(by_name["tcp_workshop"][0], results)

    def test_closed_workshop_open_motd_fails(self):
        # Closed means refusal: an open marker on the workshop vhost fails.
        tcp = TcpFake(game=CLOSED, workshop=OPEN)
        tcp.start()
        results = probe.check(
            self.args(expect_game="closed", expect_workshop="closed", tcp_port=tcp.port)
        )
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertFalse(by_name["tcp_workshop"][0], results)

    def test_closed_workshop_passes_when_closed_expected(self):
        tcp = TcpFake(CLOSED)
        tcp.start()
        gate = {
            "backend": "game",
            "gate": "closed",
            "backends": {
                "game": {"gate": "closed"},
                "workshop": {"gate": "closed"},
            },
        }
        self.gate_file.write_text(json.dumps(gate), encoding="utf-8")
        results = probe.check(
            self.args(expect_game="closed", expect_workshop="closed", tcp_port=tcp.port)
        )
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

    def test_game_only_skips_a_dead_workshop(self):
        # A Game deploy never consults the Workshop: no vhost, a mismatched
        # Workshop gate-file leg, and no container discovery still pass.
        gate = {
            "backend": "game",
            "gate": "public",
            "backends": {
                "game": {"gate": "public"},
                "workshop": {"gate": "closed"},
            },
        }
        self.gate_file.write_text(json.dumps(gate), encoding="utf-8")
        with patch.object(
            probe,
            "workshop_host_from_container",
            side_effect=AssertionError("no discovery in Game-only mode"),
        ):
            results = probe.check(self.args(game_only=True, workshop_host=None))
        by_name = {item[1]: (item[0], item[2]) for item in results}
        self.assertTrue(all(ok for ok, _, _ in results), results)
        self.assertIn("skipped", by_name["tcp_workshop"][1].lower())

    def test_game_only_still_fails_a_closed_game(self):
        tcp = TcpFake(game=CLOSED, workshop=CLOSED)
        tcp.start()
        results = probe.check(
            self.args(game_only=True, workshop_host=None, tcp_port=tcp.port)
        )
        by_name = {item[1]: item[0] for item in results}
        self.assertFalse(by_name["tcp_game"], results)
        self.assertTrue(by_name["tcp_workshop"], results)

    def test_game_only_still_checks_raknet(self):
        # The RakNet handshake runs in both modes: Game entry needs it too.
        closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        results = probe.check(self.args(game_only=True, udp_port=port))
        by_name = {item[1]: item[0] for item in results}
        self.assertFalse(by_name["raknet"], results)
        self.assertTrue(by_name["tcp_workshop"], results)

    def test_bad_tag_is_usage_error(self):
        with self.assertRaises(SystemExit):
            probe.main(["--tag", "not-a-tag"])

    def test_no_tag_checks_entry_shape_only(self):
        results = probe.check(self.args(tag=None))
        by_name = {item[1]: item[0] for item in results}
        self.assertTrue(by_name["rooms"], results)


if __name__ == "__main__":
    unittest.main()
