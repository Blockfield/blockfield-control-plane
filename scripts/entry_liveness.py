"""Vendored byte copy of Blockfield/blockfield-server scripts/entry_liveness.py (canonical). Sync rule: copy it again in the same PR that changes the canonical script.
Synthetic entry-liveness gate: prove a player can get in after a deploy.

Runs after every prod deploy (server, proxy, CP, Workshop move) and fails the
deploy job when entry is dead. No credentials beyond what the runner already
has: the proxy answers status/RakNet pings anonymously, /api/rooms is public,
and the host gate file is read-only.

What each probe proves:
- rooms: Game serves the deployed tag and reports available (site already
  folds the CP gate into `available`, so false here also catches a CP outage).
- tcp_game: the proxy's composed gate (file gate + CP lease, reloaded on
  every ping by BackendRouting.reloadGate) leaves the Game leg open. The file
  may say public while a stale CP lease fails closed: that combination fails
  here and names the CP leg.
- tcp_workshop: the Workshop virtual host answers with its gate applied
  (proves proxy routing to the Workshop leg, not just the default backend).
- raknet: the RakNet listener players actually use answers Open Connection
  Request 1 (transport alive; raknetify answers below the login gate, but
  never answers an unconnected ping).
- gate_file: the host file leg matches the expected states, so an intended
  maintenance reads as SKIP-worthy instead of a mysterious ping failure.
  --game-only skips the Workshop legs (tcp_workshop, Workshop gate-file leg):
  Game deploys use it so a down/asleep/mid-transition Workshop never blocks
  Game entry verification; Workshop releases keep the full gate.

Exit 0 = entry alive, 1 = entry dead, 2 = usage/config error.
"""

import argparse
import json
import socket
import struct
import subprocess
import urllib.request

TAG = __import__("re").compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
# Proxy #48 closed Workshop for ~16 h with no gate catching it: the exact
# texts the proxy plugin serves when a leg is not open.
CLOSED_MARKERS = ("технические работы",)
OPEN_MARKER = "blockfield"
# Raknetify never answers an unconnected ping (0x01 times out); it answers
# Open Connection Request 1 with the client's protocol version, padded like one.
RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
RAKNET_OPEN_REQUEST_1 = 0x05
RAKNET_OPEN_REPLY_1 = 0x06
RAKNET_PROTOCOL = 10
RAKNET_PADDED_SIZE = 1200
TIMEOUT = 10


def text(node):
    """Plain text of a Velocity ping description (str or chat-component JSON)."""
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        parts = [node.get("text", "")]
        parts.extend(text(item) for item in node.get("extra", []))
        return "".join(parts)
    if isinstance(node, list):
        return "".join(text(item) for item in node)
    return ""


def varint(value):
    out = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            out.append(part | 0x80)
        else:
            out.append(part)
            return bytes(out)


def read_varint(buffer, offset=0):
    value = shift = 0
    while True:
        byte = buffer[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift >= 35:
            raise ValueError("varint too long")


def frame(packet_id, payload=b""):
    body = varint(packet_id) + payload
    return varint(len(body)) + body


def status_ping(host, port, server_host):
    """One Java status exchange; returns the parsed status JSON."""
    payload = (
        varint(774)
        + varint(len(server_host.encode()))
        + server_host.encode()
        + struct.pack(">H", port)
        + varint(1)
    )
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendall(frame(0, payload) + frame(0))
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("proxy closed the status connection")
            data += chunk
            if len(data) > 1 << 20:
                raise ValueError("status response too large")
            try:
                length, offset = read_varint(data)
            except IndexError:
                continue
            if len(data) < offset + length:
                continue
            body = data[offset : offset + length]
            packet_id, offset = read_varint(body)
            if packet_id != 0:
                raise ValueError("unexpected status packet")
            size, offset = read_varint(body, offset)
            return json.loads(body[offset : offset + size])


def raknet_ping(host, port):
    """One RakNet Open Connection Request 1; returns the server GUID hex.

    Raknetify ignores unconnected pings, so the leg must use the handshake
    players use. Protocol 10 is answered with 0x06; a wrong protocol (e.g. 11)
    gets 0x19 incompatible, which fails the leg.
    """
    packet = (
        bytes((RAKNET_OPEN_REQUEST_1,))
        + RAKNET_MAGIC
        + bytes((RAKNET_PROTOCOL,))
        + bytes(RAKNET_PADDED_SIZE - 1 - len(RAKNET_MAGIC) - 1)
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(2048)
    if not data or data[0] != RAKNET_OPEN_REPLY_1:
        raise ValueError("not an Open Connection Reply 1")
    if data[1:17] != RAKNET_MAGIC:
        raise ValueError("RakNet reply magic mismatch")
    return data[17:25].hex()


def rooms_state(url):
    request = urllib.request.Request(
        url, headers={"Cache-Control": "no-cache", "User-Agent": "blockfield-entry"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def gate_file_states(path):
    with open(path, encoding="utf-8") as stream:
        gate = json.load(stream)
    backends = gate.get("backends", {})
    if backends:
        return {name: leg.get("gate") for name, leg in backends.items()}
    return {gate.get("backend", "game"): gate.get("gate")}


def workshop_host_from_container():
    """BLOCKFIELD_WORKSHOP_HOST off the running proxy container (read-only)."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}} {{.Image}}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        cid, _, image = line.partition(" ")
        if "blockfield-proxy" not in image:
            continue
        try:
            result = subprocess.run(
                ["docker", "inspect", cid.strip()],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        env = json.loads(result.stdout)[0].get("Config", {}).get("Env") or []
        for entry in env:
            name, _, value = entry.partition("=")
            if name == "BLOCKFIELD_WORKSHOP_HOST":
                return value.strip() or None
    return None


def check(args):
    results = []

    def record(ok, name, detail):
        results.append((ok, name, detail))
        print(f"{'ok' if ok else 'FAIL'} {name}: {detail}", flush=True)

    try:
        rooms = rooms_state(args.rooms_url)
    except Exception as error:
        record(False, "rooms", f"{args.rooms_url} unreachable ({error})")
    else:
        build_ok = args.tag is None or rooms.get("build") == args.tag
        record(
            build_ok and rooms.get("available") is True,
            "rooms",
            f"build={rooms.get('build')} available={rooms.get('available')} "
            f"(want {args.tag or 'any'}/True)",
        )
    try:
        status = status_ping(args.proxy_host, args.tcp_port, args.proxy_host)
    except Exception as error:
        record(False, "tcp_game", f"status ping failed ({error})")
    else:
        description = text(status.get("description", ""))
        closed = any(marker in description for marker in CLOSED_MARKERS)
        opened = OPEN_MARKER in description.lower() and not closed
        want_open = args.expect_game == "public"
        record(
            opened == want_open,
            "tcp_game",
            f"motd={description.strip()[:80]!r} "
            + (
                "(composed game gate open)"
                if opened
                else (
                    "(composed gate closed as intended)"
                    if not want_open
                    else "(composed gate closed: file leg public + CP leg stale?)"
                )
            ),
        )
    if args.game_only:
        # Game deploys never consult the Workshop: skip its vhost probe, which
        # would fail while the Workshop is down, asleep or mid-transition.
        record(True, "tcp_workshop", "skipped: Game-only gate")
    else:
        workshop_host = args.workshop_host or workshop_host_from_container()
        if workshop_host is None:
            # proxy#48 closed the Workshop leg with no gate catching it: an
            # unverified Workshop leg fails the gate, it never slips through.
            record(
                False,
                "tcp_workshop",
                "no BLOCKFIELD_WORKSHOP_HOST: container discovery failed and none "
                "given (pass --workshop-host; proxy#48 mode: unverified leg)",
            )
        else:
            try:
                status = status_ping(args.proxy_host, args.tcp_port, workshop_host)
            except Exception as error:
                record(False, "tcp_workshop", f"workshop vhost ping failed ({error})")
            else:
                description = text(status.get("description", ""))
                # The proxy serves the gate message itself on the workshop
                # vhost (BackendRouting.onPing), and the controller writes the
                # maintenance text as that message in every non-public
                # workshop state: builders and closed show the same refusal
                # marker. So the leg expects the marker the configured gate
                # serves, and anything else (game MOTD from a misroute,
                # empty, or a ping failure above) fails: a dead backend must
                # not pass.
                closed = any(marker in description for marker in CLOSED_MARKERS)
                opened = OPEN_MARKER in description.lower() and not closed
                if args.expect_workshop == "public":
                    ok = opened
                    why = (
                        "(workshop leg open)"
                        if opened
                        else "(workshop leg closed while open expected)"
                    )
                elif args.expect_workshop in ("builders", "testers"):
                    ok = closed
                    why = (
                        "(workshop leg serves builders gate)"
                        if closed
                        else "(workshop leg down or misrouted: no builders marker)"
                    )
                else:
                    ok = closed
                    why = (
                        "(workshop leg closed as intended)"
                        if closed
                        else "(workshop leg open while closed expected)"
                    )
                record(
                    ok,
                    "tcp_workshop",
                    f"vhost={workshop_host} motd={description.strip()[:80]!r} " + why,
                )
    try:
        guid = raknet_ping(args.proxy_host, args.udp_port)
    except Exception as error:
        record(False, "raknet", f"open connection request 1 failed ({error})")
    else:
        record(True, "raknet", f"open reply 1 guid={guid}")
    if args.gate_file is not None:
        try:
            states = gate_file_states(args.gate_file)
        except (OSError, ValueError) as error:
            record(False, "gate_file", f"{args.gate_file} unreadable ({error})")
        else:
            want = {"game": args.expect_game}
            if not args.game_only:
                want["workshop"] = args.expect_workshop
            record(
                all(states.get(leg) == state for leg, state in want.items()),
                "gate_file",
                f"{states} (want {want})",
            )
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        default=None,
        help="deployed release tag (vX.Y.Z): /api/rooms build must match; "
        "omit for entry-shape checks (proxy/CP deploys keep the Game build)",
    )
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=25565)
    parser.add_argument("--udp-port", type=int, default=25566)
    parser.add_argument("--rooms-url", default="https://blockfield.pro/api/rooms")
    parser.add_argument("--gate-file", default=None)
    parser.add_argument("--workshop-host", default=None)
    parser.add_argument("--expect-game", default="public")
    parser.add_argument("--expect-workshop", default="builders")
    parser.add_argument(
        "--game-only",
        action="store_true",
        help="check the Game legs only: skip the Workshop vhost probe and "
        "the Workshop gate-file leg (Game deploys never consult the Workshop)",
    )
    args = parser.parse_args(argv)
    if args.tag is not None and not TAG.fullmatch(args.tag):
        parser.error("expected a release tag (vX.Y.Z)")
    results = check(args)
    if any(not ok for ok, _, _ in results):
        raise SystemExit(f"entry dead after {args.tag or 'deploy'}")
    print(f"entry alive after {args.tag or 'deploy'}")


if __name__ == "__main__":
    main()
