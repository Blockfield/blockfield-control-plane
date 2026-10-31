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
- raknet: the RakNet listener players actually use answers an unconnected
  ping (transport alive; raknetify answers below the login gate).
- gate_file: the host file leg matches the expected states, so an intended
  maintenance reads as SKIP-worthy instead of a mysterious ping failure.

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
# RakNet unconnected ping magic, answered by raknetify below the login gate.
RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
RAKNET_PING_ID = 0x01
RAKNET_PONG_ID = 0x1C
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
    """One RakNet unconnected ping; returns the server MOTD string."""
    packet = struct.pack(">Bq", RAKNET_PING_ID, 0x123456) + RAKNET_MAGIC
    packet += struct.pack(">q", 0x789ABC)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(2048)
    if len(data) < 35 or data[0] != RAKNET_PONG_ID:
        raise ValueError("not a RakNet pong")
    if data[17:33] != RAKNET_MAGIC:
        raise ValueError("RakNet pong magic mismatch")
    size = struct.unpack(">H", data[33:35])[0]
    return data[35 : 35 + size].decode("utf-8", "replace")


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
            # proxy#55: a closed leg serves a non-empty MOTD, so bool() passed
            # a shut Workshop. Apply the same marker logic as the game leg.
            closed = any(marker in description for marker in CLOSED_MARKERS)
            opened = OPEN_MARKER in description.lower() and not closed
            want_open = args.expect_workshop in ("public", "builders")
            record(
                opened == want_open,
                "tcp_workshop",
                f"vhost={workshop_host} motd={description.strip()[:80]!r} "
                + (
                    "(workshop leg open)"
                    if opened
                    else (
                        "(workshop leg closed as intended)"
                        if not want_open
                        else "(workshop leg closed while builders expected)"
                    )
                ),
            )
    try:
        motd = raknet_ping(args.proxy_host, args.udp_port)
    except Exception as error:
        record(False, "raknet", f"unconnected ping failed ({error})")
    else:
        record(True, "raknet", f"pong motd={motd[:80]!r}")
    if args.gate_file is not None:
        try:
            states = gate_file_states(args.gate_file)
        except (OSError, ValueError) as error:
            record(False, "gate_file", f"{args.gate_file} unreadable ({error})")
        else:
            want = {"game": args.expect_game, "workshop": args.expect_workshop}
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
    args = parser.parse_args(argv)
    if args.tag is not None and not TAG.fullmatch(args.tag):
        parser.error("expected a release tag (vX.Y.Z)")
    results = check(args)
    if any(not ok for ok, _, _ in results):
        raise SystemExit(f"entry dead after {args.tag or 'deploy'}")
    print(f"entry alive after {args.tag or 'deploy'}")


if __name__ == "__main__":
    main()
