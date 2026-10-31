"""Dokploy digest pin for control-plane: pin payload, verify, rollback, fail-closed."""

import importlib.util
import json
import os
import stat
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("DOKPLOY_PIN_TIMEOUT", "60")
os.environ.setdefault("DOKPLOY_PIN_POLL", "0")

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "dokploy_pin", ROOT / "scripts" / "dokploy-pin.py"
)
pinmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pinmod)

IMAGE = "ghcr.io/blockfield/blockfield-control-plane"
NEW = "a" * 64
OLD = "b" * 64

# Stub docker replays canned answers; the fake Dokploy API flips `running` on redeploy.
DOCKER_STUB = """#!/bin/bash
echo "docker $*" >> "$CALLS"
state="$STATE"
case "$*" in
  *"buildx imagetools inspect"*)
    if [[ "$*" == *":latest"* ]]; then digest="$(cat "$state/latest")"; else all="$*"; digest="${all##*@}"; digest="${digest%% *}"; fi
    echo "{\\"digest\\": \\"$digest\\"}"
    ;;
  "ps"*) echo "cid1" ;;
  "inspect cid1") echo '[{"Image":"imgref1"}]' ;;
  "image inspect imgref1") echo "[{\\"RepoDigests\\": [\\"$IMAGE@$(cat "$state/running")\\"]}]" ;;
  "service inspect"*) cat "$state/swarm" ;;
esac
"""


class Harness:
    """Fake Dokploy API + stub docker + stub PATH for one test."""

    def __init__(self, test, latest=NEW, running=OLD, swarm="completed"):
        self.test = test
        self.calls = []
        self.state = Path(test.tmp) / "state"
        self.state.mkdir()
        (self.state / "latest").write_text(f"sha256:{latest}")
        (self.state / "running").write_text(f"sha256:{running}")
        (self.state / "swarm").write_text(swarm)
        bin_dir = Path(test.tmp) / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(
            DOCKER_STUB.replace("$IMAGE@", IMAGE + "@"), newline="\n"
        )
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        harness = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                harness.calls.append(
                    {
                        "path": self.path,
                        "key": self.headers.get("x-api-key"),
                        "body": body,
                    }
                )
                if self.path == "/api/application.saveDockerProvider":
                    (harness.state / "pinned").write_text(
                        body["dockerImage"].split("@", 1)[1]
                    )
                elif self.path == "/api/application.redeploy":
                    pinned = (harness.state / "pinned").read_text()
                    (harness.state / "running").write_text(pinned)
                payload = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._env = patch.dict(
            os.environ,
            {
                "PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin",
                "CALLS": str(Path(test.tmp) / "calls"),
                "STATE": str(self.state),
                "DOKPLOY_API_URL": f"http://127.0.0.1:{self.server.server_port}",
                "DOKPLOY_API_TOKEN": "test-token",
            },
        )
        self._env.start()

    def stop(self):
        self._env.stop()
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


class PinDeployTest(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(
            lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True)
        )

    def harness(self, **kwargs):
        harness = Harness(self, **kwargs)
        self.addCleanup(harness.stop)
        return harness

    def test_deploy_pins_the_latest_digest_and_verifies_it(self):
        api = self.harness()
        pinmod.deploy()
        self.assertEqual(
            [call["path"] for call in api.calls],
            ["/api/application.saveDockerProvider", "/api/application.redeploy"],
        )
        body = api.calls[0]["body"]
        self.assertEqual(
            body,
            {
                "applicationId": "DyQyXrajbCB3qiHl3MBQF",
                "dockerImage": f"{IMAGE}@sha256:{NEW}",
                "username": None,
                "password": None,
                "registryUrl": None,
            },
        )
        self.assertEqual(api.calls[0]["key"], "test-token")
        self.assertEqual((api.state / "running").read_text(), f"sha256:{NEW}")

    def test_deploy_accepts_an_explicit_digest(self):
        api = self.harness(latest=OLD)
        pinmod.deploy(f"sha256:{NEW}")
        self.assertEqual(
            api.calls[0]["body"]["dockerImage"], f"{IMAGE}@sha256:{NEW}"
        )

    def test_deploy_of_the_running_digest_refreshes_the_pin_without_redeploy(self):
        api = self.harness(latest=OLD, running=OLD)
        pinmod.deploy(f"sha256:{OLD}")
        self.assertEqual(
            [call["path"] for call in api.calls],
            ["/api/application.saveDockerProvider"],
        )
        self.assertEqual(
            api.calls[0]["body"]["dockerImage"], f"{IMAGE}@sha256:{OLD}"
        )

    def test_failed_deploy_re_pins_the_previous_digest(self):
        api = self.harness(swarm="paused")
        with self.assertRaises(SystemExit):
            pinmod.deploy()
        self.assertEqual(
            [call["path"] for call in api.calls],
            [
                "/api/application.saveDockerProvider",
                "/api/application.redeploy",
                "/api/application.saveDockerProvider",
                "/api/application.redeploy",
            ],
        )
        self.assertEqual(
            api.calls[0]["body"]["dockerImage"], f"{IMAGE}@sha256:{NEW}"
        )
        self.assertEqual(
            api.calls[2]["body"]["dockerImage"], f"{IMAGE}@sha256:{OLD}"
        )
        self.assertEqual((api.state / "running").read_text(), f"sha256:{OLD}")

    def test_pin_fails_closed_without_api_credentials(self):
        self.harness()
        with patch.dict(os.environ, {"DOKPLOY_API_TOKEN": ""}):
            with self.assertRaisesRegex(SystemExit, "DOKPLOY_API_TOKEN"):
                pinmod.deploy()
        with patch.dict(os.environ, {"DOKPLOY_API_URL": ""}):
            with self.assertRaisesRegex(SystemExit, "DOKPLOY_API_URL"):
                pinmod.deploy()


if __name__ == "__main__":
    unittest.main()
