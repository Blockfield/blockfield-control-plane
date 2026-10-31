"""The deploy moves only the release-only :prod channel, never :latest, and needs no Dokploy API token."""

import importlib.util
import json
import os
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "deploy_webhooks", ROOT / "scripts" / "deploy-webhooks.py"
)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

SERVICE = "blockfield-control-plane"
DIGEST = "sha256:" + "a" * 64
PREVIOUS = "sha256:" + "b" * 64
IMAGE = "ghcr.io/blockfield/blockfield-control-plane"


class ProdChannelTest(unittest.TestCase):
    def run_deploy(self, digest, runs, swarm="completed", log=None):
        creates, webhooks = [], []

        def fake_docker(*args):
            if args[:3] == ("buildx", "imagetools", "create"):
                creates.append(args)
                return ""
            raise AssertionError(f"unexpected docker call: {args}")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"{}"

        def capture(request, timeout=30):
            webhooks.append(json.loads(request.data.decode()))
            return FakeResponse()

        with (
            patch.object(deploy, "docker", side_effect=fake_docker),
            patch.object(
                deploy, "registry_digest", return_value=digest
            ) as registry_digest,
            patch.object(deploy, "runs", side_effect=runs),
            patch.object(
                deploy,
                "dokploy_log",
                return_value=(
                    "p",
                    log if log is not None else "✅ pulled\nDigest: " + digest,
                ),
            ),
            patch.object(deploy, "swarm_update", return_value=swarm),
            patch.object(urllib.request, "urlopen", side_effect=capture),
            patch.dict(os.environ, {"DOKPLOY_CP_WEBHOOK": "https://dokploy.invalid/hook"}),
        ):
            deploy.deploy(SERVICE, digest)
        return creates, webhooks, registry_digest

    def test_channel_move_and_wait_target_prod(self):
        creates, webhooks, registry_digest = self.run_deploy(DIGEST, [True])
        (create,) = creates
        tag = create[create.index("--tag") + 1]
        self.assertEqual(tag, f"{IMAGE}:prod")
        self.assertEqual(create[-1], f"{IMAGE}@{DIGEST}")
        registry_digest.assert_called_once_with(f"{IMAGE}:prod")
        # Already running: the channel still names the digest, no webhook sent.
        self.assertEqual(webhooks, [])

    def test_webhook_redeploys_the_prod_channel(self):
        creates, webhooks, _ = self.run_deploy(DIGEST, [False, True, True])
        self.assertEqual(len(creates), 1)
        (hook,) = webhooks
        self.assertEqual(hook["repository"], {"repo_name": IMAGE})
        self.assertEqual(hook["push_data"]["tag"], "prod")

    def test_failed_deploy_rolls_back_by_moving_prod_back(self):
        with self.assertRaises(SystemExit):
            self.run_deploy(DIGEST, [False, True], swarm="paused")
        # Rollback is a deploy of the previous digest: the channel moves back
        # to it and the webhook redeploys it.
        creates, webhooks, _ = self.run_deploy(PREVIOUS, [False, True, True])
        (create,) = creates
        tag = create[create.index("--tag") + 1]
        self.assertEqual(tag, f"{IMAGE}:prod")
        self.assertEqual(create[-1], f"{IMAGE}@{PREVIOUS}")
        (hook,) = webhooks
        self.assertEqual(hook["push_data"]["tag"], "prod")

    def test_no_dokploy_api_token_in_workflows(self):
        for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            text = workflow.read_text()
            self.assertNotIn("DOKPLOY_API_TOKEN", text, workflow.name)
            self.assertNotIn("saveDockerProvider", text, workflow.name)
        self.assertFalse((ROOT / "scripts" / "dokploy-pin.py").exists())


if __name__ == "__main__":
    unittest.main()
