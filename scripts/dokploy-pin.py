"""Pin the prod control-plane image by digest in Dokploy and verify it.

The Dokploy app is configured with a digest-pinned image
ghcr.io/blockfield/blockfield-control-plane@sha256:<digest> (Docker provider: only dockerImage; authentication
uses the centrally configured GHCR registry, so no per-app registry credentials). deploy() pins the target digest
via the Dokploy API, redeploys and returns only when every running task of the swarm service was started from that
digest and swarm has closed the update's monitor window. On failure the previous (running) digest is re-pinned:
rollback is a redeploy of the previous digest (see docs/DEPLOY.md).

Usage: dokploy-pin.py deploy [sha256:<digest>]   (default: the digest :latest currently serves)
       dokploy-pin.py verify <sha256:digest>
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

SERVICE = "blockfield-control-plane"
APP_NAME = "blockfield-control-plane-xwcxgx"
APPLICATION_ID = "DyQyXrajbCB3qiHl3MBQF"
IMAGE = "ghcr.io/blockfield/blockfield-control-plane"
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TIMEOUT = int(os.environ.get("DOKPLOY_PIN_TIMEOUT", "1200"))
POLL = int(os.environ.get("DOKPLOY_PIN_POLL", "5"))


def docker(*args):
    try:
        return subprocess.run(
            ["docker", *args],
            text=True,
            capture_output=True,
            check=True,
            timeout=120,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        print(
            f"docker {' '.join(args[:4])}: {error.stderr.strip()[-400:]}",
            file=sys.stderr,
            flush=True,
        )
        raise


def registry_digest(ref):
    return json.loads(
        docker("buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}")
    )["digest"]


def running():
    """(digests of our image) for every running task of the swarm service."""
    ids = docker(
        "ps",
        "--no-trunc",
        "--filter",
        "label=com.docker.swarm.service.name=" + APP_NAME,
        "--format",
        "{{.ID}}",
    ).split()
    result = []
    for cid in ids:
        container = json.loads(docker("inspect", cid))[0]
        digests = (
            json.loads(docker("image", "inspect", container["Image"]))[0].get(
                "RepoDigests"
            )
            or []
        )
        result.append(
            {d.split("@", 1)[1] for d in digests if d.startswith(f"{IMAGE}@")}
        )
    return result


def serves(digest):
    tasks = running()
    return bool(tasks) and all(digest in own for own in tasks)


def current():
    """Digest the running tasks were started from (the exact rollback target)."""
    tasks = running()
    if len(tasks) != 1 or len(tasks[0]) != 1:
        raise ValueError(
            f"{SERVICE}: the running image is ambiguous; no automatic rollback"
        )
    (digest,) = tasks[0]
    if registry_digest(f"{IMAGE}@{digest}") != digest:
        raise ValueError(
            f"{SERVICE}: the running image is gone from the registry; no automatic rollback"
        )
    return digest


def swarm_state():
    """completed/updating/paused/rollback_* of the last service update; '' when it has none."""
    return docker(
        "service", "inspect", APP_NAME, "--format", "{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}"
    )


def dokploy_api(path, payload):
    base = os.environ.get("DOKPLOY_API_URL", "").rstrip("/")
    token = os.environ.get("DOKPLOY_API_TOKEN", "")
    if not base or not token:
        raise SystemExit(
            f"{SERVICE}: set DOKPLOY_API_URL (Dokploy dashboard base URL) and DOKPLOY_API_TOKEN "
            "(Dokploy profile settings -> API/CLI) repository secrets before deploying; see docs/DEPLOY.md"
        )
    request = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "x-api-key": token},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
    except urllib.error.HTTPError as error:
        # Never print the token: it travels only in the request header.
        raise SystemExit(f"{SERVICE}: Dokploy API {path} refused ({error.code})") from None
    except urllib.error.URLError as error:
        raise SystemExit(
            f"{SERVICE}: Dokploy API unreachable ({type(error.reason).__name__})"
        ) from None


def pin(digest):
    if not DIGEST.fullmatch(digest):
        raise ValueError("Expected an immutable image digest")
    dokploy_api(
        "/api/application.saveDockerProvider",
        {
            "applicationId": APPLICATION_ID,
            "dockerImage": f"{IMAGE}@{digest}",
            "username": None,
            "password": None,
            "registryUrl": None,
        },
    )


def redeploy():
    dokploy_api("/api/application.redeploy", {"applicationId": APPLICATION_ID})


def verify(digest):
    """Every running task serves the digest and the swarm update has settled."""
    deadline = time.monotonic() + TIMEOUT
    while True:
        try:
            state = swarm_state()
        except subprocess.CalledProcessError:
            print(f"{SERVICE}: cannot read the swarm update state, retrying", flush=True)
            state = None
        settled = state is not None and not state.startswith("rollback") and state not in ("paused", "updating")
        if settled and serves(digest):
            print(f"{SERVICE}: runs {digest}")
            return
        if state is not None and (state.startswith("rollback") or state == "paused"):
            raise SystemExit(f"{SERVICE}: swarm update {state}; see docker service ps")
        if time.monotonic() >= deadline:
            raise SystemExit(f"{SERVICE}: {digest} is not serving after {TIMEOUT} s")
        time.sleep(POLL)


def deploy(target=None):
    digest = target or registry_digest(f"{IMAGE}:latest")
    if not DIGEST.fullmatch(digest):
        raise ValueError("Expected an immutable image digest")
    previous = current()
    if previous == digest:
        print(f"{SERVICE}: {digest} already serves, pin refreshed without redeploy")
        pin(digest)
        return
    pin(digest)
    try:
        redeploy()
        verify(digest)
    except BaseException:
        print(f"{SERVICE}: rolling back to {previous}", flush=True)
        try:
            pin(previous)
            redeploy()
            verify(previous)
        except BaseException as rollback_error:
            raise SystemExit(
                f"{SERVICE}: deploy of {digest} failed AND rollback to {previous} failed: {rollback_error}"
            ) from None
        raise


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "deploy":
        deploy(*sys.argv[2:3])
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify(sys.argv[2])
    else:
        raise SystemExit(__doc__)
