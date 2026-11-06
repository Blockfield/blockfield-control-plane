# Vendored from blockfield-server@399b45c21b33ba8ecd29cc1abd9d79001e21a7d3 scripts/deploy-webhooks.py (server#278: deploy history).
# Local differences, kept deliberately: APPS pins this repo's Dokploy app names, webhook secrets
# and the release-only :prod channel; LOGS is the deploy host's fixed path; docker() also
# translates timeouts to CalledProcessError (covered by tests/test_deploy_channel.py).
"""Deploy an exact release through the app's Dokploy webhook. Actions hold only webhook URLs, never a Dokploy API key.

The Dokploy webhook redeploys only the image configured in the app and answers before pulling. So every app is
configured once with its release-only channel tag ghcr.io/blockfield/<app>:prod: main builds keep their own tags
and only the Deploy workflow moves :prod, by digest
(`docker buildx imagetools create --tag <image>:prod <image>@sha256:<digest>`). deploy() points the channel at
the validated digest, calls the webhook and returns only when the Dokploy log shows the pull of that digest,
every running task of the swarm service runs it healthy and swarm has closed the update's monitor window.

    deploy-webhooks.py digest <app> <vX.Y.Z>   registry digest of a release image
    deploy-webhooks.py current <app>           digest of the running image (the exact rollback target)
    deploy-webhooks.py deploy <app> <digest>   <app>: control-plane
    deploy-webhooks.py serves <app> <digest>   exit 0 when every running task was started from this digest

A finished rollout appends {surface, version, digest, previous_digest, ts, run} to the host's
deploy-history.jsonl under BLOCKFIELD_MINECRAFT_ROOT and pulls the previous digest,
so a rollback re-points to a warm image instead of pulling cold.
"""

import contextlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

REGISTRY = "ghcr.io/blockfield/"
# Dokploy app name (= swarm service and log directory), the repository secret holding its webhook URL,
# and the release-only channel tag the app is configured to run (:prod).
APPS = {
    "blockfield-control-plane": (
        "blockfield-control-plane-xwcxgx",
        "DOKPLOY_CP_WEBHOOK",
        "prod",
    ),
}
# The Workshop runs the server image on its own channel; there is no blockfield-workshop package.
IMAGES = {"blockfield-workshop": "blockfield-server"}
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# Dokploy log directory on the deploy host. deploy() requires an absolute path.
LOGS = Path("/etc/dokploy/logs")
# One channel move and rollout at a time on the deploy host, whichever repository runs it.
LOCK = "/tmp/blockfield-deploy.lock"
# Held for a whole server or client deploy (validation to rollback), so the pair is never checked by one job and
# switched by another. Deploy server holds it from its workflow with flock(1).
PAIR_LOCK = "/tmp/blockfield-pair.lock"
# Webhook to healthy task on the new digest: pull, stop-first stop (grace 120 s), then the game server's health check
# (start period 600 s, 6 retries x 30 s). Measured on prod 2026-09-27: about 1.5 min.
STARTUP = 1200
# Healthy to swarm's "completed": the service's UpdateConfig.Monitor (server 120 s, proxy 60 s)
# plus this margin; 600 s when the monitor cannot be read.
MARGIN = 300
POLL = 5
# Host deploy record, read by scripts/rollback.py. The root is host configuration (configure-deploy.py);
# without it (tests, local runs) nothing is recorded or pulled.
HISTORY = "deploy-history.jsonl"


def docker(*args):
    try:
        return subprocess.run(
            ["docker", *args], text=True, capture_output=True, check=True, timeout=300
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        # The registry's answer (denied, not found) is the useful part of the failure.
        print(
            f"docker {' '.join(args[:4])}: {error.stderr.strip()[-400:]}",
            file=sys.stderr,
            flush=True,
        )
        raise
    except subprocess.TimeoutExpired as error:
        # TimeoutExpired is not a CalledProcessError: translate it so every caller
        # keeps the documented docker() failure contract.
        print(
            f"docker {' '.join(args[:4])}: timed out after {error.timeout} s",
            file=sys.stderr,
            flush=True,
        )
        raise subprocess.CalledProcessError(
            124, error.cmd, error.stdout, error.stderr
        ) from error


def repository(service):
    return REGISTRY + IMAGES.get(service, service)


def registry_digest(ref):
    return json.loads(
        docker("buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}")
    )["digest"]


def release_digest(service, tag):
    if service not in APPS or not TAG.fullmatch(tag):
        raise ValueError("Expected a known app and a release tag")
    return registry_digest(f"{repository(service)}:{tag}")


def target_digest(service, ref):
    """Registry digest for a tag-or-digest deploy input (a digest passes through)."""
    if service not in APPS:
        raise ValueError("Expected a known app and a release tag or image digest")
    if DIGEST.fullmatch(ref or ""):
        return ref
    return release_digest(service, ref)


def running(service):
    """(digests of this app's repository, health) for every running task of the swarm service."""
    ids = docker(
        "ps",
        "--no-trunc",
        "--filter",
        "label=com.docker.swarm.service.name=" + APPS[service][0],
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
        own = {
            d.split("@", 1)[1]
            for d in digests
            if d.startswith(f"{repository(service)}@")
        }
        result.append(
            (own, (container["State"].get("Health") or {}).get("Status", "none"))
        )
    return result


def runs(service, digest):
    tasks = running(service)
    return bool(tasks) and all(
        digest in own and health in ("healthy", "none") for own, health in tasks
    )


def swarm_update(service):
    """completed/updating/paused/rollback_* of the last service update; '' when it has none.

    Raises CalledProcessError when the inspect itself fails: the state is unknown, which
    deploy() must never read as a completed update.
    """
    return docker(
        "service",
        "inspect",
        APPS[service][0],
        "--format",
        "{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}",
    )


def monitor_window(service):
    try:
        # json: a plain template prints the Duration as "1m0s"
        nanoseconds = docker(
            "service",
            "inspect",
            APPS[service][0],
            "--format",
            "{{with .Spec.UpdateConfig}}{{json .Monitor}}{{end}}",
        )
        return int(nanoseconds) // 10**9 or 600
    except (subprocess.CalledProcessError, ValueError):
        return 600


def serves(service, digest):
    """Every running task was started from digest, healthy or not: which release the app is actually on."""
    tasks = running(service)
    return bool(tasks) and all(digest in own for own, _ in tasks)


def current(service):
    tasks = running(service)
    if len(tasks) != 1 or not tasks[0][0]:
        raise ValueError(
            f"{service}: the running image is not one {repository(service)} digest; no automatic rollback"
        )
    # One image can carry several repo digests (pulled under other manifests); roll back to one the registry still has.
    for digest in sorted(tasks[0][0]):
        try:
            if registry_digest(f"{repository(service)}@{digest}") == digest:
                return digest
        except subprocess.CalledProcessError:
            continue
    raise ValueError(
        f"{service}: the running image is gone from the registry; no automatic rollback"
    )


def call(service, note):
    # Docker Hub payload: Dokploy refuses (301) when the image or tag differs from the app's channel,
    # so a secret pasted into the wrong repository cannot redeploy another app.
    body = {
        "repository": {"repo_name": repository(service)},
        "push_data": {"tag": APPS[service][2], "pusher": note},
    }
    request = urllib.request.Request(
        os.environ[APPS[service][1]],
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Go-http-client/1.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
    except urllib.error.HTTPError as error:
        try:
            message = json.loads(error.read()).get("message", "")
        except ValueError:
            message = ""
        # Never print the URL: its path is the secret.
        raise SystemExit(
            f"{service}: Dokploy webhook refused ({error.code}) {message}"
        ) from None
    except urllib.error.URLError as error:
        raise SystemExit(
            f"{service}: Dokploy webhook unreachable ({type(error.reason).__name__})"
        ) from None


def dokploy_log(service, since, seen):
    logs = [
        p
        for p in (LOGS / APPS[service][0]).glob("*.log")
        if p.stat().st_mtime >= since and p not in seen
    ]
    newest = max(logs, key=lambda p: p.stat().st_mtime, default=None)
    return newest, newest.read_text(errors="replace") if newest else ""


def history_path():
    root = os.environ.get("BLOCKFIELD_MINECRAFT_ROOT", "")
    return Path(root) / HISTORY if root and Path(root).is_absolute() else None


def parse_history(text):
    records = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue  # a torn line never blocks a deploy or a rollback
        if isinstance(entry, dict):
            records.append(entry)
    return records


def read_history(path):
    try:
        return parse_history(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []


def record(surface, digest, previous, **fields):
    """Append one finished deploy to the host history; a failed write only warns (prod already switched)."""
    path = history_path()
    if path is None:
        return None
    entry = {
        "surface": surface,
        "version": None,
        **fields,
        "digest": digest,
        "previous_digest": previous,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run": "/".join(
            os.environ.get(name, "-")
            for name in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        ),
    }
    try:
        # One short O_APPEND write per deploy: concurrent writers never interleave inside a line.
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError as error:
        print(f"::warning::deploy history not written: {error}", flush=True)
    return entry


def build_info(service, digest):
    """Release and client contract baked into a server image; {} for other images or when unreadable."""
    if IMAGES.get(service, service) != "blockfield-server":
        return {}
    try:
        build = json.loads(
            docker(
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "cat",
                f"{repository(service)}@{digest}",
                "/opt/blockfield-build.json",
            )
        )
    except (subprocess.SubprocessError, OSError, ValueError):
        return {}
    return {"version": build.get("build"), "compatibility": build.get("compatibility")}


def keep_warm(service, previous):
    """Pull the previous digest so a rollback starts warm, then drop recorded images that left the window.

    The window is every surface's last digest and its previous one (two per surface); only digests this
    history recorded are ever removed, so images Dokploy or a person pulled stay. Failures only warn.
    """
    path = history_path()
    if path is None or previous is None:
        return
    image = repository(service)
    try:
        docker("pull", "--quiet", f"{image}@{previous}")
        records = read_history(path)
        last = {entry.get("surface"): entry for entry in records}
        keep = {e.get(k) for e in last.values() for k in ("digest", "previous_digest")}
        recorded = {e.get(k) for e in records for k in ("digest", "previous_digest")}
        listed = docker("image", "ls", "--digests", "--format", "{{.Digest}}", image)
        for digest in sorted((set(listed.split()) & recorded) - keep):
            try:
                docker("image", "rm", f"{image}@{digest}")
            except subprocess.CalledProcessError:
                pass  # still used by a container: it stays
    except (subprocess.SubprocessError, OSError) as error:
        print(
            f"::warning::{service}: previous image not kept warm ({type(error).__name__})",
            flush=True,
        )


def remember(service, digest, previous):
    if history_path() is None:
        return
    record(
        service.removeprefix("blockfield-"),
        digest,
        previous,
        **build_info(service, digest),
    )
    keep_warm(service, previous)


def previous_release(service, digest):
    """Rollback target for deploying digest: what runs now, unless that is digest itself.

    A re-run of the running release (unhealthy X redeployed) must not record X as its own
    previous: fall back to the newest same-surface history entry for another digest, or None.
    keep_warm pulls and keeps exactly this digest, so the window still holds the last good release.
    """
    try:
        previous = current(service)
    except (ValueError, subprocess.SubprocessError):
        return None
    if previous != digest:
        return previous
    try:
        records = read_history(history_path())
    except OSError:
        return None
    surface = service.removeprefix("blockfield-")
    # No started-row filtering here: this copy never writes status rows, so every entry is a release.
    for entry in reversed(records):
        if (
            entry.get("surface", surface) == surface
            and isinstance(entry.get("digest"), str)
            and entry["digest"] != digest
        ):
            return entry["digest"]
    return None


def wait(condition, seconds, message):
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > deadline:
            raise SystemExit(message)
        time.sleep(POLL)


@contextlib.contextmanager
def pair_lock(seconds=1800):
    if fcntl is None:
        raise RuntimeError("Production deployment locking requires a Linux runner")
    with open(PAIR_LOCK, "a") as lock:
        deadline = time.monotonic() + seconds
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise SystemExit(
                        "Another server or client deploy holds the pair lock"
                    ) from None
                print("Waiting for the pair lock", flush=True)
                time.sleep(POLL)
        yield


def deploy(service, digest):
    if service not in APPS or not DIGEST.fullmatch(digest):
        raise ValueError("Unexpected deployment target")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", APPS[service][0]):
        name = APPS[service][1].removesuffix("_WEBHOOK") + "_APP"
        raise ValueError(f"Set {name} to the deploy-host app name")
    if not LOGS.is_absolute():
        raise ValueError("Set DOKPLOY_LOG_DIR to an absolute deploy-host path")
    if fcntl is None:
        raise RuntimeError("Production deployment locking requires a Linux runner")
    image = repository(service)
    channel = APPS[service][2]
    with open(LOCK, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # The channel always names what should run, so a redeploy from the Dokploy UI repeats it.
        docker(
            "buildx",
            "imagetools",
            "create",
            "--tag",
            f"{image}:{channel}",
            f"{image}@{digest}",
        )
        wait(
            lambda: registry_digest(f"{image}:{channel}") == digest,
            120,
            f"{service}: registry does not serve the new channel",
        )
        if runs(service, digest):
            print(f"{service}: {digest} already runs, webhook not sent")
            return
        previous = None
        if history_path() is not None:
            # The history's previous_digest: what ran before this rollout (none when it is not one digest).
            previous = previous_release(service, digest)
        note = f"{os.environ.get('GITHUB_REPOSITORY', 'local')} run {os.environ.get('GITHUB_RUN_ID', '-')} {digest}"
        sent, resent, seen = time.time() - 1, False, set()
        call(service, note)
        limit, monitoring = STARTUP, False
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            path, log = dokploy_log(service, sent, seen)
            # A pull that failed or returned another digest (registry lag) left the service untouched: safe to resend once.
            if "❌" in log or ("✅" in log and "Digest: " + digest not in log):
                if resent:
                    raise SystemExit(
                        f"{service}: Dokploy deployment failed:\n"
                        + "\n".join(log.splitlines()[-8:])
                    )
                print(
                    f"{service}: Dokploy pull failed, resending the webhook once",
                    flush=True,
                )
                seen.add(path)
                resent = True
                call(service, note)
            # The update state is only this update's once a task of the digest ran healthy; before that it can be
            # the previous update's paused or rollback.
            elif log and (monitoring or runs(service, digest)):
                # Swarm may still pause or roll back the update inside its monitor window.
                try:
                    state = swarm_update(service)
                except subprocess.CalledProcessError:
                    # The update state is unknown, never a completed update: keep waiting
                    # for a readable state within the deadline instead of reporting success.
                    print(
                        f"{service}: cannot read the swarm update state, retrying",
                        flush=True,
                    )
                    state = None
                if state is not None and (
                    state.startswith("rollback") or state == "paused"
                ):
                    raise SystemExit(
                        f"{service}: swarm update {state}; see docker service ps"
                    )
                if state is not None and state != "updating" and runs(service, digest):
                    print(f"{service}: runs {digest}")
                    remember(service, digest, previous)
                    return
                if not monitoring:
                    # A slow start does not eat into the monitor window: the limit restarts here.
                    monitoring, limit = True, monitor_window(service) + MARGIN
                    deadline = time.monotonic() + limit
                    print(
                        f"{service}: healthy on {digest}, waiting up to {limit} s for swarm to complete the update",
                        flush=True,
                    )
            time.sleep(POLL)
        if monitoring:
            raise SystemExit(
                f"{service}: swarm has not completed the update {limit} s after the task became healthy; "
                "see docker service inspect"
            )
        raise SystemExit(
            f"{service}: {digest} is not running healthy after {STARTUP} s; see the Dokploy deployment log"
        )


if __name__ == "__main__":
    command, app, *rest = sys.argv[1:]
    service = "blockfield-" + app
    if command == "digest":
        print(release_digest(service, *rest))
    elif command == "current":
        print(current(service))
    elif command == "deploy":
        deploy(service, *rest)
    elif command == "serves":
        sys.exit(0 if serves(service, *rest) else 1)
    else:
        raise SystemExit(__doc__)
