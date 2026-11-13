"""Pinned gate; ephemeral PostgreSQL comes from the locked pgserver wheel."""

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sweep_stale_backends():
    """Stop and remove ephemeral PostgreSQL left by an interrupted earlier run.

    pgserver daemonizes postgres into its own session, so a run killed before
    its fixture teardown leaves it behind. Only directories older than any
    legal run (20 min + grace) are touched, and only a postgres whose command
    line names that directory is signalled.
    """
    cutoff = time.time() - 25 * 60
    for data in (ROOT / ".cache").glob("cp-pg-*"):
        if data.stat().st_mtime > cutoff:
            continue
        pid_file = next(data.rglob("postmaster.pid"), None)
        if pid_file:
            try:
                pid = int(pid_file.read_text().split()[0])
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
            except (OSError, ValueError, IndexError):
                pid = None
            if pid and str(data).encode() in cmdline:
                os.kill(pid, signal.SIGTERM)
                for _ in range(60):
                    if not Path(f"/proc/{pid}").exists():
                        break
                    time.sleep(0.5)
        shutil.rmtree(data, ignore_errors=True)


def main():
    if sys.argv[1:] not in ([], ["--review-regressions"]):
        raise SystemExit("usage: check_v2.py [--review-regressions]")
    pytest_args = ["-k", "c3_"] if sys.argv[1:] else []
    sweep_stale_backends()
    for command in (
        [
            "ruff",
            "format",
            "--check",
            "cpv2",
            "tests/test_v2_models.py",
            "tests/test_v2_core.py",
            "scripts/check_v2.py",
        ],
        [
            "ruff",
            "check",
            "cpv2",
            "tests/test_v2_models.py",
            "tests/test_v2_core.py",
            "scripts/check_v2.py",
        ],
    ):
        subprocess.run(command, check=True, cwd=ROOT, timeout=300)

    # The full suite reports every failure (no --maxfail), so it gets a longer
    # budget; on timeout, Ctrl+C or SIGTERM (CI cancel) pytest gets SIGINT
    # first so its fixtures tear the ephemeral PostgreSQL down, and only after
    # a grace period is its whole session killed. pytest runs in its own
    # session, so those signals reach only this process and are forwarded.
    def terminated(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminated)
    stops = {signal.SIGINT, signal.SIGTERM}
    # Masked across Popen so a signal cannot land between the fork and
    # `pytest` being bound; the child unmasks before exec.
    signal.pthread_sigmask(signal.SIG_BLOCK, stops)
    pytest = subprocess.Popen(
        [sys.executable, "-m", "pytest", "-q", *pytest_args],
        cwd=ROOT,
        start_new_session=True,
        preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_UNBLOCK, stops),
    )

    def stop():
        # Further Ctrl+C/SIGTERM during teardown must not cut the grace wait
        # short; the gate exits right after anyway.
        signal.pthread_sigmask(signal.SIG_BLOCK, stops)
        os.killpg(pytest.pid, signal.SIGINT)
        try:
            pytest.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(pytest.pid, signal.SIGKILL)
            pytest.wait()

    try:
        # Unmasked inside the try: a signal that arrived during Popen is
        # delivered here and still reaches stop().
        signal.pthread_sigmask(signal.SIG_UNBLOCK, stops)
        code = pytest.wait(timeout=1200)
    except subprocess.TimeoutExpired:
        stop()
        raise SystemExit("pytest exceeded 20 minutes")
    except KeyboardInterrupt:
        stop()
        raise
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
