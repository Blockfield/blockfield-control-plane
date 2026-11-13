"""Pinned gate; ephemeral PostgreSQL comes from the locked pgserver wheel."""

import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.argv[1:] not in ([], ["--review-regressions"]):
        raise SystemExit("usage: check_v2.py [--review-regressions]")
    pytest_args = ["-k", "c3_"] if sys.argv[1:] else []
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
    # budget; on timeout pytest gets SIGINT first so its fixtures tear the
    # ephemeral PostgreSQL down instead of being killed mid-run.
    # Own session: the final kill takes pytest and its PostgreSQL child
    # together, so a hung run never leaves the backend behind.
    pytest = subprocess.Popen(
        [sys.executable, "-m", "pytest", "-q", *pytest_args],
        cwd=ROOT,
        start_new_session=True,
    )

    def terminated(signum, frame):
        # CI cancels by SIGTERM; route it through the same cleanup as Ctrl+C.
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminated)

    def stop():
        # SIGINT first so fixtures tear the backend down; then the group.
        os.killpg(pytest.pid, signal.SIGINT)
        try:
            pytest.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(pytest.pid, signal.SIGKILL)
            pytest.wait()

    try:
        code = pytest.wait(timeout=1200)
    except subprocess.TimeoutExpired:
        stop()
        raise SystemExit("pytest exceeded 20 minutes")
    except KeyboardInterrupt:
        # Ctrl+C and SIGTERM reach only this process (pytest has its own session).
        stop()
        raise
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
