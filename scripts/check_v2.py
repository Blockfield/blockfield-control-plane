"""Pinned gate; ephemeral PostgreSQL comes from the locked pgserver wheel."""

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
        [sys.executable, "-m", "pytest", "-q", *pytest_args],
    ):
        subprocess.run(command, check=True, cwd=ROOT, timeout=300)


if __name__ == "__main__":
    main()
