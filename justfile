check:
    uv run --frozen python scripts/check_v2.py

format-check:
    uv run --frozen ruff format --check cpv2 tests/test_v2_models.py tests/test_v2_core.py scripts/check_v2.py

lint:
    uv run --frozen ruff check cpv2 tests/test_v2_models.py tests/test_v2_core.py scripts/check_v2.py
