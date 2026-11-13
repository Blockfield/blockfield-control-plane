import os
import uvicorn

if __name__ == "__main__":
    # Two instances share the image: the internal one (default) and the
    # public one (CP_PUBLIC_ONLY=1, exact allowlist only). Each has its own
    # connection table and DB pool, so anonymous public traffic cannot starve
    # the internal control channel; the public side caps lower and lets
    # Traefik inFlightReq/rateLimit bite first (see docs/PUBLIC.md).
    public_only = os.environ.get("CP_PUBLIC_ONLY") == "1"
    default_limit = "32" if public_only else "96"
    uvicorn.run(
        "cpv2.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=int(os.environ.get("CP_PORT", "8080")),
        access_log=False,
        limit_concurrency=int(os.environ.get("CP_LIMIT_CONCURRENCY", default_limit)),
        timeout_keep_alive=5,
        timeout_graceful_shutdown=15,
    )
