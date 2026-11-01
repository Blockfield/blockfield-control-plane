import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "cpv2.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=int(os.environ.get("CP_PORT", "8080")),
        access_log=False,
        limit_concurrency=96,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=15,
    )
