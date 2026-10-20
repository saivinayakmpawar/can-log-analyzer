"""``python -m app`` starts the server (equivalent to the uvicorn command in the README)."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        timeout_keep_alive=10,
    )
