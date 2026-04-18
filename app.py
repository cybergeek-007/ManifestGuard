"""Legacy launcher for ManifestGuard v2."""

from __future__ import annotations

import os
import sys


def main() -> None:
    from backend.serve import bootstrap_python_path

    bootstrap_python_path()
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - launcher guidance
        raise SystemExit(
            "ManifestGuard v2 now uses FastAPI + React.\n"
            "Install dependencies with `pip install -r requirements.txt`, then run:\n"
            "  python app.py\n"
            "and separately:\n"
            "  cd frontend && npm install && npm run dev\n"
        ) from exc

    from backend.main import app

    uvicorn.run(
        app,
        host=os.getenv("MANIFESTGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("MANIFESTGUARD_PORT", "8000")),
        reload=os.getenv("MANIFESTGUARD_RELOAD", "0") == "1",
    )


if __name__ == "__main__":
    sys.exit(main())
