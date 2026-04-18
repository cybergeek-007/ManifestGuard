from __future__ import annotations

import argparse
import os
import site
import sys
from pathlib import Path


def bootstrap_python_path() -> Path:
    project_root = Path(__file__).resolve().parent.parent
    workspace_deps = project_root / ".pydeps"
    if workspace_deps.exists():
        sys.path.insert(0, str(workspace_deps))

    try:
        user_site = site.getusersitepackages()
    except Exception:
        user_site = None
    if user_site and user_site not in sys.path:
        sys.path.append(user_site)
    return project_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ManifestGuard API server.")
    parser.add_argument("--host", default=os.getenv("MANIFESTGUARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MANIFESTGUARD_PORT", "8000")))
    parser.add_argument("--reload", action="store_true", default=os.getenv("MANIFESTGUARD_RELOAD", "0") == "1")
    return parser.parse_args()


def main() -> None:
    bootstrap_python_path()
    import uvicorn
    from backend.main import app

    args = parse_args()
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
