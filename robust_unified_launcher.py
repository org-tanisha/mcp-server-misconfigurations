import sys
import os
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Force create/open log file with flush
log_file = project_root / "unified_server.log"
f = open(log_file, "a+", encoding="utf-8")
f.write("\n--- Unified Server Starting ---\n")
f.flush()
sys.stderr = f

from mcp_server.unified_server import build_unified_server

def main():
    try:
        f.write("Building server...\n")
        f.flush()
        server = build_unified_server()
        f.write("Server built, running stdio...\n")
        f.flush()
        server.run("stdio")
    except Exception as e:
        import traceback
        f.write(f"Server Error: {e}\n")
        traceback.print_exc(file=f)
        f.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()
