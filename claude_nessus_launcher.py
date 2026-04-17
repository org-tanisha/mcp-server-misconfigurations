import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Log to file for robustness
log_file = project_root / "nessus_server.log"
f = open(log_file, "a+", encoding="utf-8")
f.write("\n--- Nessus Launcher Starting ---\n")
f.flush()
sys.stderr = f

from mcp_server.nessus_server import build_nessus_server

def main():
    try:
        server = build_nessus_server()
        server.run("stdio")
    except Exception as e:
        import traceback
        f.write(f"Server Error: {e}\n")
        traceback.print_exc(file=f)
        f.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()
