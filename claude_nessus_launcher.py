from __future__ import annotations

from mcp_server.nessus_server import build_nessus_server


def main() -> None:
    server = build_nessus_server()
    server.run("stdio")


if __name__ == "__main__":
    main()
