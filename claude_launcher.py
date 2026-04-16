from __future__ import annotations

from mcp_server.server import build_server


def main() -> None:
    server = build_server()
    server.run("stdio")


if __name__ == "__main__":
    main()

