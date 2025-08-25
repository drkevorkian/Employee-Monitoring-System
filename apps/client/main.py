#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client import MonitoringClient  # type: ignore


def main():
    client = MonitoringClient()
    if client.connect_to_server():
        client.start()


if __name__ == "__main__":
    main()
