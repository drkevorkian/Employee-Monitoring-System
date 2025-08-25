#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Ensure project root on path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import MonitoringServer, MonitoringServerGUI  # type: ignore
from PySide6.QtWidgets import QApplication


def main():
    app = QApplication(sys.argv)
    server = MonitoringServer()
    gui = MonitoringServerGUI(server)
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
