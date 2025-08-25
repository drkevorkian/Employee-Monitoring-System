import json
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Dict, Optional

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QObject, QSortFilterProxyModel, QFileSystemWatcher
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


@dataclass
class Bug:
    bug_id: str
    description: str
    status: str
    severity: str
    category: str


class BugRepository(QObject):
    """Loads bugs from history text and applies local overrides."""

    def __init__(self, history_path: str, overrides_path: str):
        super().__init__()
        self.history_path = history_path
        self.overrides_path = overrides_path
        self.quick_wins: List[str] = []
        self._overrides: Dict[str, Dict[str, str]] = {}

    def load(self) -> List[Bug]:
        bugs = self._parse_history()
        self._load_overrides()
        # Apply overrides on top of parsed data
        for bug in bugs:
            if bug.bug_id in self._overrides:
                override = self._overrides[bug.bug_id]
                bug.status = override.get("status", bug.status)
                bug.severity = override.get("severity", bug.severity)
        return bugs

    def _load_overrides(self) -> None:
        try:
            if os.path.exists(self.overrides_path):
                with open(self.overrides_path, "r", encoding="utf-8") as f:
                    self._overrides = json.load(f)
            else:
                self._overrides = {}
        except Exception:
            self._overrides = {}

    def save_override(self, bug: Bug) -> None:
        self._overrides[bug.bug_id] = {
            "status": bug.status,
            "severity": bug.severity,
        }
        os.makedirs(os.path.dirname(self.overrides_path), exist_ok=True)
        with open(self.overrides_path, "w", encoding="utf-8") as f:
            json.dump(self._overrides, f, indent=2)

    def _parse_history(self) -> List[Bug]:
        bugs: List[Bug] = []
        self.quick_wins = []
        if not os.path.exists(self.history_path):
            return bugs

        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                lines = [line.rstrip("\n") for line in f]
        except UnicodeDecodeError:
            with open(self.history_path, "r", encoding="latin-1") as f:
                lines = [line.rstrip("\n") for line in f]

        current_category = "General"
        in_quick_wins = False

        # Regex: ID, em-dash or hyphen, description, Status: X., Severity: Y.
        id_desc_status_sev = re.compile(
            r"^(?P<id>[A-Z]+-\d+)\s+[—-]\s+(?P<desc>.*?)(?:\s+Status:\s*(?P<status>[A-Za-z]+)\.)\s+Severity:\s*(?P<severity>[A-Za-z]+)\.$"
        )

        for raw in lines:
            line = raw.strip()
            if not line:
                continue

            # Section headers
            if line.lower().startswith("quick wins"):
                in_quick_wins = True
                continue

            header_match = re.match(r"^[A-Za-z].*\)$", line)
            if header_match and not line.startswith("Bug list") and not in_quick_wins:
                current_category = line
                continue

            if in_quick_wins:
                # Treat non-empty lines as quick wins until next section or EOF
                if not (line.endswith(":") or re.match(r"^[A-Za-z].*\)$", line)):
                    self.quick_wins.append(line)
                continue

            m = id_desc_status_sev.match(line)
            if m:
                bug = Bug(
                    bug_id=m.group("id"),
                    description=m.group("desc").strip(),
                    status=m.group("status").strip().capitalize(),
                    severity=m.group("severity").strip().capitalize(),
                    category=current_category,
                )
                bugs.append(bug)

        return bugs


class BugTableModel(QAbstractTableModel):
    HEADERS = ["ID", "Category", "Description", "Status", "Severity"]

    def __init__(self, bugs: List[Bug]):
        super().__init__()
        self._bugs = bugs

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # type: ignore[override]
        return len(self._bugs)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # type: ignore[override]
        return len(self.HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):  # type: ignore[override]
        if not index.isValid():
            return None
        bug = self._bugs[index.row()]
        col = index.column()
        if role in (Qt.DisplayRole, Qt.EditRole):
            if col == 0:
                return bug.bug_id
            if col == 1:
                return bug.category
            if col == 2:
                return bug.description
            if col == 3:
                return bug.status
            if col == 4:
                return bug.severity
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):  # type: ignore[override]
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def bug_at(self, row: int) -> Optional[Bug]:
        if 0 <= row < len(self._bugs):
            return self._bugs[row]
        return None

    def set_bugs(self, bugs: List[Bug]) -> None:
        self.beginResetModel()
        self._bugs = bugs
        self.endResetModel()


class BugFilterProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.search_text = ""
        self.status_filter = "All"
        self.severity_filter = "All"
        self.category_filter = "All"

    def set_filters(self, search: str, status: str, severity: str, category: str) -> None:
        self.search_text = search.lower()
        self.status_filter = status
        self.severity_filter = severity
        self.category_filter = category
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # type: ignore[override]
        model: BugTableModel = self.sourceModel()  # type: ignore[assignment]
        bug = model.bug_at(source_row)
        if bug is None:
            return True

        if self.status_filter != "All" and bug.status != self.status_filter:
            return False
        if self.severity_filter != "All" and bug.severity != self.severity_filter:
            return False
        if self.category_filter != "All" and bug.category != self.category_filter:
            return False

        if self.search_text:
            hay = f"{bug.bug_id} {bug.category} {bug.description} {bug.status} {bug.severity}".lower()
            return self.search_text in hay
        return True


class BugViewer(QMainWindow):
    def __init__(self, history_path: str):
        super().__init__()

        self.setWindowTitle("Bug Tracker - Interactive Viewer")
        self.resize(1100, 700)

        overrides_path = os.path.join(os.path.dirname(history_path), "overrides.json")
        self.repo = BugRepository(history_path, overrides_path)
        self.bugs = self.repo.load()

        # Central UI setup
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # Top filter/search bar
        top = QHBoxLayout()
        main_layout.addLayout(top)

        top.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search ID, description, category...")
        top.addWidget(self.search_edit, 2)

        top.addWidget(QLabel("Status:"))
        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "Open", "Verify", "Closed"])
        top.addWidget(self.status_combo)

        top.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All", "Low", "Medium", "High", "Critical"])
        top.addWidget(self.severity_combo)

        top.addWidget(QLabel("Category:"))
        self.category_combo = QComboBox()
        self.category_combo.addItem("All")
        for c in sorted({b.category for b in self.bugs}):
            self.category_combo.addItem(c)
        top.addWidget(self.category_combo)

        # Splitter with table and details
        splitter = QSplitter()
        main_layout.addWidget(splitter, 1)

        # Table
        self.model = BugTableModel(self.bugs)
        self.proxy = BugFilterProxy()
        self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        splitter.addWidget(self.table)

        # Details panel
        details_container = QWidget()
        details_layout = QVBoxLayout(details_container)
        details_layout.setContentsMargins(8, 8, 8, 8)
        details_layout.setSpacing(8)

        self.details_title = QLabel("Select a bug to see details")
        self.details_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        details_layout.addWidget(self.details_title)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(200)
        details_layout.addWidget(self.details_text, 1)

        # Status/severity editors
        edit_row = QHBoxLayout()
        edit_row.addWidget(QLabel("Status:"))
        self.edit_status = QComboBox()
        self.edit_status.addItems(["Open", "Verify", "Closed"]) 
        edit_row.addWidget(self.edit_status)

        edit_row.addWidget(QLabel("Severity:"))
        self.edit_severity = QComboBox()
        self.edit_severity.addItems(["Low", "Medium", "High", "Critical"]) 
        edit_row.addStretch(1)
        details_layout.addLayout(edit_row)

        btn_row = QHBoxLayout()
        self.apply_btn = QPushButton("Apply Update")
        self.export_json_btn = QPushButton("Export JSON")
        self.export_csv_btn = QPushButton("Export CSV")
        self.reload_btn = QPushButton("Reload")
        btn_row.addWidget(self.apply_btn)
        btn_row.addWidget(self.export_json_btn)
        btn_row.addWidget(self.export_csv_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(self.reload_btn)
        details_layout.addLayout(btn_row)

        # Quick wins viewer
        self.quick_wins = QTextEdit()
        self.quick_wins.setReadOnly(True)
        self.quick_wins.setPlaceholderText("Quick wins will appear here if present in history.txt")
        details_layout.addWidget(QLabel("Quick wins:"))
        details_layout.addWidget(self.quick_wins)

        splitter.addWidget(details_container)
        splitter.setSizes([700, 400])

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Actions (menu)
        self._create_actions()

        # Connections
        self.search_edit.textChanged.connect(self._update_filters)
        self.status_combo.currentIndexChanged.connect(self._update_filters)
        self.severity_combo.currentIndexChanged.connect(self._update_filters)
        self.category_combo.currentIndexChanged.connect(self._update_filters)
        self.table.selectionModel().currentRowChanged.connect(self._sync_selection)
        self.apply_btn.clicked.connect(self._apply_update)
        self.export_json_btn.clicked.connect(self._export_json)
        self.export_csv_btn.clicked.connect(self._export_csv)
        self.reload_btn.clicked.connect(self._reload)

        # File watcher for live reload
        self.watcher = QFileSystemWatcher([history_path])
        self.watcher.fileChanged.connect(self._on_file_changed)

        self._refresh_counts()
        self._load_quick_wins()

        # Initial selection
        if self.proxy.rowCount() > 0:
            self.table.selectRow(0)

        # Light theme styling with blizzard blue accents
        self._apply_light_theme()

    def _create_actions(self) -> None:
        dark_toggle = QAction("Toggle Dark Mode", self)
        dark_toggle.setCheckable(True)
        dark_toggle.toggled.connect(self._toggle_theme)
        self.menuBar().addAction(dark_toggle)

        open_action = QAction("Open History...", self)
        open_action.triggered.connect(self._open_history)
        self.menuBar().addAction(open_action)

    def _apply_light_theme(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #FFFFFF; color: #212529; }
            /* Table colors tuned for readability */
            QTableView {
                background: #FFFFFF;
                color: #212529;
                alternate-background-color: #F8F9FA;
                gridline-color: #E9ECEF;
                selection-background-color: #00BFFF;
                selection-color: #FFFFFF;
            }
            QTableView::item:selected {
                background: #00BFFF;
                color: #FFFFFF;
            }
            QHeaderView::section {
                background: #F1F3F5;
                color: #212529;
                padding: 6px;
                border: 1px solid #DEE2E6;
            }
            QTableCornerButton::section {
                background: #F1F3F5; border: 1px solid #DEE2E6;
            }
            QPushButton { background-color: #00BFFF; color: #FFFFFF; border: none; padding: 8px 14px; border-radius: 6px; }
            QPushButton:hover { background-color: #00A5E0; }
            QPushButton:disabled { background-color: #B0C4DE; }
            QLineEdit, QTextEdit, QComboBox { background: #FFFFFF; color: #212529; border: 1px solid #CED4DA; border-radius: 6px; padding: 6px; }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border: 2px solid #00BFFF; }
            QStatusBar { background: #F8F9FA; color: #212529; }
            """
        )

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #1E1E1E; color: #EAEAEA; }
            QLabel { color: #EAEAEA; }
            QTableView {
                background: #232323;
                alternate-background-color: #1B1B1B;
                color: #EAEAEA;
                gridline-color: #2C2C2C;
                selection-background-color: #00BFFF;
                selection-color: #000000;
            }
            QTableView::item:selected {
                background: #00BFFF;
                color: #000000;
            }
            QHeaderView::section { background: #2C2C2C; color: #EAEAEA; padding: 6px; border: 1px solid #3A3A3A; }
            QPushButton { background-color: #00BFFF; color: #000000; border: none; padding: 8px 14px; border-radius: 6px; font-weight: bold; }
            QPushButton:hover { background-color: #00A5E0; }
            QLineEdit, QTextEdit, QComboBox { background: #2B2B2B; color: #EAEAEA; border: 1px solid #3A3A3A; border-radius: 6px; padding: 6px; }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border: 2px solid #00BFFF; }
            QStatusBar { background: #2B2B2B; color: #EAEAEA; }
            """
        )

    def _toggle_theme(self, checked: bool) -> None:
        if checked:
            self._apply_dark_theme()
        else:
            self._apply_light_theme()

    def _open_history(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open history.txt", os.path.dirname(self.repo.history_path), "Text Files (*.txt)")
        if path:
            self.repo.history_path = path
            self.watcher.removePaths(self.watcher.files())
            self.watcher.addPath(path)
            self._reload()

    def _on_file_changed(self, _path: str) -> None:
        # Debounce by re-adding watcher and reloading
        self.watcher.removePaths(self.watcher.files())
        if os.path.exists(self.repo.history_path):
            self.watcher.addPath(self.repo.history_path)
        self._reload()

    def _reload(self) -> None:
        self.bugs = self.repo.load()
        self.model.set_bugs(self.bugs)
        self._populate_categories()
        self._update_filters()
        self._refresh_counts()
        self._load_quick_wins()

    def _populate_categories(self) -> None:
        current = self.category_combo.currentText() if self.category_combo.count() else "All"
        self.category_combo.blockSignals(True)
        self.category_combo.clear()
        self.category_combo.addItem("All")
        for c in sorted({b.category for b in self.bugs}):
            self.category_combo.addItem(c)
        # Try to restore selection
        idx = self.category_combo.findText(current)
        self.category_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.category_combo.blockSignals(False)

    def _load_quick_wins(self) -> None:
        if self.repo.quick_wins:
            self.quick_wins.setPlainText("\n".join(self.repo.quick_wins))
        else:
            self.quick_wins.clear()

    def _update_filters(self) -> None:
        self.proxy.set_filters(
            self.search_edit.text(),
            self.status_combo.currentText(),
            self.severity_combo.currentText(),
            self.category_combo.currentText(),
        )
        self._refresh_counts()

    def _refresh_counts(self) -> None:
        # Compute counts from model data (with overrides applied)
        open_cnt = sum(1 for b in self.bugs if b.status == "Open")
        verify_cnt = sum(1 for b in self.bugs if b.status == "Verify")
        closed_cnt = sum(1 for b in self.bugs if b.status == "Closed")
        total = len(self.bugs)
        self.status_bar.showMessage(
            f"Total: {total}  |  Open: {open_cnt}  |  Verify: {verify_cnt}  |  Closed: {closed_cnt}"
        )

    def _sync_selection(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            self.details_title.setText("Select a bug to see details")
            self.details_text.clear()
            return
        source_row = self.proxy.mapToSource(current).row()
        bug = self.model.bug_at(source_row)
        if not bug:
            return
        self.details_title.setText(f"{bug.bug_id}  —  {bug.category}")
        self.details_text.setPlainText(bug.description)
        # Populate editors
        self.edit_status.setCurrentText(bug.status)
        self.edit_severity.setCurrentText(bug.severity)

    def _get_selected_bug(self) -> Optional[Bug]:
        sel = self.table.selectionModel().currentIndex()
        if not sel.isValid():
            return None
        return self.model.bug_at(self.proxy.mapToSource(sel).row())

    def _apply_update(self) -> None:
        bug = self._get_selected_bug()
        if not bug:
            QMessageBox.information(self, "No selection", "Please select a bug first.")
            return
        bug.status = self.edit_status.currentText()
        bug.severity = self.edit_severity.currentText()
        try:
            self.repo.save_override(bug)
            self.model.dataChanged.emit(QModelIndex(), QModelIndex())  # refresh all
            self._refresh_counts()
            QMessageBox.information(self, "Saved", f"Updated {bug.bug_id}.")
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "bugs_export.json", "JSON (*.json)")
        if not path:
            return
        data = [bug.__dict__ for bug in self.bugs]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            QMessageBox.information(self, "Exported", f"Saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "bugs_export.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(",".join(BugTableModel.HEADERS) + "\n")
                for b in self.bugs:
                    row = [b.bug_id, b.category, b.description.replace(",", " "), b.status, b.severity]
                    f.write(",".join(row) + "\n")
            QMessageBox.information(self, "Exported", f"Saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))


def _default_history_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "history", "history.txt")


def main() -> None:
    app = QApplication(sys.argv)
    history_path = _default_history_path()
    window = BugViewer(history_path)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()


