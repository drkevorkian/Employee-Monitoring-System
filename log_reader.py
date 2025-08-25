#!/usr/bin/env python3
"""
Log Reader Utility for Employee Monitoring System
Provides a GUI interface to read and analyze logs from different components.
"""

import os
import sys
import glob
from datetime import datetime
from typing import List, Dict, Optional

try:
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QTextEdit, QComboBox, QPushButton, 
                                 QLabel, QSplitter, QListWidget, QListWidgetItem,
                                 QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView)
    from PySide6.QtCore import Qt, QTimer, QThread, Signal
    from PySide6.QtGui import QFont, QTextCursor
except ImportError as e:
    print(f"Required library not found: {e}")
    print("Please install required packages: pip install -r requirements.txt")
    sys.exit(1)

class LogReader(QMainWindow):
    """Main log reader application."""
    
    def __init__(self):
        super().__init__()
        self.log_dir = "logs"
        self.current_log_file = None
        self.log_cache = {}
        self._init_ui()
        self._refresh_log_list()
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Employee Monitoring System - Log Reader")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create toolbar
        toolbar_layout = QHBoxLayout()
        
        # Component selector
        self.component_combo = QComboBox()
        self.component_combo.addItems(['All Components', 'server', 'client', 'client_gui', 'database', 'security'])
        self.component_combo.currentTextChanged.connect(self._on_component_changed)
        
        # Log type selector
        self.log_type_combo = QComboBox()
        self.log_type_combo.addItems(['All Logs', 'errors', 'security', 'database', 'network', 'info', 'debug'])
        self.log_type_combo.currentTextChanged.connect(self._on_log_type_changed)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_log_list)
        
        # Auto-refresh toggle
        self.auto_refresh_btn = QPushButton("⏸ Auto-refresh")
        self.auto_refresh_btn.setCheckable(True)
        self.auto_refresh_btn.clicked.connect(self._toggle_auto_refresh)
        
        # Search box
        search_label = QLabel("Search:")
        self.search_box = QTextEdit()
        self.search_box.setMaximumHeight(30)
        self.search_box.setPlaceholderText("Enter search terms...")
        self.search_box.textChanged.connect(self._filter_logs)
        
        toolbar_layout.addWidget(QLabel("Component:"))
        toolbar_layout.addWidget(self.component_combo)
        toolbar_layout.addWidget(QLabel("Log Type:"))
        toolbar_layout.addWidget(self.log_type_combo)
        toolbar_layout.addWidget(refresh_btn)
        toolbar_layout.addWidget(self.auto_refresh_btn)
        toolbar_layout.addWidget(search_label)
        toolbar_layout.addWidget(self.search_box)
        toolbar_layout.addStretch()
        
        main_layout.addLayout(toolbar_layout)
        
        # Create splitter for log list and content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Log file list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        left_layout.addWidget(QLabel("Available Log Files:"))
        self.log_list = QListWidget()
        self.log_list.itemClicked.connect(self._on_log_selected)
        left_layout.addWidget(self.log_list)
        
        # Right panel - Log content
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        right_layout.addWidget(QLabel("Log Content:"))
        self.log_content = QTextEdit()
        self.log_content.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.log_content)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([400, 1000])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Auto-refresh timer
        self.auto_refresh_timer = QTimer()
        self.auto_refresh_timer.timeout.connect(self._refresh_log_list)
        self.auto_refresh_timer.setInterval(5000)  # 5 seconds
    
    def _on_component_changed(self, component: str):
        """Handle component selection change."""
        self._refresh_log_list()
    
    def _on_log_type_changed(self, log_type: str):
        """Handle log type selection change."""
        self._refresh_log_list()
    
    def _toggle_auto_refresh(self, checked: bool):
        """Toggle auto-refresh functionality."""
        if checked:
            self.auto_refresh_timer.start()
            self.auto_refresh_btn.setText("▶ Auto-refresh")
            self.status_bar.showMessage("Auto-refresh enabled")
        else:
            self.auto_refresh_timer.stop()
            self.auto_refresh_btn.setText("⏸ Auto-refresh")
            self.status_bar.showMessage("Auto-refresh disabled")
    
    def _refresh_log_list(self):
        """Refresh the list of available log files."""
        try:
            self.log_list.clear()
            self.log_cache.clear()
            
            component = self.component_combo.currentText()
            log_type = self.log_type_combo.currentText()
            
            if component == "All Components":
                components = ['server', 'client', 'client_gui', 'database', 'security']
            else:
                components = [component]
            
            for comp in components:
                comp_dir = os.path.join(self.log_dir, comp)
                if not os.path.exists(comp_dir):
                    continue
                
                # Get log files based on type
                if log_type == "All Logs":
                    # Get all log files
                    log_files = glob.glob(os.path.join(comp_dir, "*.log"))
                    log_files.extend(glob.glob(os.path.join(comp_dir, "*", "*.log")))
                else:
                    # Get specific log type files
                    type_dir = os.path.join(comp_dir, log_type.lower())
                    if os.path.exists(type_dir):
                        log_files = glob.glob(os.path.join(type_dir, "*.log"))
                    else:
                        log_files = []
                
                for log_file in sorted(log_files, reverse=True):
                    # Get file info
                    file_stat = os.stat(log_file)
                    file_size = file_stat.st_size
                    mod_time = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    # Create list item
                    rel_path = os.path.relpath(log_file, self.log_dir)
                    item_text = f"{rel_path}\nSize: {file_size:,} bytes | Modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')}"
                    
                    item = QListWidgetItem(item_text)
                    item.setData(Qt.ItemDataRole.UserRole, log_file)
                    
                    # Color code by log type
                    if "errors" in log_file:
                        item.setBackground(Qt.GlobalColor.lightGray)
                    elif "security" in log_file:
                        item.setBackground(Qt.GlobalColor.lightYellow)
                    elif "database" in log_file:
                        item.setBackground(Qt.GlobalColor.lightBlue)
                    elif "network" in log_file:
                        item.setBackground(Qt.GlobalColor.lightGreen)
                    
                    self.log_list.addItem(item)
            
            self.status_bar.showMessage(f"Found {self.log_list.count()} log files")
            
        except Exception as e:
            self.status_bar.showMessage(f"Error refreshing log list: {e}")
    
    def _on_log_selected(self, item: QListWidgetItem):
        """Handle log file selection."""
        try:
            log_file = item.data(Qt.ItemDataRole.UserRole)
            if not log_file or not os.path.exists(log_file):
                return
            
            # Load and display log content
            self._load_log_content(log_file)
            self.current_log_file = log_file
            
            # Update status
            file_size = os.path.getsize(log_file)
            self.status_bar.showMessage(f"Displaying: {os.path.basename(log_file)} ({file_size:,} bytes)")
            
        except Exception as e:
            self.status_bar.showMessage(f"Error loading log file: {e}")
    
    def _load_log_content(self, log_file: str):
        """Load and display log file content."""
        try:
            if log_file in self.log_cache:
                content = self.log_cache[log_file]
            else:
                # Read log file
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Cache the content
                self.log_cache[log_file] = content
            
            # Display content
            self.log_content.setPlainText(content)
            
            # Move cursor to end
            cursor = self.log_content.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.log_content.setTextCursor(cursor)
            
        except Exception as e:
            self.log_content.setPlainText(f"Error reading log file: {e}")
    
    def _filter_logs(self):
        """Filter logs based on search terms."""
        search_text = self.search_box.toPlainText().lower()
        
        if not search_text:
            # Show all items
            for i in range(self.log_list.count()):
                self.log_list.item(i).setHidden(False)
            return
        
        # Filter items
        for i in range(self.log_list.count()):
            item = self.log_list.item(i)
            log_file = item.data(Qt.ItemDataRole.UserRole)
            
            if log_file and log_file in self.log_cache:
                content = self.log_cache[log_file].lower()
                if search_text in content:
                    item.setHidden(False)
                else:
                    item.setHidden(True)
            else:
                item.setHidden(True)
        
        visible_count = sum(1 for i in range(self.log_list.count()) if not self.log_list.item(i).isHidden())
        self.status_bar.showMessage(f"Showing {visible_count} log files matching search")

def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Employee Monitoring System - Log Reader")
    app.setApplicationVersion("1.0")
    
    # Create and show main window
    window = LogReader()
    window.show()
    
    # Start event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
