#!/usr/bin/env python3
"""
Test script to verify signal connections are working properly.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel
    from PySide6.QtCore import Signal
    print("✓ PySide6 imported successfully")
except ImportError as e:
    print(f"✗ PySide6 import failed: {e}")
    sys.exit(1)

class TestWidget(QWidget):
    """Test widget with signals."""
    
    test_signal = Signal(str)
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the test UI."""
        layout = QVBoxLayout()
        
        # Test button
        self.test_button = QPushButton("Test Signal")
        self.test_button.clicked.connect(self._emit_signal)
        layout.addWidget(self.test_button)
        
        # Status label
        self.status_label = QLabel("No signal received")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def _emit_signal(self):
        """Emit the test signal."""
        print("Emitting test signal...")
        self.test_signal.emit("Test message from widget")
        print("Signal emitted successfully")

class TestReceiver(QWidget):
    """Test receiver widget."""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the test UI."""
        layout = QVBoxLayout()
        
        # Status label
        self.status_label = QLabel("Waiting for signal...")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def handle_signal(self, message):
        """Handle the received signal."""
        print(f"Signal received: {message}")
        self.status_label.setText(f"Signal received: {message}")

def test_signal_connections():
    """Test signal connections."""
    print("Testing signal connections...")
    
    # Create Qt application
    app = QApplication(sys.argv)
    
    # Create test widgets
    sender = TestWidget()
    receiver = TestReceiver()
    
    # Connect signal
    print("Connecting signal...")
    sender.test_signal.connect(receiver.handle_signal)
    print("Signal connected successfully")
    
    # Show widgets
    sender.show()
    receiver.show()
    
    print("Test widgets displayed. Click 'Test Signal' button to test.")
    print("Press Ctrl+C to exit.")
    
    # Start event loop
    try:
        sys.exit(app.exec())
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    test_signal_connections()
