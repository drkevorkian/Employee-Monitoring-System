#!/usr/bin/env python3
"""
GUI Client Program for Employee Monitoring System
Modern interface that runs from the taskbar with system tray support.
"""

import os
import sys
import time
import json
import socket
import threading
import struct
import queue
import logging
import configparser
import base64
import platform
import psutil
import uuid
import signal
import subprocess
import shutil
from typing import Dict, Any, Optional
from datetime import datetime
from PIL import ImageGrab, Image
import io

# Import required libraries with error handling
try:
    import pyautogui
    import numpy as np
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                                 QSystemTrayIcon, QMenu, QMessageBox,
                                 QProgressBar, QFrame, QSlider, QCheckBox)
    from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSize, QRect
    from PySide6.QtGui import QPixmap, QImage, QFont, QIcon, QPalette, QColor, QAction
except ImportError as e:
    print(f"Required library not found: {e}")
    print("Please install required packages: pip install -r requirements.txt")
    sys.exit(1)

# Import our custom logging system
try:
    from logging_config import get_logger
    logger = get_logger('client_gui')
except ImportError as e:
    # Fallback to basic logging if custom system not available
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('client_gui.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)

class MessagePopupWidget(QWidget):
    """Facebook-style message popup widget for client GUI."""
    
    def __init__(self, message_id: str, message: str, parent=None):
        super().__init__(parent)
        self.message_id = message_id
        self.last_message_id = None
        self.setWindowTitle("Message from Server")
        # Make the popup taller by approximately two inches (DPI-aware)
        try:
            screen = QApplication.primaryScreen()
            dpi_y = float(screen.logicalDotsPerInchY()) if screen else 96.0
        except Exception:
            dpi_y = 96.0
        additional_px = int(max(160, min(240, dpi_y * 2)))  # clamp around 2 inches
        popup_width = 360
        popup_height = 260 + additional_px
        self.setFixedSize(popup_width, popup_height)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._is_minimized = False  # Track minimized state
        self._normal_size = QSize(popup_width, popup_height)
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Main frame with rounded corners and better styling
        self.main_frame = QFrame()
        self.main_frame.setStyleSheet("""
            QFrame {
                background-color: #FFFFFF;
                border: 2px solid #00BFFF;
                border-radius: 15px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FFFFFF, stop:1 #F8F9FA);
            }
        """)
        
        frame_layout = QVBoxLayout(self.main_frame)
        self._frame_layout = frame_layout
        frame_layout.setSpacing(12)  # Increased spacing between elements
        frame_layout.setContentsMargins(18, 18, 18, 18)  # Increased margins
        
        # Header bar with title and window controls
        self.header_bar = QFrame()
        self.header_bar.setStyleSheet("""
            QFrame {
                background-color: #00BFFF;
                border-radius: 8px;
            }
        """)
        header_h = QHBoxLayout(self.header_bar)
        header_h.setContentsMargins(10, 6, 6, 6)
        header_h.setSpacing(6)
        header_title = QLabel("💬 Message from Server")
        header_title.setStyleSheet("""
            QLabel { color: #FFFFFF; font-weight: bold; font-size: 14px; }
        """)
        header_h.addWidget(header_title)
        header_h.addStretch(1)
        # Minimize and Close buttons in header
        self.minimize_button = QPushButton("_")
        self.minimize_button.setFixedSize(22, 22)
        self.minimize_button.setStyleSheet("""
            QPushButton { background-color: #f39c12; color: #fff; border: none; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #e67e22; }
        """)
        self.minimize_button.clicked.connect(self._minimize_popup)
        header_h.addWidget(self.minimize_button)
        # Delete (soft delete) button
        self.delete_button = QPushButton("🗑")
        self.delete_button.setFixedSize(22, 22)
        self.delete_button.setStyleSheet("""
            QPushButton { background-color: #ff6b6b; color: #fff; border: none; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #e05656; }
        """)
        self.delete_button.setToolTip("Delete message (soft delete)")
        self.delete_button.clicked.connect(self._soft_delete_message)
        header_h.addWidget(self.delete_button)
        self.close_button = QPushButton("×")
        self.close_button.setFixedSize(22, 22)
        self.close_button.setStyleSheet("""
            QPushButton { background-color: #e74c3c; color: #fff; border: none; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #c0392b; }
        """)
        self.close_button.clicked.connect(self.close)
        header_h.addWidget(self.close_button)
        frame_layout.addWidget(self.header_bar)

        # Content container that we can collapse on minimize
        self.content_container = QWidget()
        content_layout = QVBoxLayout(self.content_container)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(8)
        
        # Message content (scrollable text area for conversation history)
        self.message_label = QTextEdit("No message")
        self.message_label.setReadOnly(True)  # Read-only for conversation display
        self.message_label.setStyleSheet("""
            QTextEdit {
                color: #2C3E50;
                font-size: 11px;
                padding: 10px;
                background-color: #F8F9FA;
                border-radius: 8px;
                border: 1px solid #DEE2E6;
                font-weight: normal;
                line-height: 1.4;
            }
            QTextEdit:focus {
                border: 2px solid #00BFFF;
            }
        """)
        # Allocate generous space for conversation history (~50% of popup height)
        try:
            self.message_label.setMaximumHeight(int(self._normal_size.height() * 0.5))
        except Exception:
            self.message_label.setMaximumHeight(220)
        content_layout.addWidget(self.message_label)
        
        # Response section
        response_label = QLabel("Response:")
        response_label.setStyleSheet("""
            QLabel {
                color: #2C3E50;
                font-weight: bold;
                font-size: 12px;
                padding: 2px;
                background-color: #E8F4FD;
                border-radius: 4px;
                margin: 2px;
            }
        """)
        content_layout.addWidget(response_label)
        
        # Response text input
        self.response_input = QTextEdit()
        self.response_input.setMaximumHeight(60)
        self.response_input.setStyleSheet("""
            QTextEdit {
                border: 1px solid #DEE2E6;
                border-radius: 5px;
                padding: 8px;
                font-size: 11px;
                background-color: #FFFFFF;
                color: #2C3E50;
            }
            QTextEdit:focus {
                border: 2px solid #00BFFF;
                background-color: #FFFFFF;
            }
        """)
        content_layout.addWidget(self.response_input)
        
        # Send button
        self.send_button = QPushButton("Send Response")
        self.send_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00BFFF, stop:1 #0099CC);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
                min-height: 20px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0099CC, stop:1 #007399);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #007399, stop:1 #005580);
            }
        """)
        self.send_button.clicked.connect(self._send_response)
        content_layout.addWidget(self.send_button)

        # Status indicator for message states (sent/delivered/read)
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.status_label.setStyleSheet("""
            QLabel { color: rgba(255,0,0,0.7); font-size: 11px; }
        """)
        content_layout.addWidget(self.status_label)

        # Add content container to frame
        frame_layout.addWidget(self.content_container)
        
        # (buttons moved to header)
        
        layout.addWidget(self.main_frame)
        self.setLayout(layout)
        
        # Auto-close timer
        self.auto_close_timer = QTimer()
        self.auto_close_timer.timeout.connect(self.close)
        
        # Make popup draggable
        self._dragging = False
        self._drag_position = None
        
    def _flash_popup(self):
        """Flash the popup to draw attention to new messages."""
        try:
            # Store original style
            original_style = self.main_frame.styleSheet()
            
            # Flash with a more noticeable border and background
            flash_style = original_style.replace(
                "border: 2px solid #00BFFF;",
                "border: 3px solid #FF6B35;"
            ).replace(
                "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FFFFFF, stop:1 #F8F9FA);",
                "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FFF8E1, stop:1 #FFECB3);"
            )
            self.main_frame.setStyleSheet(flash_style)
            
            # Restore original style after 500ms (longer flash)
            QTimer.singleShot(500, lambda: self.main_frame.setStyleSheet(original_style))
            
        except Exception as e:
            logger.debug(f"Could not flash popup: {e}")
        
    def mousePressEvent(self, event):
        """Handle mouse press for dragging."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
    
    def mouseMoveEvent(self, event):
        """Handle mouse move for dragging."""
        if event.buttons() & Qt.MouseButton.LeftButton and self._dragging:
            self.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()
    
    def mouseReleaseEvent(self, event):
        """Handle mouse release for dragging."""
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            event.accept()
        
    def show_message(self, message: str, message_id: str = None, auto_close: bool = False):
        """Show a message in the popup."""
        # Track message id and mark delivered to server
        if message_id:
            self.last_message_id = message_id
            self._send_message_status('delivered')
        # Append new message to existing conversation
        current_text = self.message_label.toPlainText()
        if current_text == "No message":
            self.message_label.setPlainText(message)
        else:
            # Add timestamp and append new message
            timestamp = datetime.now().strftime("%H:%M")
            new_message = f"{current_text}\n\n[{timestamp}] Server: {message}"
            self.message_label.setPlainText(new_message)
        
        # Auto-scroll to bottom to show latest message
        self.message_label.verticalScrollBar().setValue(
            self.message_label.verticalScrollBar().maximum()
        )
        
        # Flash the popup to draw attention (like real IM apps)
        self._flash_popup()
        
        self.response_input.clear()
        
        # Ensure the popup is visible and on top
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)
        self.show()
        self.raise_()
        self.activateWindow()
        
        # Position using availableGeometry to respect taskbar and multi-monitor work area
        screen = QApplication.primaryScreen()
        geometry = screen.availableGeometry() if screen else self.geometry()
        margin_right = 24
        stack_spacing = 16
        base_x = geometry.right() - self.width() - margin_right
        base_y = geometry.bottom() - self.height() - 140
        # Compute stack index from active popups
        try:
            manager = self.parent().message_manager if hasattr(self.parent(), 'message_manager') else None
            index = manager.get_active_count() - 1 if manager else 0
        except Exception:
            index = 0
        x = base_x - (index * stack_spacing)
        y = base_y - (index * stack_spacing)
        x = max(geometry.left() + 24, x)
        y = max(geometry.top() + 24, y)
        self.move(x, y)
        
        # Update status indicator to 'delivered' (two outlined checks)
        self._update_status_checks('delivered')

        # Log the message being displayed for debugging
        logger.info(f"Message popup displayed at ({x}, {y}) with message: {message}")
        
    def _minimize_popup(self):
        """Minimize the popup to just show the header (like real IM apps)."""
        if hasattr(self, '_is_minimized') and self._is_minimized:
            # Restore to full size
            self.content_container.show()
            self.setFixedSize(self._normal_size)
            self.minimize_button.setText("_")
            self._is_minimized = False
            logger.debug(f"Message popup {self.message_id} restored to full size")
        else:
            # Minimize to just header (collapse content area for reliable close button access)
            self.content_container.hide()
            # Make minimized height a bit taller for visibility
            minimized_height = max(72, self.header_bar.sizeHint().height() + 28)
            self.setFixedSize(self.width(), minimized_height)
            self.minimize_button.setText("□")
            self._is_minimized = True
            logger.debug(f"Message popup {self.message_id} minimized")
        
    def _send_response(self):
        """Send response to server."""
        response = self.response_input.toPlainText().strip()
        if response:
            try:
                # Get the parent window (ClientMainWindow) to access the client
                parent_window = self.parent()
                if hasattr(parent_window, 'monitoring_thread') and parent_window.monitoring_thread:
                    # Create a proper response message to send to server
                    response_message = {
                        'type': 'chat_response',
                        'message': response,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Send the response via worker thread to avoid GUI-thread socket writes
                    parent_window.monitoring_thread.send_request.emit(response_message)
                    success = True
                    if success:
                        logger.info(f"Response sent to server for message {self.message_id}: {response}")
                        # Add user response to conversation history
                        timestamp = datetime.now().strftime("%H:%M")
                        current_text = self.message_label.toPlainText()
                        user_response = f"{current_text}\n[{timestamp}] You: {response}"
                        self.message_label.setPlainText(user_response)
                        
                        # Auto-scroll to bottom to show latest message
                        self.message_label.verticalScrollBar().setValue(
                            self.message_label.verticalScrollBar().maximum()
                        )
                        
                        # Clear the input field after sending
                        self.response_input.clear()
                        # Show a brief success indicator
                        self.response_input.setStyleSheet("""
                            QTextEdit {
                                border: 2px solid #27ae60;
                                border-radius: 5px;
                                padding: 8px;
                                font-size: 11px;
                                background-color: #D5F4E6;
                                color: #2C3E50;
                            }
                        """)
                        # Mark last server message as read
                        self._send_message_status('read')
                        self._update_status_checks('read')
                        # Reset style after 1.5 seconds
                        QTimer.singleShot(1500, lambda: self.response_input.setStyleSheet("""
                            QTextEdit {
                                border: 1px solid #DEE2E6;
                                border-radius: 5px;
                                padding: 8px;
                                font-size: 11px;
                                background-color: #FFFFFF;
                                color: #2C3E50;
                            }
                            QTextEdit:focus {
                                border: 2px solid #00BFFF;
                                background-color: #FFFFFF;
                            }
                        """))
                    else:
                        logger.error(f"Failed to send response to server for message {self.message_id}")
                        # Show error indicator
                        self.response_input.setStyleSheet("""
                            QTextEdit {
                                border: 2px solid #e74c3c;
                                border-radius: 5px;
                                padding: 8px;
                                font-size: 11px;
                                background-color: #FDF2F2;
                                color: #2C3E50;
                            }
                        """)
                        # Reset style after 2.5 seconds
                        QTimer.singleShot(2500, lambda: self.response_input.setStyleSheet("""
                            QTextEdit {
                                border: 1px solid #DEE2E6;
                                border-radius: 5px;
                                padding: 8px;
                                font-size: 11px;
                                background-color: #FFFFFF;
                                color: #2C3E50;
                            }
                            QTextEdit:focus {
                                border: 2px solid #00BFFF;
                                background-color: #FFFFFF;
                            }
                        """))
                else:
                    logger.error("Parent window does not have client with _send_data method")
                
                # Don't close the popup - keep it open for conversation like a real IM app
                
            except Exception as e:
                logger.error(f"Error sending response to server: {e}")
                # Show error indicator
                self.response_input.setStyleSheet("""
                    QTextEdit {
                        border: 2px solid #e74c3c;
                        border-radius: 5px;
                        padding: 8px;
                        font-size: 11px;
                        background-color: #FDF2F2;
                        color: #2C3E50;
                    }
                """)
                # Reset style after 2.5 seconds
                QTimer.singleShot(2500, lambda: self.response_input.setStyleSheet("""
                    QTextEdit {
                        border: 1px solid #DEE2E6;
                        border-radius: 5px;
                        padding: 8px;
                        font-size: 11px;
                        background-color: #FFFFFF;
                        color: #2C3E50;
                    }
                    QTextEdit:focus {
                        border: 2px solid #00BFFF;
                        background-color: #FFFFFF;
                    }
                """))
        else:
            # Show error if no response
            self.response_input.setStyleSheet("""
                QTextEdit {
                    border: 2px solid #e74c3c;
                    border-radius: 5px;
                    padding: 8px;
                    font-size: 11px;
                    background-color: #FDF2F2;
                    color: #2C3E50;
                }
            """)
            # Reset style after 2.5 seconds
            QTimer.singleShot(2500, lambda: self.response_input.setStyleSheet("""
                QTextEdit {
                    border: 1px solid #DEE2E6;
                    border-radius: 5px;
                    padding: 8px;
                    font-size: 11px;
                    background-color: #FFFFFF;
                    color: #2C3E50;
                }
                QTextEdit:focus {
                    border: 2px solid #00BFFF;
                    background-color: #FFFFFF;
                }
            """))
    
    def closeEvent(self, event):
        """Handle close event to notify message manager."""
        try:
            # Notify parent that this popup is closing
            if hasattr(self.parent(), 'message_popup_closed'):
                self.parent().message_popup_closed(self.message_id)
            # Mark as read when popup closes
            self._send_message_status('read')
            self._update_status_checks('read')
        except:
            pass
        super().closeEvent(event)

    def _soft_delete_message(self):
        """Soft-delete the current message (sets deleted=1 on server)."""
        self._send_message_status('deleted')
        self._update_status_checks('read')

    def _send_message_status(self, status: str) -> None:
        try:
            if not self.last_message_id:
                return
            parent_window = self.parent()
            if hasattr(parent_window, 'monitoring_thread') and parent_window.monitoring_thread:
                status_message = {
                    'type': 'message_status',
                    'status': status,
                    'message_id': self.last_message_id,
                    'timestamp': datetime.now().isoformat()
                }
                parent_window.monitoring_thread.send_request.emit(status_message)
        except Exception as e:
            logger.debug(f"Failed to send message status: {e}")

    def _update_status_checks(self, state: str) -> None:
        """Update the status label with styled check marks."""
        # one circled check for sent, two for delivered, filled for read
        color = 'rgba(255,0,0,0.7)'
        if state == 'sent':
            html = f"<span style='color:{color}'>◯✓</span>"
        elif state == 'delivered':
            html = f"<span style='color:{color}'>◯✓ ◯✓</span>"
        else:  # read
            html = f"<span style='color:{color}'>●✓ ●✓</span>"
        self.status_label.setText(html)


class MessageManager:
    """Manages multiple message popups for the client GUI."""
    
    def __init__(self, parent_window):
        self.parent_window = parent_window
        self.active_popups = {}  # message_id -> popup_widget
        self.popup_counter = 0
        self._unread_count = 0
        
    def show_message(self, message: str, message_id: str = None, auto_close: bool = True) -> str:
        """Show a new message popup and return the message ID."""
        try:
            # Generate/reuse a single popup channel for server chat
            channel_id = "server_chat"
            if channel_id in self.active_popups:
                popup = self.active_popups[channel_id]
                logger.info(f"Appending message to existing popup: {channel_id}")
                popup.show_message(message, message_id, auto_close)
                popup.raise_()
                popup.activateWindow()
                self.mark_delivered()
                return channel_id

            # Create new popup instance; preserve server-provided message_id if given
            self.popup_counter += 1
            popup_channel_id = channel_id
            popup = MessagePopupWidget(popup_channel_id, "", self.parent_window)
            logger.info(f"Creating message popup with ID: {message_id} for message: {message}")
            
            # Position popup with offset for multiple messages
            self._position_popup(popup, popup_channel_id)
            
            # Store popup reference
            self.active_popups[popup_channel_id] = popup
            
            # Show popup
            popup.show_message(message, message_id, auto_close)
            self.mark_delivered()
            
            logger.info(f"New message popup created with channel: {popup_channel_id} (msg_id={message_id})")
            return popup_channel_id
            
        except Exception as e:
            logger.error(f"Failed to create message popup: {e}")
            return None
    
    def _position_popup(self, popup, message_id):
        """Position popup with offset for multiple messages."""
        try:
            screen = QApplication.primaryScreen()
            geometry = screen.availableGeometry() if screen else popup.geometry()
            # Position more towards center-right, not all the way to the right edge
            base_x = geometry.right() - popup.width() - 24
            # Position higher on screen and respect taskbar
            base_y = geometry.bottom() - popup.height() - 140
            
            # Calculate offset based on number of active popups
            popup_index = len(self.active_popups)
            offset_x = popup_index * 30  # Increased spacing between popups
            offset_y = popup_index * 30  # Increased spacing between popups
            
            # Ensure popup stays on screen
            final_x = max(geometry.left() + 24, base_x - offset_x - 40)
            final_y = max(geometry.top() + 24, base_y - offset_y)
            
            popup.move(final_x, final_y)
            
        except Exception as e:
            logger.error(f"Failed to position popup: {e}")
    
    def close_popup(self, message_id: str):
        """Close a specific message popup."""
        try:
            if message_id in self.active_popups:
                popup = self.active_popups[message_id]
                popup.close()
                del self.active_popups[message_id]
                logger.info(f"Closed message popup: {message_id}")
                
                # Reposition remaining popups
                self._reposition_popups()
                
        except Exception as e:
            logger.error(f"Failed to close popup {message_id}: {e}")
    
    def _reposition_popups(self):
        """Reposition all remaining popups."""
        try:
            for i, (message_id, popup) in enumerate(self.active_popups.items()):
                screen = QApplication.primaryScreen()
                geometry = screen.availableGeometry() if screen else popup.geometry()
                base_x = geometry.right() - popup.width() - 24
                base_y = geometry.bottom() - popup.height() - 140
                
                offset_x = i * 30  # Increased spacing between popups
                offset_y = i * 30  # Increased spacing between popups
                
                final_x = max(geometry.left() + 24, base_x - offset_x - 40)
                final_y = max(geometry.top() + 24, base_y - offset_y)
                
                popup.move(final_x, final_y)
                
        except Exception as e:
            logger.error(f"Failed to reposition popups: {e}")
    
    def close_all_popups(self):
        """Close all active message popups."""
        try:
            for message_id in list(self.active_popups.keys()):
                self.close_popup(message_id)
            logger.info("All message popups closed")
        except Exception as e:
            logger.error(f"Failed to close all popups: {e}")
    
    def get_active_count(self) -> int:
        """Get the number of active popups."""
        return len(self.active_popups)

    def increment_unseen(self) -> None:
        self._unread_count += 1

    def mark_delivered(self) -> None:
        if self._unread_count > 0:
            self._unread_count -= 1

    def get_unread_count(self) -> int:
        return self._unread_count


class MonitoringThread(QThread):
    """Thread for handling monitoring operations."""
    
    # Signals for GUI updates
    status_updated = Signal(str, str)  # status, message
    connection_status = Signal(bool)  # connected
    error_occurred = Signal(str)  # error message
    message_received = Signal(str)  # message from server
    # Enqueue network send requests from GUI to this thread
    send_request = Signal(dict)
    
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.is_running = False
        # Ensure send requests are handled in this thread's context
        try:
            self.send_request.disconnect()
        except Exception:
            pass
        self.send_request.connect(self.handle_send_request)
        # Create a queue for outgoing messages from GUI
        if not hasattr(self.client, 'outgoing_queue'):
            self.client.outgoing_queue = queue.Queue()
        
    def run(self):
        """Run the monitoring thread."""
        try:
            self.is_running = True
            self.client.run_monitoring()
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.is_running = False
    
    def stop(self):
        """Stop the monitoring thread."""
        self.is_running = False
        self.client.stop()

    def handle_send_request(self, data: dict) -> None:
        """Handle a send request coming from the GUI thread safely in this worker thread."""
        try:
            self.client._send_data(data)
        except Exception as e:
            self.error_occurred.emit(str(e))

    # No Qt slot required; GUI enqueues to client's thread-safe queue

class MonitoringClient:
    """
    Client application that captures screen data and system information,
    sending it to the monitoring server.
    """
    
    def __init__(self, config_file: str = 'config.ini'):
        """
        Initialize the monitoring client.
        
        Args:
            config_file: Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.server_host = self.config.get('Client', 'server_host', fallback='localhost')
        self.server_port = self.config.getint('Client', 'server_port', fallback=8080)
        self.screen_capture_interval = self.config.getfloat('Client', 'screen_capture_interval', fallback=1.0)
        self.image_quality = self.config.getint('Client', 'image_quality', fallback=85)
        self.compression_level = self.config.getint('Client', 'compression_level', fallback=6)
        self.max_image_size = self.config.get('Client', 'max_image_size', fallback='1920x1080')
        self.auto_reconnect = self.config.getboolean('Client', 'auto_reconnect', fallback=True)
        self.reconnect_delay = self.config.getint('Client', 'reconnect_delay', fallback=5)
        
        # Client state
        self.client_id = str(uuid.uuid4())[:16]
        self.is_running = False
        self.socket = None
        self.connected = False
        self.last_heartbeat = time.time()
        self.heartbeat_interval = 30  # seconds
        
        # Platform-specific settings
        self.platform = platform.system()
        if isinstance(self.platform, str):
            self.platform = self.platform.lower()
        
        # Signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Message callback for GUI updates - will be set by GUI
        self.message_callback = None
        
        logger.info(f"Monitoring client initialized: {self.client_id}")
        logger.info(f"Platform: {self.platform}")
    
    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        if os.path.exists(config_file):
            config.read(config_file)
            logger.info(f"Configuration loaded from {config_file}")
        else:
            logger.warning(f"Configuration file {config_file} not found, using defaults")
        
        return config
    
    def _signal_handler(self, signum, frame):
        """Handle system signals for graceful shutdown."""
        logger.info(f"Received signal {signum}, shutting down gracefully")
        self.stop()
        sys.exit(0)
    
    def connect_to_server(self) -> bool:
        """Connect to the monitoring server."""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)  # 10 second timeout
            
            # Connect to server
            self.socket.connect((self.server_host, self.server_port))
            self.socket.settimeout(None)  # Remove timeout after connection

            # Enable TCP keepalive and low-latency options
            try:
                self._configure_keepalive(self.socket)
                # Disable Nagle to reduce latency for chat/commands
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception as e:
                logger.warning(f"Could not configure socket options: {e}")
            
            # Send client registration
            registration_success = self._send_registration()
            if registration_success:
                self.connected = True
                logger.info(f"Connected to server {self.server_host}:{self.server_port}")
                return True
            else:
                logger.error("Failed to register with server")
                self.socket.close()
                self.socket = None
                return False
                
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            if self.socket:
                self.socket.close()
                self.socket = None
            return False

    def _configure_keepalive(self, sock: socket.socket) -> None:
        """Enable cross-platform TCP keepalive with sensible defaults."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Windows specific
            if hasattr(socket, 'SIO_KEEPALIVE_VALS') and sys.platform.startswith('win'):
                # Keepalive time: 10s, interval: 3s, count is implicit
                sock.ioctl(socket.SIO_KEEPALIVE_VALS, struct.pack('III', 1, 10000, 3000))
            else:
                # Linux/macOS (if available)
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except Exception as e:
            logger.warning(f"Keepalive configuration failed: {e}")
    
    def _send_registration(self) -> bool:
        """Send client registration to server."""
        try:
            # Get system information
            system_info = self.get_system_info()
            
            # Create registration message
            registration = {
                'type': 'client_registration',
                'client_id': self.client_id,
                'system_info': system_info
            }
            
            # Send registration
            self._send_data(registration)
            
            # Wait for response
            response = self._receive_data()
            if response and response.get('status') == 'accepted':
                logger.info("Registration accepted by server")
                return True
            else:
                logger.error("Registration rejected by server")
                return False
                
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information."""
        try:
            # Basic system info
            system_info = {
                'hostname': platform.node(),
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'capabilities': {
                    'remote_reboot': True,
                    'service_management': True,
                    'messaging': True,
                    'file_operations': True
                }
            }
            
            # Memory and CPU info
            try:
                memory = psutil.virtual_memory()
                system_info['memory'] = {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent
                }
                
                cpu_percent = psutil.cpu_percent(interval=1)
                system_info['cpu'] = {
                    'count': psutil.cpu_count(),
                    'percent': cpu_percent
                }
            except Exception as e:
                logger.warning(f"Could not get memory/CPU info: {e}")
            
            # Network info
            try:
                network_info = {}
                for interface, addresses in psutil.net_if_addrs().items():
                    for addr in addresses:
                        if addr.family == socket.AF_INET:  # IPv4
                            network_info['ip_address'] = addr.address
                        elif addr.family == psutil.AF_LINK:  # MAC address
                            network_info['mac_address'] = addr.address
                system_info['network_info'] = network_info
            except Exception as e:
                logger.warning(f"Could not get network info: {e}")
            
            # Disk info
            try:
                disk_info = {}
                for partition in psutil.disk_partitions():
                    if partition.device:
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            disk_info[partition.device] = {
                                'mountpoint': partition.mountpoint,
                                'total': usage.total,
                                'free': usage.free,
                                'percent': usage.percent
                            }
                        except PermissionError:
                            continue
                system_info['disk_info'] = disk_info
            except Exception as e:
                logger.warning(f"Could not get disk info: {e}")
            
            return system_info
            
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {
                'hostname': 'Unknown',
                'platform': 'Unknown',
                'capabilities': {}
            }
    
    def _send_data(self, data: Dict[str, Any]):
        """Send data to server (called from worker thread)."""
        try:
            if not self.socket:
                logger.error("No socket connection available")
                return False
            # Convert to JSON and encrypt all transport data
            json_bytes = json.dumps(data, default=str).encode('utf-8')
            try:
                from security import SecurityManager
                if not hasattr(self, '_transport_security'):
                    # Reuse config
                    self._transport_security = SecurityManager(self.config)
                sec = self._transport_security
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce = os.urandom(12)
                ct = sec.db_aead.encrypt(nonce, json_bytes, b'TRANSv1')
                payload = b'TRV1' + nonce + ct
            except Exception as e:
                logger.warning(f"Falling back to plaintext due to security init error: {e}")
                payload = json_bytes
            length_bytes = len(payload).to_bytes(4, byteorder='big')
            self.socket.sendall(length_bytes + payload)
            return True
        except (socket.error, ConnectionError, OSError) as e:
            logger.warning(f"Connection error while sending data: {e}")
            self.connected = False
            return False
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            return False
    
    def _receive_data(self) -> Optional[Dict[str, Any]]:
        """Receive data from server."""
        try:
            if not self.socket:
                return None
            
            # Receive data length first
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None
            
            data_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive data in chunks
            data_bytes = b''
            while len(data_bytes) < data_length:
                chunk = self.socket.recv(min(4096, data_length - len(data_bytes)))
                if not chunk:
                    break
                data_bytes += chunk
            
            if len(data_bytes) == data_length:
                # Decrypt if transport header present
                try:
                    if data_bytes.startswith(b'TRV1'):
                        if not hasattr(self, '_transport_security'):
                            from security import SecurityManager
                            self._transport_security = SecurityManager(self.config)
                        sec = self._transport_security
                        raw = data_bytes[4:]
                        nonce, ct = raw[:12], raw[12:]
                        json_bytes = sec.db_aead.decrypt(nonce, ct, b'TRANSv1')
                    else:
                        json_bytes = data_bytes
                    return json.loads(json_bytes.decode('utf-8'))
                except Exception as e:
                    logger.error(f"Failed to decrypt/parse transport data: {e}")
                    return None
            else:
                logger.error("Incomplete data received from server")
                return None
                
        except Exception as e:
            logger.error(f"Failed to receive data: {e}")
            return None
    
    def run_monitoring(self):
        """Run the main monitoring loop."""
        try:
            self.is_running = True
            
            backoff = self.reconnect_delay
            while self.is_running:
                try:
                    # Connect if not connected
                    if not self.connected:
                        if not self.connect_to_server():
                            if self.auto_reconnect:
                                logger.info(f"Reconnecting in {backoff} seconds...")
                                time.sleep(backoff)
                                # Exponential backoff with cap at 60s
                                backoff = min(60, max(1, backoff * 2))
                                continue
                            else:
                                break
                        else:
                            backoff = self.reconnect_delay
                    
                    # Send heartbeat
                    if time.time() - self.last_heartbeat > self.heartbeat_interval:
                        self._send_heartbeat()
                        self.last_heartbeat = time.time()
                    
                    # Check for server commands
                    if self._check_for_commands():
                        continue
                    
                    # Capture and send screen
                    if self.connected:
                        self._capture_and_send_screen()
                    
                    # Sleep for capture interval
                    time.sleep(self.screen_capture_interval)
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    
                    # Check if it's a connection-related error
                    if isinstance(e, (socket.error, ConnectionError, OSError)):
                        logger.warning("Connection error detected, will attempt reconnection")
                        self.connected = False
                        if self.socket:
                            try:
                                self.socket.close()
                            except:
                                pass
                            self.socket = None
                    else:
                        logger.error(f"Non-connection error: {e}")
                    
                    if not self.auto_reconnect:
                        logger.error("Auto-reconnect disabled, stopping monitoring")
                        break
                    
                    logger.info(f"Reconnecting in {self.reconnect_delay} seconds...")
                    time.sleep(self.reconnect_delay)
                    
        except Exception as e:
            logger.error(f"Monitoring failed: {e}")
        finally:
            self.is_running = False
            if self.socket:
                self.socket.close()
                self.socket = None
    
    def _send_heartbeat(self):
        """Send heartbeat to server."""
        try:
            heartbeat = {
                'type': 'heartbeat',
                'client_id': self.client_id,
                'timestamp': datetime.now().isoformat()
            }
            self._send_data(heartbeat)
            logger.debug("Heartbeat sent")
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")
    
    def _check_for_commands(self) -> bool:
        """Check for commands from server."""
        try:
            if not self.socket:
                return False
            
            # Check if there's data available without blocking
            try:
                # Use select to check if data is available without blocking
                import select
                ready, _, _ = select.select([self.socket], [], [], 0.1)
                if not ready:
                    return False
                
                data = self._receive_data()
                if data:
                    self._handle_server_command(data)
                    return True
                    
            except (socket.timeout, OSError):
                # No data available, continue
                pass
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking for commands: {e}")
            return False
    
    def _handle_server_command(self, command: Dict[str, Any]) -> bool:
        """Handle commands received from the server."""
        try:
            command_type = command.get('type')
            logger.info(f"Received server command: {command_type}")
            
            if command_type == 'reboot':
                return self._handle_reboot_command(command)
            elif command_type == 'shutdown':
                return self._handle_shutdown_command(command)
            elif command_type == 'service_control':
                return self._handle_service_control_command(command)
            elif command_type == 'update_config':
                return self._handle_config_update_command(command)
            elif command_type == 'chat_message':
                return self._handle_chat_message_command(command)
            elif command_type == 'file_list_request':
                return self._handle_file_list_request(command)
            elif command_type == 'file_content_request':
                return self._handle_file_content_request(command)
            elif command_type == 'file_operation':
                return self._handle_file_operation_command(command)
            elif command_type == 'heartbeat_response':
                # Server is sending heartbeat_response instead of heartbeat - handle it gracefully
                logger.debug("Received heartbeat_response from server - sending acknowledgment")
                response = {
                    'type': 'command_response',
                    'command_id': command.get('command_id', 'heartbeat_ack'),
                    'status': 'success',
                    'message': 'Heartbeat acknowledged'
                }
                return self._send_data(response)
            elif command_type == 'heartbeat':
                # Respond to server heartbeat
                logger.debug("Received heartbeat from server - sending response")
                response = {
                    'type': 'heartbeat_response',
                    'client_id': self.client_id,
                    'timestamp': datetime.now().isoformat()
                }
                return self._send_data(response)
            else:
                logger.warning(f"Unknown command type: {command_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling server command: {e}")
            return False
    
    def _capture_and_send_screen(self):
        """Capture screen and send to server."""
        try:
            # Capture screen
            screenshot = ImageGrab.grab()
            
            # Convert to bytes (prefer PNG without JPEG-only quality parameter)
            img_byte_arr = io.BytesIO()
            image_format = 'PNG'
            screenshot.save(img_byte_arr, format='PNG', optimize=True)
            img_bytes = img_byte_arr.getvalue()
            
            # Compress if needed
            if len(img_bytes) > 1024 * 1024:  # 1MB
                screenshot = screenshot.resize((screenshot.width // 2, screenshot.height // 2), Image.Resampling.LANCZOS)
                img_byte_arr = io.BytesIO()
                image_format = 'JPEG'
                screenshot.save(img_byte_arr, format='JPEG', quality=70, optimize=True)
                img_bytes = img_byte_arr.getvalue()
            
            # Encode to base64
            image_data_b64 = base64.b64encode(img_bytes).decode('utf-8')
            
            # Create screen capture message
            screen_capture = {
                'type': 'screen_capture',
                'client_id': self.client_id,
                'image_data': image_data_b64,
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'resolution': f"{screenshot.width}x{screenshot.height}",
                    'format': image_format,
                    'size_bytes': len(img_bytes),
                    'compression_ratio': len(img_bytes) / (screenshot.width * screenshot.height * 3)
                }
            }
            
            # Send to server
            if self._send_data(screen_capture):
                logger.debug(f"Screen capture sent: {len(img_bytes)} bytes")
            else:
                logger.error("Failed to send screen capture")
                
        except Exception as e:
            logger.error(f"Screen capture failed: {e}")
    
    def stop(self):
        """Stop the monitoring client."""
        try:
            self.is_running = False
            
            if self.socket:
                self.socket.close()
                self.socket = None
            
            self.connected = False
            logger.info("Monitoring client stopped")
            
        except Exception as e:
            logger.error(f"Error stopping client: {e}")

    def _handle_reboot_command(self, command: Dict[str, Any]) -> bool:
        """Handle reboot command from server."""
        try:
            logger.info("Executing remote reboot command from server")
            
            # Send acknowledgment
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'executing',
                'message': 'Reboot command received, executing...'
            }
            self._send_data(response)
            
            # Execute reboot based on platform
            if self.platform == 'windows':
                subprocess.run(['shutdown', '/r', '/t', '0'], check=True)
            elif self.platform in ['linux', 'darwin']:
                subprocess.run(['reboot'], check=True)
            else:
                logger.error(f"Unsupported platform for reboot: {self.platform}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Reboot command failed: {e}")
            # Send error response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'error',
                'message': f'Reboot failed: {str(e)}'
            }
            self._send_data(response)
            return False
    
    def _handle_shutdown_command(self, command: Dict[str, Any]) -> bool:
        """Handle shutdown command from server."""
        try:
            logger.info("Executing remote shutdown command from server")
            
            # Send acknowledgment
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'executing',
                'message': 'Shutdown command received, executing...'
            }
            self._send_data(response)
            
            # Execute shutdown based on platform
            if self.platform == 'windows':
                subprocess.run(['shutdown', '/s', '/t', '0'], check=True)
            elif self.platform in ['linux', 'darwin']:
                subprocess.run(['shutdown', '-h', 'now'], check=True)
            else:
                logger.error(f"Unsupported platform for shutdown: {self.platform}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Shutdown command failed: {e}")
            # Send error response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'error',
                'message': f'Shutdown failed: {str(e)}'
            }
            self._send_data(response)
            return False
    
    def _handle_service_control_command(self, command: Dict[str, Any]) -> bool:
        """Handle service control command from server."""
        try:
            action = command.get('action', 'restart')
            logger.info(f"Executing service control command: {action}")
            
            # Send acknowledgment
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'executing',
                'message': f'Service control command {action} received, executing...'
            }
            self._send_data(response)
            
            # Execute service control based on platform
            if self.platform == 'windows':
                if action == 'start':
                    subprocess.run(['sc', 'start', 'EmployeeMonitoringClient'], check=True)
                elif action == 'stop':
                    subprocess.run(['sc', 'stop', 'EmployeeMonitoringClient'], check=True)
                elif action == 'restart':
                    subprocess.run(['sc', 'stop', 'EmployeeMonitoringClient'], check=True)
                    time.sleep(2)
                    subprocess.run(['sc', 'start', 'EmployeeMonitoringClient'], check=True)
            elif self.platform == 'linux':
                if action == 'start':
                    subprocess.run(['systemctl', 'start', 'EmployeeMonitoringClient'], check=True)
                elif action == 'stop':
                    subprocess.run(['systemctl', 'stop', 'EmployeeMonitoringClient'], check=True)
                elif action == 'restart':
                    subprocess.run(['systemctl', 'restart', 'EmployeeMonitoringClient'], check=True)
            else:
                logger.error(f"Unsupported platform for service control: {self.platform}")
                return False
            
            # Send success response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'success',
                'message': f'Service control {action} completed successfully'
            }
            self._send_data(response)
            
            return True
            
        except Exception as e:
            logger.error(f"Service control command failed: {e}")
            # Send error response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'error',
                'message': f'Service control failed: {str(e)}'
            }
            self._send_data(response)
            return False
    
    def _handle_config_update_command(self, command: Dict[str, Any]) -> bool:
        """Handle configuration update command from server."""
        try:
            new_config = command.get('config', {})
            logger.info("Updating client configuration from server")
            
            # Update local config
            for section, options in new_config.items():
                if not self.config.has_section(section):
                    self.config.add_section(section)
                
                for key, value in options.items():
                    self.config.set(section, key, str(value))
            
            # Save updated config
            with open('config.ini', 'w') as configfile:
                self.config.write(configfile)
            
            # Send success response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'success',
                'message': 'Configuration updated successfully'
            }
            self._send_data(response)
            
            logger.info("Configuration updated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Configuration update failed: {e}")
            # Send error response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'error',
                'message': f'Configuration update failed: {str(e)}'
            }
            self._send_data(response)
            return False
    
    def _handle_chat_message_command(self, command: Dict[str, Any]) -> bool:
        """Handle chat message command from server."""
        try:
            message = command.get('message', '')
            msg_id = command.get('message_id')
            logger.info(f"Received chat message from server: {message}")
            
            # Call the message handler method directly
            if hasattr(self, 'message_callback') and self.message_callback:
                self.message_callback(message, msg_id)
            
            # Send acknowledgment response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'success',
                'message': 'Chat message received'
            }
            self._send_data(response)
            
            return True
            
        except Exception as e:
            logger.error(f"Chat message handling failed: {e}")
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'error',
                'message': f'Chat message handling failed: {str(e)}'
            }
            self._send_data(response)
            return False
    
    def _handle_file_list_request(self, command: Dict[str, Any]) -> bool:
        """Handle file list request from server."""
        try:
            directory_path = command.get('directory_path', '/')
            logger.info(f"File list request for directory: {directory_path}")
            
            # Normalize path for Windows
            if self.platform == 'windows':
                if directory_path == '/':
                    directory_path = 'C:\\'
                elif directory_path.startswith('/'):
                    # Convert Unix-style paths to Windows
                    directory_path = directory_path.replace('/', '\\')
                    if len(directory_path) >= 2 and directory_path[1] == '\\':
                        directory_path = directory_path[0] + ':' + directory_path[1:]
                    else:
                        directory_path = 'C:' + directory_path
            
            # Get directory listing
            try:
                files = []
                directories = []
                
                if os.path.exists(directory_path):
                    logger.info(f"Directory exists, listing contents...")
                    for item in os.listdir(directory_path):
                        item_path = os.path.join(directory_path, item)
                        try:
                            if os.path.isdir(item_path):
                                directories.append(item)
                                logger.debug(f"Found directory: {item}")
                            else:
                                # Get file info
                                stat = os.stat(item_path)
                                files.append({
                                    'name': item,
                                    'type': 'file',
                                    'size': stat.st_size,
                                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                })
                                logger.debug(f"Found file: {item} ({stat.st_size} bytes)")
                        except (PermissionError, OSError) as e:
                            logger.warning(f"Could not access {item_path}: {e}")
                            continue
                else:
                    logger.warning(f"Directory does not exist: {directory_path}")
                    # Try to provide a default directory listing
                    if self.platform == 'windows':
                        default_dirs = ['C:\\', 'C:\\Users', 'C:\\Program Files', 'C:\\Windows']
                        for default_dir in default_dirs:
                            if os.path.exists(default_dir):
                                directory_path = default_dir
                                break
                        else:
                            directory_path = 'C:\\'
                    else:
                        default_dirs = ['/', '/home', '/var', '/etc']
                        for default_dir in default_dirs:
                            if os.path.exists(default_dir):
                                directory_path = default_dir
                                break
                        else:
                            directory_path = '/'
                    
                    # Try to list the default directory
                    try:
                        for item in os.listdir(directory_path):
                            item_path = os.path.join(directory_path, item)
                            try:
                                if os.path.isdir(item_path):
                                    directories.append(item)
                                else:
                                    stat = os.stat(item_path)
                                    files.append({
                                        'name': item,
                                        'type': 'file',
                                        'size': stat.st_size,
                                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                    })
                            except (PermissionError, OSError):
                                continue
                    except (PermissionError, OSError) as e:
                        logger.error(f"Could not access default directory {directory_path}: {e}")
                
                # Send file list response
                response = {
                    'type': 'file_list_response',
                    'client_id': self.client_id,
                    'directory_path': directory_path,
                    'files': files,
                    'directories': directories
                }
                
                logger.info(f"Sending file list response: {response}")
                success = self._send_data(response)
                
                if success:
                    logger.info(f"File list response sent successfully: {len(files)} files, {len(directories)} directories")
                else:
                    logger.error("Failed to send file list response")
                
                return success
                
            except PermissionError:
                logger.error(f"Permission denied accessing directory: {directory_path}")
                response = {
                    'type': 'file_list_response',
                    'client_id': self.client_id,
                    'directory_path': directory_path,
                    'files': [],
                    'directories': [],
                    'error': 'Permission denied'
                }
                self._send_data(response)
                return False
                
        except Exception as e:
            logger.error(f"File list request failed: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            
            response = {
                'type': 'file_list_response',
                'client_id': self.client_id,
                'directory_path': directory_path,
                'files': [],
                'directories': [],
                'error': str(e)
            }
            self._send_data(response)
            return False
    
    def _handle_file_content_request(self, command: Dict[str, Any]) -> bool:
        """Handle file content request from server."""
        try:
            file_path = command.get('file_path', '')
            logger.info(f"File content request for: {file_path}")
            
            # Normalize path for Windows
            if self.platform == 'windows':
                if file_path.startswith('/'):
                    # Convert Unix-style paths to Windows
                    file_path = file_path.replace('/', '\\')
                    if len(file_path) >= 2 and file_path[1] == '\\':
                        file_path = file_path[0] + ':' + file_path[1:]
                    else:
                        file_path = 'C:' + file_path
            
            if not os.path.exists(file_path):
                response = {
                    'type': 'file_content_response',
                    'client_id': self.client_id,
                    'file_path': file_path,
                    'error': 'File not found'
                }
                self._send_data(response)
                return False
            
            # Check if file is too large (limit to 10MB)
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB
                response = {
                    'type': 'file_content_response',
                    'client_id': self.client_id,
                    'file_path': file_path,
                    'error': 'File too large (max 10MB)'
                }
                self._send_data(response)
                return False
            
            # Read file content
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Check if file is binary
                is_binary = self._is_binary_file(content)
                
                if is_binary:
                    # Encode binary content as base64
                    content_b64 = base64.b64encode(content).decode('utf-8')
                    response = {
                        'type': 'file_content_response',
                        'client_id': self.client_id,
                        'file_path': file_path,
                        'content': content_b64,
                        'file_size': file_size,
                        'is_binary': True
                    }
                else:
                    # Send text content directly
                    response = {
                        'type': 'file_content_response',
                        'client_id': self.client_id,
                        'file_path': file_path,
                        'content': content.decode('utf-8', errors='ignore'),
                        'file_size': file_size,
                        'is_binary': False
                    }
                
                self._send_data(response)
                logger.info(f"File content sent: {file_path} ({file_size} bytes)")
                return True
                
            except PermissionError:
                response = {
                    'type': 'file_content_response',
                    'client_id': self.client_id,
                    'file_path': file_path,
                    'error': 'Permission denied'
                }
                self._send_data(response)
                return False
                
        except Exception as e:
            logger.error(f"File content request failed: {e}")
            response = {
                'type': 'file_content_response',
                'client_id': self.client_id,
                'file_path': file_path,
                'error': str(e)
            }
            self._send_data(response)
            return False
    
    def _handle_file_operation_command(self, command: Dict[str, Any]) -> bool:
        """Handle file operation command from server."""
        try:
            operation = command.get('operation', '')
            file_path = command.get('file_path', '')
            logger.info(f"File operation request: {operation} on {file_path}")
            
            if operation == 'delete':
                return self._handle_file_delete(file_path, command)
            elif operation == 'copy':
                return self._handle_file_copy(file_path, command)
            elif operation == 'move':
                return self._handle_file_move(file_path, command)
            elif operation == 'create':
                return self._handle_file_create(file_path, command)
            else:
                logger.warning(f"Unknown file operation: {operation}")
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': operation,
                    'file_path': file_path,
                    'status': 'error',
                    'message': f'Unknown operation: {operation}'
                }
                self._send_data(response)
                return False
                
        except Exception as e:
            logger.error(f"File operation command failed: {e}")
            response = {
                'type': 'file_operation_response',
                'client_id': self.client_id,
                'operation': operation,
                'file_path': file_path,
                'status': 'error',
                'message': str(e)
            }
            self._send_data(response)
            return False
    
    def _is_binary_file(self, content: bytes) -> bool:
        """Check if file content is binary."""
        try:
            # Check for null bytes or non-printable characters
            return b'\x00' in content or not content.decode('utf-8', errors='ignore').isprintable()
        except:
            return True
    
    def _handle_file_delete(self, file_path: str, command: Dict[str, Any]) -> bool:
        """Handle file deletion."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'delete',
                    'file_path': file_path,
                    'status': 'success',
                    'message': 'File deleted successfully'
                }
                self._send_data(response)
                logger.info(f"File deleted: {file_path}")
                return True
            else:
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'delete',
                    'file_path': file_path,
                    'status': 'error',
                    'message': 'File not found'
                }
                self._send_data(response)
                return False
                
        except Exception as e:
            response = {
                'type': 'file_operation_response',
                'client_id': self.client_id,
                'operation': 'delete',
                'file_path': file_path,
                'status': 'error',
                'message': str(e)
            }
            self._send_data(response)
            return False
    
    def _handle_file_copy(self, file_path: str, command: Dict[str, Any]) -> bool:
        """Handle file copy operation."""
        try:
            destination = command.get('destination', '')
            if not destination:
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'copy',
                    'file_path': file_path,
                    'status': 'error',
                    'message': 'Destination path not specified'
                }
                self._send_data(response)
                return False
            
            if os.path.exists(file_path):
                shutil.copy2(file_path, destination)
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'copy',
                    'file_path': file_path,
                    'status': 'success',
                    'message': f'File copied to {destination}'
                }
                self._send_data(response)
                logger.info(f"File copied: {file_path} -> {destination}")
                return True
            else:
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'copy',
                    'file_path': file_path,
                    'status': 'error',
                    'message': 'Source file not found'
                }
                self._send_data(response)
                return False
                
        except Exception as e:
            response = {
                'type': 'file_operation_response',
                'client_id': self.client_id,
                'operation': 'copy',
                'file_path': file_path,
                'status': 'error',
                'message': str(e)
            }
            self._send_data(response)
            return False
    
    def _handle_file_move(self, file_path: str, command: Dict[str, Any]) -> bool:
        """Handle file move operation."""
        try:
            destination = command.get('destination', '')
            if not destination:
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'move',
                    'file_path': file_path,
                    'status': 'error',
                    'message': 'Destination path not specified'
                }
                self._send_data(response)
                return False
            
            if os.path.exists(file_path):
                shutil.move(file_path, destination)
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'move',
                    'file_path': file_path,
                    'status': 'success',
                    'message': f'File moved to {destination}'
                }
                self._send_data(response)
                logger.info(f"File moved: {file_path} -> {destination}")
                return True
            else:
                response = {
                    'type': 'file_operation_response',
                    'client_id': self.client_id,
                    'operation': 'move',
                    'file_path': file_path,
                    'status': 'error',
                    'message': 'Source file not found'
                }
                self._send_data(response)
                return False
                
        except Exception as e:
            response = {
                'type': 'file_operation_response',
                'client_id': self.client_id,
                'operation': 'move',
                'file_path': file_path,
                'status': 'error',
                'message': str(e)
            }
            self._send_data(response)
            return False
    
    def _handle_file_create(self, file_path: str, command: Dict[str, Any]) -> bool:
        """Handle file creation operation."""
        try:
            content = command.get('content', '')
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Write file content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            response = {
                'type': 'file_operation_response',
                'client_id': self.client_id,
                'operation': 'create',
                'file_path': file_path,
                'status': 'success',
                'message': 'File created successfully'
            }
            self._send_data(response)
            logger.info(f"File created: {file_path}")
            return True
            
        except Exception as e:
            response = {
                'type': 'file_operation_response',
                'client_id': self.client_id,
                'operation': 'create',
                'file_path': file_path,
                'status': 'error',
                'message': str(e)
            }
            self._send_data(response)
            return False


class ClientMainWindow(QMainWindow):
    """Main window for the monitoring client GUI."""
    
    # Define signals for thread-safe communication
    message_signal = Signal(str, str)  # message, message_id
    
    def __init__(self):
        super().__init__()
        self.client = MonitoringClient()
        self.monitoring_thread = None
        self.tray_icon = None
        
        # Create message manager for handling multiple message popups
        self.message_manager = MessageManager(self)
        
        # Connect the message signal
        self.message_signal.connect(self._show_server_message)
        
        # Connect client message callback BEFORE starting monitoring
        # Set up the client to use our method for message handling
        self.client.message_callback = self._handle_server_message
        
        self._init_ui()
        self._setup_system_tray()
        self._setup_timers()
        
        # Start monitoring last
        self._start_monitoring()
        
        # Debug: Verify button text after UI creation
        self._verify_button_text()
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Employee Monitoring Client")
        self.setGeometry(100, 100, 400, 300)
        self.setFixedSize(400, 300)
        
        # Set window icon
        try:
            self.setWindowIcon(QIcon("icon.png"))
        except:
            pass
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title_label = QLabel("🖥️ Employee Monitoring Client")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        layout.addWidget(title_label)
        
        # Status section
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        status_frame.setStyleSheet("""
            QFrame {
                border: 2px solid #3498db;
                border-radius: 10px;
                background-color: #ecf0f1;
            }
        """)
        status_layout = QVBoxLayout(status_frame)
        
        # Connection status
        self.connection_label = QLabel("🔴 Disconnected")
        self.connection_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.connection_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #e74c3c;
                padding: 5px;
            }
        """)
        status_layout.addWidget(self.connection_label)
        
        # Server info
        self.server_label = QLabel(f"Server: {self.client.server_host}:{self.client.server_port}")
        self.server_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.server_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #7f8c8d;
                padding: 5px;
            }
        """)
        status_layout.addWidget(self.server_label)
        
        # Client ID
        self.client_id_label = QLabel(f"Client ID: {self.client.client_id}")
        self.client_id_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.client_id_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #7f8c8d;
                padding: 5px;
            }
        """)
        status_layout.addWidget(self.client_id_label)
        
        layout.addWidget(status_frame)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3498db;
                border-radius: 5px;
                text-align: center;
                background-color: #ecf0f1;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Status message
        self.status_label = QLabel("Initializing...")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #7f8c8d;
                padding: 5px;
            }
        """)
        layout.addWidget(self.status_label)
        
        # Message popup status
        self.message_status_label = QLabel("Messages: 0")
        self.message_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message_status_label.setStyleSheet("""
            QLabel {
                font-size: 10px;
                color: #00BFFF;
                padding: 3px;
                background-color: #f8f9fa;
                border-radius: 3px;
                border: 1px solid #00BFFF;
            }
        """)
        layout.addWidget(self.message_status_label)
        
        # Control buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)  # Add spacing between buttons
        button_layout.setContentsMargins(10, 10, 10, 10)  # Add margins around the button area
        
        # Start/Stop button
        self.start_stop_button = QPushButton("⏹ Stop")
        self.start_stop_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: 2px solid #c0392b;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
                min-width: 80px;
                min-height: 32px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #c0392b;
                border-color: #a93226;
            }
            QPushButton:pressed {
                background-color: #a93226;
                border-color: #8e2a1f;
            }
        """)
        self.start_stop_button.clicked.connect(self._toggle_monitoring)
        self.start_stop_button.setToolTip("Stop/Start monitoring and screen capture")
        button_layout.addWidget(self.start_stop_button)
        
        # Debug: Log button creation
        logger.info(f"Created Start/Stop button with text: '{self.start_stop_button.text()}'")
        
        # Settings button
        self.settings_button = QPushButton("⚙ Settings")
        self.settings_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: 2px solid #7f8c8d;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
                min-width: 80px;
                min-height: 32px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
                border-color: #6c7b7d;
            }
            QPushButton:pressed {
                background-color: #6c7b7d;
                border-color: #5a6c7d;
            }
        """)
        self.settings_button.clicked.connect(self._show_settings)
        self.settings_button.setToolTip("Open client settings and configuration")
        button_layout.addWidget(self.settings_button)
        
        # Debug: Log button creation
        logger.info(f"Created Settings button with text: '{self.settings_button.text()}'")
        
        # Close all messages button
        self.close_messages_button = QPushButton("🗑️ Close All")
        self.close_messages_button.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: white;
                border: 2px solid #d35400;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
                min-width: 80px;
                min-height: 32px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #d35400;
                border-color: #ba4a00;
            }
            QPushButton:pressed {
                background-color: #ba4a00;
                border-color: #a04000;
            }
        """)
        self.close_messages_button.clicked.connect(self._close_all_messages)
        self.close_messages_button.setToolTip("Close all open message popups from the server")
        button_layout.addWidget(self.close_messages_button)
        
        # Debug: Log button creation
        logger.info(f"Created Close All button with text: '{self.close_messages_button.text()}'")
        
        layout.addLayout(button_layout)
        
        # Minimize to tray checkbox
        self.minimize_checkbox = QCheckBox("Minimize to system tray on close")
        self.minimize_checkbox.setChecked(True)
        self.minimize_checkbox.setStyleSheet("""
            QCheckBox {
                font-size: 11px;
                color: #7f8c8d;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
        """)
        layout.addWidget(self.minimize_checkbox)
    
    def _setup_system_tray(self):
        """Setup system tray icon and menu."""
        try:
            # Check if system tray is available
            if not QSystemTrayIcon.isSystemTrayAvailable():
                logger.warning("System tray is not available on this system")
                return
            
            # Create tray icon
            self.tray_icon = QSystemTrayIcon(self)
            
            # Set icon - try to use a default system icon if custom icon not found
            try:
                self.tray_icon.setIcon(QIcon("icon.png"))
            except:
                # Use a default icon - create a simple colored icon
                try:
                    # Create a simple colored icon
                    pixmap = QPixmap(32, 32)
                    pixmap.fill(QColor(52, 152, 219))  # Blue color
                    self.tray_icon.setIcon(QIcon(pixmap))
                except:
                    logger.warning("Could not create default icon for system tray")
            
            # Create tray menu
            tray_menu = QMenu()
            
            # Show/Hide action
            self.show_action = QAction("Show/Hide", self)
            self.show_action.triggered.connect(self._toggle_window_visibility)
            tray_menu.addAction(self.show_action)
            
            tray_menu.addSeparator()
            
            # Start/Stop action
            self.tray_start_stop_action = QAction("Stop Monitoring", self)
            self.tray_start_stop_action.triggered.connect(self._toggle_monitoring)
            tray_menu.addAction(self.tray_start_stop_action)
            
            # Settings action
            self.tray_settings_action = QAction("Settings", self)
            self.tray_settings_action.triggered.connect(self._show_settings)
            tray_menu.addAction(self.tray_settings_action)
            
            tray_menu.addSeparator()
            
            # Exit action
            exit_action = QAction("Exit", self)
            exit_action.triggered.connect(self._exit_application)
            tray_menu.addAction(exit_action)
            
            # Set tray menu
            self.tray_icon.setContextMenu(tray_menu)
            
            # Connect tray icon activation
            self.tray_icon.activated.connect(self._tray_icon_activated)
            
            # Show tray icon
            self.tray_icon.show()
            
            logger.info("System tray setup completed successfully")
            
        except Exception as e:
            logger.error(f"Failed to setup system tray: {e}")
            # Create a fallback tray icon
            try:
                self.tray_icon = QSystemTrayIcon(self)
                pixmap = QPixmap(32, 32)
                pixmap.fill(QColor(52, 152, 219))
                self.tray_icon.setIcon(QIcon(pixmap))
                self.tray_icon.show()
                logger.info("Fallback system tray icon created")
            except Exception as fallback_error:
                logger.error(f"Failed to create fallback system tray icon: {fallback_error}")
    
    def _ensure_tray_icon(self):
        """Ensure tray icon is available and visible."""
        if not self.tray_icon or not self.tray_icon.isVisible():
            logger.info("Recreating system tray icon")
            self._setup_system_tray()
    
    def _setup_timers(self):
        """Setup timers for periodic updates."""
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(1000)  # Update every second
    
    def _start_monitoring(self):
        """Start the monitoring thread."""
        try:
            if not self.monitoring_thread or not self.monitoring_thread.is_running:
                self.monitoring_thread = MonitoringThread(self.client)
                self.monitoring_thread.status_updated.connect(self._update_status)
                self.monitoring_thread.connection_status.connect(self._update_connection_status)
                self.monitoring_thread.error_occurred.connect(self._handle_error)
                self.monitoring_thread.start()
                
                self.start_stop_button.setText("⏹ Stop")
                self.start_stop_button.setStyleSheet("""
                    QPushButton {
                        background-color: #e74c3c;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 5px;
                        font-weight: bold;
                        font-size: 12px;
                    }
                    QPushButton:hover {
                        background-color: #c0392b;
                    }
                    QPushButton:pressed {
                        background-color: #a93226;
                    }
                """)
                
                self.tray_start_stop_action.setText("Stop Monitoring")
                self.status_label.setText("Monitoring started...")
                
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self._handle_error(str(e))
    
    def _stop_monitoring(self):
        """Stop the monitoring thread."""
        try:
            if self.monitoring_thread and self.monitoring_thread.is_running:
                self.monitoring_thread.stop()
                self.monitoring_thread.wait()
                
                self.start_stop_button.setText("▶ Start")
                self.start_stop_button.setStyleSheet("""
                    QPushButton {
                        background-color: #27ae60;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 5px;
                        font-weight: bold;
                        font-size: 12px;
                    }
                    QPushButton:hover {
                        background-color: #229954;
                    }
                    QPushButton:pressed {
                        background-color: #1e8449;
                    }
                """)
                
                self.tray_start_stop_action.setText("Start Monitoring")
                self.status_label.setText("Monitoring stopped")
                self.connection_label.setText("🔴 Disconnected")
                self.connection_label.setStyleSheet("""
                    QLabel {
                        font-size: 14px;
                        font-weight: bold;
                        color: #e74c3c;
                        padding: 5px;
                    }
                """)
                
        except Exception as e:
            logger.error(f"Failed to stop monitoring: {e}")
            self._handle_error(str(e))
    
    def _toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if self.monitoring_thread and self.monitoring_thread.is_running:
            self._stop_monitoring()
        else:
            self._start_monitoring()
    
    def _update_status(self, status: str = '', message: str = ''):
        """Update status display."""
        try:
            if self.client.connected:
                self.connection_label.setText("🟢 Connected")
                self.connection_label.setStyleSheet("""
                    QLabel {
                        font-size: 14px;
                        font-weight: bold;
                        color: #27ae60;
                        padding: 5px;
                    }
                """)
                self.progress_bar.setRange(0, 0)  # Indeterminate
            else:
                self.connection_label.setText("🔴 Disconnected")
                self.connection_label.setStyleSheet("""
                    QLabel {
                        font-size: 14px;
                        font-weight: bold;
                        color: #e74c3c;
                        padding: 5px;
                    }
                """)
                self.progress_bar.setRange(0, 1)
                self.progress_bar.setValue(0)
            
            # Update message popup count
            if hasattr(self, 'message_manager'):
                message_count = self.message_manager.get_unread_count()
                self.message_status_label.setText(f"Messages: {message_count}")
                if message_count > 0:
                    self.message_status_label.setStyleSheet("""
                        QLabel {
                            font-size: 10px;
                            color: #e74c3c;
                            padding: 3px;
                            background-color: #fdf2f2;
                            border-radius: 3px;
                            border: 1px solid #e74c3c;
                            font-weight: bold;
                        }
                    """)
                else:
                    self.message_status_label.setStyleSheet("""
                        QLabel {
                            font-size: 10px;
                            color: #00BFFF;
                            padding: 3px;
                            background-color: #f8f9fa;
                            border-radius: 3px;
                            border: 1px solid #00BFFF;
                        }
                    """)
                
        except Exception as e:
            logger.error(f"Error updating status: {e}")
    
    def _update_connection_status(self, connected: bool):
        """Update connection status from monitoring thread."""
        self.client.connected = connected
        if connected:
            self.status_label.setText("Connected to server")
        else:
            self.status_label.setText("Disconnected from server")
    
    def _handle_error(self, error_message: str):
        """Handle errors from monitoring thread."""
        self.status_label.setText(f"Error: {error_message}")
        logger.error(f"GUI error: {error_message}")
    
    def _toggle_window_visibility(self):
        """Toggle window visibility."""
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.raise_()
            self.activateWindow()
    
    def _tray_icon_activated(self, reason):
        """Handle tray icon activation."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._toggle_window_visibility()
    
    def _show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog not implemented yet.")
    
    def _close_all_messages(self):
        """Close all active message popups."""
        try:
            if hasattr(self, 'message_manager'):
                self.message_manager.close_all_popups()
                logger.info("All message popups closed manually")
        except Exception as e:
            logger.error(f"Error closing all messages: {e}")
    
    def _handle_server_message(self, message: str, message_id: str = None):
        """Handle a message received from the server."""
        try:
            # Emit the signal to trigger the GUI update
            self.message_signal.emit(message, message_id)
            logger.info(f"Server message handled: {message}")
        except Exception as e:
            logger.error(f"Error handling server message: {e}")
    
    def _show_server_message(self, message: str, message_id: str = None):
        """Show a message from the server using the message manager."""
        try:
            # Count as unseen before popup is shown; showing the popup marks it delivered
            if hasattr(self, 'message_manager'):
                try:
                    self.message_manager.increment_unseen()
                except Exception:
                    pass
            shown_id = self.message_manager.show_message(message, message_id=message_id, auto_close=False)
            if shown_id:
                logger.info(f"Showing server message with ID: {shown_id}")
            else:
                logger.error("Failed to show server message")
        except Exception as e:
            logger.error(f"Error showing server message: {e}")
    
    def message_popup_closed(self, message_id: str):
        """Handle message popup closure notification."""
        try:
            logger.info(f"Message popup closed: {message_id}")
            # Ensure manager state is cleaned up and popups are repositioned
            if hasattr(self, 'message_manager') and isinstance(self.message_manager.active_popups, dict):
                try:
                    if message_id in self.message_manager.active_popups:
                        del self.message_manager.active_popups[message_id]
                        # Reposition remaining popups safely
                        try:
                            self.message_manager._reposition_popups()
                        except Exception:
                            pass
                except Exception as cleanup_err:
                    logger.debug(f"Popup cleanup error: {cleanup_err}")
        except Exception as e:
            logger.error(f"Error handling popup closure: {e}")
    
    def _exit_application(self):
        """Exit the application."""
        try:
            # Stop monitoring
            if self.monitoring_thread and self.monitoring_thread.is_running:
                self._stop_monitoring()
            
            # Close all message popups
            if hasattr(self, 'message_manager'):
                self.message_manager.close_all_popups()
            
            # Hide tray icon
            if self.tray_icon:
                self.tray_icon.hide()
            
            # Exit
            QApplication.quit()
            
        except Exception as e:
            logger.error(f"Error during exit: {e}")
            QApplication.quit()
    
    def closeEvent(self, event):
        """Handle window close event."""
        try:
            # Ensure tray icon is available
            self._ensure_tray_icon()
            
            if self.minimize_checkbox.isChecked() and self.tray_icon and self.tray_icon.isVisible():
                # Minimize to tray
                self.hide()
                event.ignore()
                
                # Show tray notification
                try:
                    self.tray_icon.showMessage(
                        "Employee Monitoring Client",
                        "Application minimized to system tray",
                        QSystemTrayIcon.MessageIcon.Information,
                        2000
                    )
                except Exception as e:
                    logger.warning(f"Could not show tray notification: {e}")
                
                logger.info("Application minimized to system tray")
                
                # Ensure the application stays alive
                QTimer.singleShot(100, lambda: self._ensure_application_running())
            else:
                # Close all message popups before exiting
                if hasattr(self, 'message_manager'):
                    self.message_manager.close_all_popups()
                
                # Exit application
                self._exit_application()
                event.accept()
                
        except Exception as e:
            logger.error(f"Error in closeEvent: {e}")
            # Fallback to normal exit
            self._exit_application()
            event.accept()
    
    def _verify_button_text(self):
        """Debug method to verify button text is properly set."""
        try:
            logger.info("=== Button Text Verification ===")
            logger.info(f"Start/Stop button text: '{self.start_stop_button.text()}'")
            logger.info(f"Settings button text: '{self.settings_button.text()}'")
            logger.info(f"Close All button text: '{self.close_messages_button.text()}'")
            logger.info(f"Start/Stop button size: {self.start_stop_button.size()}")
            logger.info(f"Settings button size: {self.settings_button.size()}")
            logger.info(f"Close All button size: {self.close_messages_button.size()}")
            logger.info("=== End Button Text Verification ===")
        except Exception as e:
            logger.error(f"Error verifying button text: {e}")
    
    def _ensure_application_running(self):
        """Ensure the application stays running when minimized to tray."""
        if not self.isVisible() and self.tray_icon and self.tray_icon.isVisible():
            # Application is minimized to tray, ensure it stays alive
            logger.debug("Application is running in system tray")


def main():
    """Main entry point for the GUI client."""
    try:
        # Create Qt application
        app = QApplication(sys.argv)
        app.setQuitOnLastWindowClosed(False)  # Keep app running when window is closed
        
        # Set application style
        app.setStyle('Fusion')
        
        # Set application properties
        app.setApplicationName("Employee Monitoring Client")
        app.setApplicationVersion("1.0")
        app.setOrganizationName("Employee Monitoring System")
        
        # Create and show main window
        window = ClientMainWindow()
        window.show()
        
        # Start event loop
        logger.info("GUI client started successfully")
        
        # Ensure application doesn't quit when window is closed
        app.aboutToQuit.connect(window._exit_application)
        
        sys.exit(app.exec())
        
    except Exception as e:
        logger.error(f"Application failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == "__main__":
    main()
