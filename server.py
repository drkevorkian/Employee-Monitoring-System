#!/usr/bin/env python3
"""
Server Program for Employee Monitoring System
Handles multiple client connections and provides a modern GUI for monitoring.
"""

import os
import sys
import time
import json
import socket
import threading
import logging
import configparser
import base64
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import queue
import uuid

# Import required libraries with error handling
try:
    from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QGridLayout, QLabel, QPushButton, 
                                 QTextEdit, QTabWidget, QSplitter, QScrollArea,
                                 QFrame, QGroupBox, QTableWidget, QTableWidgetItem,
                                 QHeaderView, QProgressBar, QStatusBar, QMenuBar,
                                 QMessageBox, QInputDialog, QFileDialog, QSlider)
    from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSize, QRect, QEvent
    from PySide6.QtGui import (QPixmap, QImage, QFont, QIcon, QPalette, QColor,
                              QPainter, QPen, QBrush)
except ImportError as e:
    print(f"Required library not found: {e}")
    print("Please install required packages: pip install -r requirements.txt")
    sys.exit(1)

# Import our custom modules
try:
    from security import SecurityManager
    from database import SecureDatabase
except ImportError as e:
    print(f"Custom module not found: {e}")
    print("Please ensure security.py and database.py are in the same directory")
    sys.exit(1)

# Import our custom logging system
try:
    from logging_config import get_logger
    logger = get_logger('server')
except ImportError as e:
    # Fallback to basic logging if custom system not available
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('server.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)

from updater.service import UpdaterService  # type: ignore
from version import get_version

class ClientConnection:
    """Represents a client connection with its associated data."""
    
    def __init__(self, client_socket: socket.socket, address: Tuple[str, int]):
        self.socket = client_socket
        self.address = address
        self.client_id = None
        self.hostname = None
        self.platform = None
        self.last_seen = datetime.now()
        self.is_active = True
        self.screen_captures = []
        self.system_info = {}
        self.session_token = None

class MonitoringServer:
    """
    Multi-threaded monitoring server that handles client connections
    and manages screen capture data.
    """
    
    def __init__(self, config_file: str = 'config.ini'):
        """
        Initialize the monitoring server.
        
        Args:
            config_file: Path to configuration file
        """
        self.config = self._load_config(config_file)
        self.host = self.config.get('Server', 'host', fallback='0.0.0.0')
        self.port = self.config.getint('Server', 'port', fallback=8080)
        self.max_clients = self.config.getint('Server', 'max_clients', fallback=250)
        self.max_connections_per_ip = self.config.getint('Server', 'max_connections_per_ip', fallback=10)
        self.connection_timeout = self.config.getint('Server', 'connection_timeout', fallback=30)
        self.heartbeat_interval = self.config.getint('Server', 'heartbeat_interval', fallback=10)
        
        # Initialize security and database
        self.security_manager = SecurityManager(self.config)
        try:
            self.database = SecureDatabase(self.config)
        except Exception as e:
            emsg = str(e).lower()
            # Auto-recover from common SQLite corruption states by wiping DB and reinitializing once
            corruption_signals = (
                'malformed database schema',
                'database disk image is malformed',
                'file is encrypted or is not a database'
            )
            if any(sig in emsg for sig in corruption_signals):
                logger.error(f"Database init error detected ('{emsg}'). Attempting auto-recovery by recreating DB…")
                try:
                    self._wipe_corrupt_database()
                    self.database = SecureDatabase(self.config)
                    logger.warning("Database auto-recovery completed; fresh schema created.")
                except Exception as rec_err:
                    logger.error(f"Database auto-recovery failed: {rec_err}")
                    raise
            else:
                raise
        
        # Server state
        self.is_running = False
        self.server_socket = None
        self.clients: Dict[str, ClientConnection] = {}
        self.client_sockets: List[socket.socket] = []
        self.ip_connection_counts: Dict[str, int] = {}
        
        # Threading
        self.accept_thread = None
        self.client_threads: List[threading.Thread] = []
        self.client_data_queue = queue.Queue()
        
        # Performance monitoring
        self.total_connections = 0
        self.total_data_received = 0
        self.start_time = None
        
        # Command tracking
        self.command_responses = {}
        
        # GUI callback (will be set by GUI)
        self.gui_callback = None
        
        # Updater: simple file-based check stub
        def _check_local_update():
            try:
                meta_path = os.path.join(os.getcwd(), 'update_meta.json')
                if os.path.exists(meta_path):
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except Exception:
                return None
            return None
        self.updater = UpdaterService(current_version=get_version(), check_func=_check_local_update, poll_seconds=15)
        self.updater.start()
        
        # Admin command token (for web bridge)
        try:
            self.admin_token = os.environ.get('EMS_ADMIN_TOKEN') or self.config.get('WebAdmin', 'admin_token')
        except Exception:
            self.admin_token = ''
        try:
            self.admin_port = int(os.environ.get('EMS_ADMIN_PORT') or self.config.get('WebAdmin', 'admin_port', fallback='9090'))
        except Exception:
            self.admin_port = 9090
        self._start_admin_http_server()
        
        logger.info(f"Monitoring server initialized: {self.host}:{self.port}")

    def _wipe_corrupt_database(self) -> None:
        """Delete the configured SQLite database file and sidecars to allow a clean reinit."""
        try:
            db_path = self.config.get('Database', 'db_path', fallback='monitoring.db')
        except Exception:
            db_path = 'monitoring.db'
        candidates = [db_path, f"{db_path}-shm", f"{db_path}-wal"]
        for p in candidates:
            try:
                if os.path.exists(p):
                    os.remove(p)
                    logger.info(f"Removed database artifact: {p}")
            except Exception as e:
                logger.warning(f"Failed to remove database artifact {p}: {e}")
    
    def set_gui_callback(self, callback):
        """Set the GUI callback function for updates."""
        self.gui_callback = callback
        logger.info("GUI callback set successfully")
    
    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        if os.path.exists(config_file):
            config.read(config_file)
            logger.info(f"Configuration loaded from {config_file}")
        else:
            logger.warning(f"Configuration file {config_file} not found, using defaults")
        
        return config

    def _start_admin_http_server(self):
        # Lightweight HTTP listener for admin actions (localhost only by default)
        try:
            import http.server
            import threading as _t
            server_ref = self
            class AdminHandler(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    length = int(self.headers.get('Content-Length', '0'))
                    body = self.rfile.read(length) if length > 0 else b''
                    token = self.headers.get('X-Admin-Token', '')
                    # Enforce token only if configured; always localhost-bound
                    if server_ref.admin_token and token != server_ref.admin_token:
                        self.send_response(401); self.end_headers(); self.wfile.write(b'{}'); return
                    try:
                        import json as _json
                        data = _json.loads(body.decode('utf-8') or '{}')
                        cmd = data.get('command')
                        client_id = data.get('client_id')
                        ok = False
                        if cmd == 'reboot' and client_id:
                            ok = server_ref.send_reboot_command(client_id)
                        elif cmd == 'shutdown' and client_id:
                            ok = server_ref.send_shutdown_command(client_id)
                        elif cmd == 'os_update_check' and client_id:
                            ok = server_ref.send_config_update_command(client_id, {'Update': {'check':'1'}})
                        elif cmd == 'os_update_apply' and client_id:
                            ok = server_ref.send_config_update_command(client_id, {'Update': {'apply':'1'}})
                        elif cmd == 'send_chat' and client_id:
                            text = str(data.get('message') or '')
                            if text:
                                ok, _mid = server_ref.send_chat_message(client_id, text)
                            else:
                                ok = False
                        elif cmd == 'exec' and client_id:
                            c = str(data.get('cmd') or '')
                            args = data.get('args') or []
                            as_admin = bool(data.get('as_admin', False))
                            timeout = int(data.get('timeout', 30))
                            ok = bool(server_ref.send_exec_command(client_id, c, args, as_admin, timeout))
                        self.send_response(200); self.end_headers(); self.wfile.write(_json.dumps({'ok': bool(ok)}).encode('utf-8'))
                    except Exception:
                        self.send_response(500); self.end_headers(); self.wfile.write(b'{"ok":false}')
                def log_message(self, fmt, *args):
                    return
            def _serve():
                import socketserver
                with socketserver.TCPServer(("127.0.0.1", self.admin_port), AdminHandler) as httpd:
                    httpd.serve_forever()
            _t.Thread(target=_serve, daemon=True).start()
            logger.info(f"Admin HTTP server listening on 127.0.0.1:{self.admin_port}")
        except Exception as e:
            logger.warning(f"Admin HTTP server failed to start: {e}")
    
    def start(self):
        """Start the monitoring server."""
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_clients)
            self.server_socket.settimeout(1)  # 1 second timeout for accept
            
            self.is_running = True
            self.start_time = time.time()
            
            # Clean up any stale client states from previous server runs
            self._cleanup_stale_clients()
            
            # Start accept thread
            self.accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            self.accept_thread.start()
            
            # Start client data processing thread
            self.data_processing_thread = threading.Thread(target=self._process_client_data, daemon=True)
            self.data_processing_thread.start()
            
            logger.info(f"Server started successfully on {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise
    
    def _accept_connections(self):
        """Accept incoming client connections."""
        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                
                # Check connection limits
                if not self._can_accept_connection(address[0]):
                    logger.warning(f"Connection limit exceeded for {address[0]}")
                    client_socket.close()
                    continue
                
                # Create client connection
                client_conn = ClientConnection(client_socket, address)
                
                # Start client handling thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_conn,),
                    daemon=True
                )
                client_thread.start()
                self.client_threads.append(client_thread)
                
                # Update connection counts
                self.ip_connection_counts[address[0]] = self.ip_connection_counts.get(address[0], 0) + 1
                self.total_connections += 1
                
                logger.info(f"New client connected: {address[0]}:{address[1]}")
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _can_accept_connection(self, ip_address: str) -> bool:
        """Check if we can accept a new connection from this IP."""
        current_count = self.ip_connection_counts.get(ip_address, 0)
        return current_count < self.max_connections_per_ip
    
    def _handle_client(self, client_conn: ClientConnection):
        """Handle individual client communication."""
        try:
            while self.is_running and client_conn.is_active:
                # Receive data from client
                data = self._receive_data(client_conn.socket)
                if not data:
                    break
                
                # Process client data
                self._process_client_message(client_conn, data)
                
        except Exception as e:
            logger.error(f"Error handling client {client_conn.address}: {e}")
        finally:
            self._cleanup_client(client_conn)
    
    def _receive_data(self, client_socket: socket.socket) -> Optional[Dict[str, Any]]:
        """Receive data from client socket."""
        try:
            # Receive data length first
            length_bytes = client_socket.recv(4)
            if not length_bytes:
                return None
            
            data_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive data in chunks
            data_bytes = b''
            while len(data_bytes) < data_length:
                chunk = client_socket.recv(min(4096, data_length - len(data_bytes)))
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
                    logger.error(f"Failed to decrypt/parse client data: {e}")
                    return None
            else:
                logger.error("Incomplete data received from client")
                return None
                
        except Exception as e:
            logger.error(f"Failed to receive data from client: {e}")
            return None
    
    def _process_client_message(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Process messages from clients."""
        try:
            message_type = message.get('type')
            
            if message_type == 'client_registration':
                self._handle_client_registration(client_conn, message)
            elif message_type == 'screen_capture':
                self._handle_screen_capture(client_conn, message)
            elif message_type == 'heartbeat':
                self._handle_heartbeat(client_conn, message)
            elif message_type == 'heartbeat_response':
                self._handle_heartbeat_response(client_conn, message)
            elif message_type == 'command_response':
                self._handle_command_response(client_conn, message)
            elif message_type == 'chat_message':
                self._handle_chat_message(client_conn, message)
            elif message_type == 'chat_response':
                self._handle_chat_response(client_conn, message)
            elif message_type == 'message_status':
                self._handle_message_status(client_conn, message)
            elif message_type == 'file_list_response':
                self._handle_file_list_response(client_conn, message)
            elif message_type == 'file_content_response':
                self._handle_file_content_response(client_conn, message)
            elif message_type == 'file_operation_response':
                self._handle_file_operation_response(client_conn, message)
            elif message_type == 'admin_command':
                self._handle_admin_command(client_conn, message)
            elif message_type == 'client_log':
                self._handle_client_log(client_conn, message)
            elif message_type == 'exec_result':
                self._handle_exec_result(client_conn, message)
            else:
                logger.warning(f"Unknown message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error processing client message: {e}")
    
    def _handle_client_registration(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle client registration."""
        try:
            client_id = message.get('client_id')
            system_info = message.get('system_info', {})
            
            # Store client information
            client_conn.client_id = client_id
            client_conn.hostname = system_info.get('hostname', 'Unknown')
            client_conn.platform = system_info.get('platform', 'Unknown')
            client_conn.system_info = system_info
            
            # Generate session token
            session_token = self.security_manager.generate_secure_token()
            client_conn.session_token = session_token
            
            # Add to clients dictionary
            self.clients[client_id] = client_conn
            
            # Store in database
            client_data = {
                'client_id': client_id,
                'hostname': client_conn.hostname,
                'platform': client_conn.platform,
                'ip_address': client_conn.address[0],
                'mac_address': system_info.get('network_info', {}).get('mac_address'),
                'logged_in_user': system_info.get('logged_in_user'),
                'user_agent': 'Monitoring Client',
                'version': '1.0',
                'capabilities': system_info.get('capabilities', {})
            }
            # attach uptime if provided
            try:
                if 'uptime_seconds' in system_info:
                    caps = client_data.get('capabilities') or {}
                    caps['uptime_seconds'] = system_info.get('uptime_seconds')
                    client_data['capabilities'] = caps
            except Exception:
                pass
            self.database.add_client(client_data)
            
            # Create session in database
            self.database.create_session(
                session_token, client_id, 'monitoring_user',
                client_conn.address[0]
            )
            
            # Send acceptance response
            response = {
                'status': 'accepted',
                'session_token': session_token,
                'message': 'Client registered successfully'
            }
            self._send_data(client_conn.socket, response)
            
            # Call GUI callback if available
            if self.gui_callback:
                try:
                    self.gui_callback('client_registered', client_id, client_conn.hostname, client_conn.platform)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
            logger.info(f"Client registered: {client_id} ({client_conn.hostname})")
            
            # Attempt to deliver any queued messages now that client is online
            try:
                self._deliver_queued_messages(client_id)
            except Exception as e:
                logger.debug(f"No queued messages delivered for {client_id}: {e}")
            
        except Exception as e:
            logger.error(f"Error handling client registration: {e}")
            # Send rejection response
            response = {
                'status': 'rejected',
                'message': 'Registration failed'
            }
            self._send_data(client_conn.socket, response)
    
    def _handle_screen_capture(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle screen capture data from client."""
        try:
            client_id = message.get('client_id')
            image_data_b64 = message.get('image_data')
            metadata = message.get('metadata', {})
            
            # Decode image data
            image_data = base64.b64decode(image_data_b64)
            
            # Update total data received counter
            self.total_data_received += len(image_data)
            
            # Store in database
            self.database.store_screen_capture(client_id, image_data, metadata)
            
            # Add to client's capture list (keep only recent ones)
            capture_info = {
                'timestamp': datetime.now(),
                'image_data': image_data,
                'metadata': metadata
            }
            client_conn.screen_captures.append(capture_info)
            
            # Keep only last 10 captures
            if len(client_conn.screen_captures) > 10:
                client_conn.screen_captures.pop(0)
            
            # Update last seen
            client_conn.last_seen = datetime.now()
            
            # Update database
            self.database.update_client_status(client_id, 'active')
            
            # Add to processing queue for GUI updates
            self.client_data_queue.put({
                'type': 'screen_capture',
                'client_id': client_id,
                'capture_info': capture_info
            })
            
            # Call GUI callback if available (this will be handled by the main thread)
            if self.gui_callback:
                try:
                    self.gui_callback('screen_capture', client_id, image_data, metadata)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
            logger.info(f"Screen capture received from {client_id}: {len(image_data)} bytes")
            
        except Exception as e:
            logger.error(f"Error handling screen capture: {e}")
    
    def _handle_heartbeat(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle client heartbeat."""
        try:
            client_conn.last_seen = datetime.now()
            
            # Send heartbeat command
            response = {
                'type': 'heartbeat',
                'timestamp': datetime.now().isoformat()
            }
            self._send_data(client_conn.socket, response)
            
        except Exception as e:
            logger.error(f"Error handling heartbeat: {e}")
    
    def _handle_heartbeat_response(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle heartbeat response from client."""
        try:
            client_conn.last_seen = datetime.now()
            logger.debug(f"Heartbeat response received from {client_conn.client_id}")
            
        except Exception as e:
            logger.error(f"Error handling heartbeat response: {e}")
    
    def _handle_command_response(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle command response from client."""
        try:
            command_id = message.get('command_id')
            status = message.get('status')
            response_message = message.get('message', '')
            
            logger.info(f"Command response from {client_conn.client_id}: {status} - {response_message}")
            
            # Store command response for tracking
            if hasattr(self, 'command_responses'):
                self.command_responses[command_id] = {
                    'client_id': client_conn.client_id,
                    'status': status,
                    'message': response_message,
                    'timestamp': datetime.now()
                }
            
        except Exception as e:
            logger.error(f"Error handling command response: {e}")
    
    def _handle_chat_message(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle chat message from client."""
        try:
            client_id = message.get('client_id')
            chat_message = message.get('message', '')
            timestamp = message.get('timestamp', datetime.now().isoformat())
            
            logger.info(f"Chat message from {client_id}: {chat_message}")
            
            # Store in database
            self.database.store_chat_message(client_id, chat_message, timestamp, 'client_to_server')
            
            # Call GUI callback for chat updates
            if self.gui_callback:
                try:
                    self.gui_callback('chat_message', client_id, chat_message, timestamp)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
        except Exception as e:
            logger.error(f"Error handling chat message: {e}")
    
    def _handle_chat_response(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle chat response from client."""
        try:
            client_id = client_conn.client_id
            chat_response = message.get('message', '')
            timestamp = message.get('timestamp', datetime.now().isoformat())
            
            logger.info(f"Chat response from {client_id}: {chat_response}")
            
            # Store in database
            self.database.store_chat_message(client_id, chat_response, timestamp, 'client_to_server')
            
            # Call GUI callback for chat updates
            if self.gui_callback:
                try:
                    self.gui_callback('chat_response', client_id, chat_response, timestamp)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
        except Exception as e:
            logger.error(f"Error handling chat response: {e}")

    def _handle_client_log(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle client log forwarding: persist to DB and audit trail."""
        try:
            client_id = message.get('client_id') or client_conn.client_id
            level = (message.get('level') or 'info').lower()
            text = message.get('message') or ''
            logger_name = message.get('logger') or 'client'
            ts = message.get('timestamp') or datetime.now().isoformat()
            module = message.get('module') or ''
            func = message.get('func') or ''
            try:
                line = int(message.get('line') or 0)
            except Exception:
                line = 0

            # Store in dedicated table
            self.database.store_client_log(
                client_id=client_id,
                level=level,
                message=text,
                logger_name=logger_name,
                timestamp=ts,
                module=module,
                function=func,
                line=line,
                ip_address=client_conn.address[0] if client_conn and client_conn.address else None,
            )

            # Mirror into activity logs for audit
            try:
                details = json.dumps({
                    'level': level,
                    'logger': logger_name,
                    'module': module,
                    'func': func,
                    'line': line,
                    'message': text[:500]
                })
            except Exception:
                details = text[:500]
            self.database.add_activity_log(
                client_id=client_id,
                action='client_log',
                details=details,
                ip_address=client_conn.address[0] if client_conn and client_conn.address else None,
                severity=level
            )
        except Exception as e:
            logger.error(f"Error handling client log: {e}")

    def _handle_message_status(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle message status updates from client (delivered/read/deleted)."""
        try:
            status = message.get('status')
            message_id = message.get('message_id')
            if not message_id:
                return
            if status == 'delivered':
                self.database.mark_message_delivered(message_id)
            elif status == 'read':
                self.database.mark_message_read(message_id)
            elif status == 'deleted':
                self.database.soft_delete_message(message_id)
            # Notify GUI so it can update status indicators
            if self.gui_callback and client_conn.client_id:
                try:
                    self.gui_callback('message_status', client_conn.client_id, status, message_id)
                except Exception as e:
                    logger.error(f"GUI callback failed for message_status: {e}")
        except Exception as e:
            logger.error(f"Error handling message status: {e}")
    
    def _handle_file_list_response(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle file list response from client."""
        try:
            client_id = message.get('client_id')
            directory_path = message.get('directory_path', '')
            files = message.get('files', [])
            directories = message.get('directories', [])
            
            logger.info(f"File list response from {client_id} for {directory_path}: {len(files)} files, {len(directories)} directories")
            
            # Store in database
            self.database.store_file_list_response(client_id, directory_path, files, directories)
            
            # Call GUI callback for file browser updates
            if self.gui_callback:
                try:
                    self.gui_callback('file_list_response', client_id, directory_path, files, directories)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
        except Exception as e:
            logger.error(f"Error handling file list response: {e}")
    
    def _handle_file_content_response(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle file content response from client."""
        try:
            client_id = message.get('client_id')
            file_path = message.get('file_path', '')
            file_content = message.get('content', '')
            file_size = message.get('file_size', 0)
            is_binary = message.get('is_binary', False)
            
            logger.info(f"File content response from {client_id} for {file_path}: {file_size} bytes, binary: {is_binary}")
            
            # Store in database
            self.database.store_file_content_response(client_id, file_path, file_content, file_size, is_binary)
            
            # Call GUI callback for file viewer updates
            if self.gui_callback:
                try:
                    self.gui_callback('file_content_response', client_id, file_path, file_content, file_size, is_binary)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
        except Exception as e:
            logger.error(f"Error handling file content response: {e}")
    
    def _handle_file_operation_response(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Handle file operation response from client."""
        try:
            client_id = message.get('client_id')
            operation = message.get('operation', '')
            file_path = message.get('file_path', '')
            status = message.get('status', '')
            message_text = message.get('message', '')
            
            logger.info(f"File operation response from {client_id}: {operation} on {file_path} - {status}: {message_text}")
            
            # Store in database
            self.database.store_file_operation_response(client_id, operation, file_path, status, message_text)
            
            # Call GUI callback for file operation updates
            if self.gui_callback:
                try:
                    self.gui_callback('file_operation_response', client_id, operation, file_path, status, message_text)
                except Exception as e:
                    logger.error(f"GUI callback failed: {e}")
            
        except Exception as e:
            logger.error(f"Error handling file operation response: {e}")

    def send_exec_command(self, client_id: str, cmd: str, args: list[str] | None = None, as_admin: bool = False, timeout: int = 30) -> Optional[str]:
        """Send an exec command to client; returns command_id if dispatched."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return None
            command_id = str(uuid.uuid4())
            payload = {
                'type': 'exec',
                'command_id': command_id,
                'cmd': cmd,
                'args': args or [],
                'as_admin': bool(as_admin),
                'timeout': int(timeout),
            }
            self._send_data(self.clients[client_id].socket, payload)
            return command_id
        except Exception as e:
            logger.error(f"Failed to send exec command: {e}")
            return None

    def _handle_exec_result(self, client_conn: ClientConnection, message: Dict[str, Any]):
        """Persist exec results from clients and emit GUI updates."""
        try:
            data = {
                'client_id': message.get('client_id') or client_conn.client_id,
                'command_id': message.get('command_id'),
                'exit_code': message.get('exit_code'),
                'stdout': message.get('stdout') or '',
                'stderr': message.get('stderr') or '',
                'cmd': (message.get('cmd') or [''])[0],
                'timestamp': message.get('timestamp') or datetime.now().isoformat()
            }
            self.database.store_exec_result(**data)
            # audit
            self.database.add_activity_log(
                client_id=data['client_id'],
                action='exec_result',
                details=json.dumps({'command_id': data['command_id'], 'exit_code': data['exit_code']})[:1000],
                ip_address=client_conn.address[0] if client_conn and client_conn.address else None,
                severity='info' if (data['exit_code'] == 0) else 'warning'
            )
            # GUI callback
            if self.gui_callback:
                try:
                    self.gui_callback('exec_result', data['client_id'], data['exit_code'], data['stdout'])
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error handling exec result: {e}")
    
    def send_reboot_command(self, client_id: str) -> bool:
        """Send reboot command to a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            command_id = str(uuid.uuid4())
            
            reboot_command = {
                'type': 'reboot',
                'command_id': command_id,
                'timestamp': datetime.now().isoformat()
            }
            
            self._send_data(client_conn.socket, reboot_command)
            logger.info(f"Reboot command sent to client {client_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send reboot command: {e}")
            return False
    
    def send_shutdown_command(self, client_id: str) -> bool:
        """Send shutdown command to a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            command_id = str(uuid.uuid4())
            
            shutdown_command = {
                'type': 'shutdown',
                'command_id': command_id,
                'timestamp': datetime.now().isoformat()
            }
            
            self._send_data(client_conn.socket, shutdown_command)
            logger.info(f"Shutdown command sent to client {client_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send shutdown command: {e}")
            return False
    
    def send_service_control_command(self, client_id: str, action: str) -> bool:
        """Send service control command to a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            command_id = str(uuid.uuid4())
            
            service_command = {
                'type': 'service_control',
                'command_id': command_id,
                'action': action,
                'timestamp': datetime.now().isoformat()
            }
            
            self._send_data(client_conn.socket, service_command)
            logger.info(f"Service control command '{action}' sent to client {client_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send service control command: {e}")
            return False
    
    def send_config_update_command(self, client_id: str, new_config: Dict[str, Any]) -> bool:
        """Send configuration update command to a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            command_id = str(uuid.uuid4())
            
            config_command = {
                'type': 'update_config',
                'command_id': command_id,
                'config': new_config,
                'timestamp': datetime.now().isoformat()
            }
            
            self._send_data(client_conn.socket, config_command)
            logger.info(f"Configuration update command sent to client {client_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send configuration update command: {e}")
            return False
    
    def get_client_command_history(self, client_id: str) -> List[Dict[str, Any]]:
        """Get command history for a specific client."""
        try:
            if not hasattr(self, 'command_responses'):
                return []
            
            client_commands = []
            for cmd_id, response in self.command_responses.items():
                if response.get('client_id') == client_id:
                    client_commands.append({
                        'command_id': cmd_id,
                        'status': response.get('status'),
                        'message': response.get('message'),
                        'timestamp': response.get('timestamp')
                    })
            
            # Sort by timestamp (newest first)
            client_commands.sort(key=lambda x: x['timestamp'], reverse=True)
            return client_commands
            
        except Exception as e:
            logger.error(f"Error getting client command history: {e}")
            return []
    
    def broadcast_command(self, command_type: str, **kwargs) -> Dict[str, bool]:
        """Broadcast a command to all connected clients."""
        try:
            results = {}
            
            for client_id in list(self.clients.keys()):
                try:
                    if command_type == 'reboot':
                        results[client_id] = self.send_reboot_command(client_id)
                    elif command_type == 'shutdown':
                        results[client_id] = self.send_shutdown_command(client_id)
                    elif command_type == 'service_control':
                        action = kwargs.get('action', 'restart')
                        results[client_id] = self.send_service_control_command(client_id, action)
                    elif command_type == 'config_update':
                        config = kwargs.get('config', {})
                        results[client_id] = self.send_config_update_command(client_id, config)
                    else:
                        logger.error(f"Unknown broadcast command type: {command_type}")
                        results[client_id] = False
                        
                except Exception as e:
                    logger.error(f"Failed to send {command_type} command to {client_id}: {e}")
                    results[client_id] = False
            
            logger.info(f"Broadcast command '{command_type}' completed. Results: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Broadcast command failed: {e}")
            return {}
    
    def send_chat_message(self, client_id: str, message: str):
        """Send a chat message to a specific client.
        
        Returns:
            (success: bool, message_id: str)
        """
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False, ""
            
            client_conn = self.clients[client_id]
            message_id = str(uuid.uuid4())
            
            chat_command = {
                'type': 'chat_message',
                'message_id': message_id,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'sender': 'server'
            }
            
            try:
                self._send_data(client_conn.socket, chat_command)
                awaiting = False
                logger.info(f"Chat message sent to client {client_id}: {message}")
            except Exception:
                # Queue for later delivery
                awaiting = True
                logger.warning(f"Client {client_id} offline or send failed; queueing message")
            
            # Store in database with message_id and awaiting_delivery flag
            self.database.store_chat_message(
                client_id=client_id,
                message=message,
                timestamp=datetime.now().isoformat(),
                direction='server_to_client',
                message_id=message_id,
                awaiting_delivery=awaiting
            )
            
            return True, message_id
            
        except Exception as e:
            logger.error(f"Failed to send chat message: {e}")
            return False, ""

    def _deliver_queued_messages(self, client_id: str) -> None:
        """Attempt to deliver queued messages to a client that just connected."""
        try:
            queued = self.database.get_undelivered_messages(client_id)
            if not queued:
                return
            client_conn = self.clients.get(client_id)
            if not client_conn:
                return
            for msg in queued:
                payload = {
                    'type': 'chat_message',
                    'message_id': msg['message_id'],
                    'message': msg['message'],
                    'timestamp': msg['timestamp'],
                    'sender': 'server'
                }
                try:
                    self._send_data(client_conn.socket, payload)
                    # Mark delivered once popup shown - client will confirm via status, but set optimistic
                except Exception as e:
                    logger.warning(f"Failed delivering queued message {msg['message_id']} to {client_id}: {e}")
        except Exception as e:
            logger.error(f"Queued delivery failed: {e}")
    
    def request_file_list(self, client_id: str, directory_path: str) -> bool:
        """Request a file list from a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            request_id = str(uuid.uuid4())
            
            file_list_command = {
                'type': 'file_list_request',
                'request_id': request_id,
                'directory_path': directory_path,
                'timestamp': datetime.now().isoformat()
            }
            
            self._send_data(client_conn.socket, file_list_command)
            logger.info(f"File list request sent to client {client_id} for {directory_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send file list request: {e}")
            return False
    
    def request_file_content(self, client_id: str, file_path: str) -> bool:
        """Request file content from a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            request_id = str(uuid.uuid4())
            
            file_content_command = {
                'type': 'file_content_request',
                'request_id': request_id,
                'file_path': file_path,
                'timestamp': datetime.now().isoformat()
            }
            
            self._send_data(client_conn.socket, file_content_command)
            logger.info(f"File content request sent to client {client_id} for {file_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send file content request: {e}")
            return False
    
    def send_file_operation(self, client_id: str, operation: str, file_path: str, **kwargs) -> bool:
        """Send a file operation command to a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            
            client_conn = self.clients[client_id]
            command_id = str(uuid.uuid4())
            
            file_operation_command = {
                'type': 'file_operation',
                'command_id': command_id,
                'operation': operation,
                'file_path': file_path,
                'timestamp': datetime.now().isoformat()
            }
            
            # Add operation-specific parameters
            if operation == 'copy' and 'destination' in kwargs:
                file_operation_command['destination'] = kwargs['destination']
            elif operation == 'move' and 'destination' in kwargs:
                file_operation_command['destination'] = kwargs['destination']
            elif operation == 'delete' and 'force' in kwargs:
                file_operation_command['force'] = kwargs['force']
            elif operation == 'create' and 'content' in kwargs:
                file_operation_command['content'] = kwargs['content']
            
            self._send_data(client_conn.socket, file_operation_command)
            logger.info(f"File operation '{operation}' command sent to client {client_id} for {file_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send file operation command: {e}")
            return False

    def send_remote_input(self, client_id: str, action: str, **kwargs) -> bool:
        """Send a remote input command to a specific client."""
        try:
            if client_id not in self.clients:
                logger.error(f"Client {client_id} not found")
                return False
            client_conn = self.clients[client_id]
            cmd = {'type': 'remote_input', 'action': action}
            cmd.update(kwargs)
            self._send_data(client_conn.socket, cmd)
            logger.info(f"Remote input '{action}' sent to client {client_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send remote input: {e}")
            return False
    
    def _send_data(self, client_socket: socket.socket, data: Dict[str, Any]):
        """Send data to client."""
        try:
            # Convert to JSON and encode, then encrypt all transport data
            json_data = json.dumps(data, default=str).encode('utf-8')
            try:
                from security import SecurityManager
                # Lazy init transport encryptor bound to server instance
                if not hasattr(self, '_transport_security'):
                    # Reuse server config
                    self._transport_security = SecurityManager(self.config)
                sec = self._transport_security
                # Encrypt using AEAD (nonce||cipher) and send with length prefix
                nonce = os.urandom(12)
                ct = sec.db_aead.encrypt(nonce, json_data, b'TRANSv1')
                payload = b'TRV1' + nonce + ct
            except Exception:
                # Fallback to raw when security init fails (should not happen)
                payload = json_data
            length_bytes = len(payload).to_bytes(4, byteorder='big')
            client_socket.sendall(length_bytes + payload)
            
        except Exception as e:
            logger.error(f"Failed to send data to client: {e}")
    
    def _process_client_data(self):
        """Process client data for GUI updates."""
        while self.is_running:
            try:
                # Get data from queue with timeout
                data = self.client_data_queue.get(timeout=1)
                
                # Process different types of data
                if data['type'] == 'screen_capture':
                    # This will be handled by the GUI
                    pass
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing client data: {e}")
    
    def _cleanup_client(self, client_conn: ClientConnection):
        """Clean up client connection."""
        try:
            if client_conn.client_id:
                # Update database
                self.database.update_client_status(client_conn.client_id, 'disconnected')
                
                            # Remove from clients dictionary
            if client_conn.client_id in self.clients:
                # Call GUI callback if available
                if self.gui_callback:
                    try:
                        self.gui_callback('client_disconnected', client_conn.client_id)
                    except Exception as e:
                        logger.error(f"GUI callback failed: {e}")
                
                del self.clients[client_conn.client_id]
            
            # Update connection counts
            ip_address = client_conn.address[0]
            if ip_address in self.ip_connection_counts:
                self.ip_connection_counts[ip_address] -= 1
                if self.ip_connection_counts[ip_address] <= 0:
                    del self.ip_connection_counts[ip_address]
            
            # Close socket
            if client_conn.socket:
                client_conn.socket.close()
            
            logger.info(f"Client disconnected: {client_conn.address[0]}:{client_conn.address[1]}")
            
        except Exception as e:
            logger.error(f"Error cleaning up client: {e}")
    
    def stop(self):
        """Stop the monitoring server."""
        try:
            self.is_running = False
            
            # Close all client connections
            for client_conn in list(self.clients.values()):
                client_conn.is_active = False
                if client_conn.socket:
                    client_conn.socket.close()
            
            # Close server socket
            if self.server_socket:
                self.server_socket.close()
            
            # Wait for threads to finish
            if self.accept_thread:
                self.accept_thread.join(timeout=5)
            
            for thread in self.client_threads:
                thread.join(timeout=1)
            
            # Cleanup resources
            self.security_manager.cleanup()
            self.database.close()
            
            logger.info("Server stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping server: {e}")
    
    def get_server_stats(self) -> Dict[str, Any]:
        """Get server statistics."""
        try:
            stats = {
                'total_connections': self.total_connections,
                'active_clients': len(self.clients),
                'ip_connections': dict(self.ip_connection_counts),
                'total_data_received': self.total_data_received,
                'uptime_seconds': time.time() - self.start_time if self.start_time else 0
            }
            
            # Add database stats
            db_stats = self.database.get_database_stats()
            stats.update(db_stats)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting server stats: {e}")
            return {}

    def _get_version(self) -> str:
        return get_version()

class ClientThumbnailWidget(QWidget):
    """Widget for displaying client screen capture thumbnails."""
    
    # Signals for remote control
    full_screen_requested = Signal(str)  # client_id
    reboot_requested = Signal(str)  # client_id
    shutdown_requested = Signal(str)  # client_id
    service_control_requested = Signal(str, str)  # client_id, action
    message_requested = Signal(str)  # client_id
    file_browser_requested = Signal(str)  # client_id
    
    def __init__(self, client_id: str, hostname: str, platform: str):
        super().__init__()
        self.client_id = client_id
        self.hostname = hostname
        self.platform = platform
        self.current_image = None
        self.last_update = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Client info label
        info_text = f"{self.hostname}\n{self.platform}"
        self.info_label = QLabel(info_text)
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.info_label.setStyleSheet("""
            QLabel {
                background-color: #2c3e50;
                color: white;
                padding: 5px;
                border-radius: 5px;
                font-weight: bold;
            }
        """)
        
        # Image display label
        self.image_label = QLabel()
        self.image_label.setMinimumSize(200, 150)
        self.image_label.setMaximumSize(200, 150)
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet("""
            QLabel {
                background-color: #34495e;
                border: 2px solid #2c3e50;
                border-radius: 5px;
            }
        """)
        self.image_label.setText("No Image")
        
        # Full Screen button
        self.full_screen_button = QPushButton("Full Screen")
        self.full_screen_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f4e79;
            }
        """)
        self.full_screen_button.clicked.connect(self._request_full_screen)
        
        # Remote Control buttons
        control_layout = QHBoxLayout()
        
        # Reboot button
        self.reboot_button = QPushButton("🔄")
        self.reboot_button.setToolTip("Reboot Client")
        self.reboot_button.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
            QPushButton:pressed {
                background-color: #d35400;
            }
        """)
        self.reboot_button.clicked.connect(self._request_reboot)
        
        # Shutdown button
        self.shutdown_button = QPushButton("⏹")
        self.shutdown_button.setToolTip("Shutdown Client")
        self.shutdown_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 3px;
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
        self.shutdown_button.clicked.connect(self._request_shutdown)
        
        # Service control button
        self.service_button = QPushButton("⚙")
        self.service_button.setToolTip("Service Control")
        self.service_button.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
            QPushButton:pressed {
                background-color: #7d3c98;
            }
        """)
        self.service_button.clicked.connect(self._request_service_control)
        
        # Message button
        self.message_button = QPushButton("💬")
        self.message_button.setToolTip("Send Message")
        self.message_button.setStyleSheet("""
            QPushButton {
                background-color: #00BFFF;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #0099CC;
            }
            QPushButton:pressed {
                background-color: #007399;
            }
        """)
        self.message_button.clicked.connect(self._request_message)
        
        # File Browser button
        self.file_browser_button = QPushButton("📁")
        self.file_browser_button.setToolTip("File Browser")
        self.file_browser_button.setStyleSheet("""
            QPushButton {
                background-color: #17a2b8;
                color: white;
                border: none;
                padding: 6px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #138496;
            }
            QPushButton:pressed {
                background-color: #0f6674;
            }
        """)
        self.file_browser_button.clicked.connect(self._request_file_browser)
        
        control_layout.addWidget(self.reboot_button)
        control_layout.addWidget(self.shutdown_button)
        control_layout.addWidget(self.service_button)
        control_layout.addWidget(self.message_button)
        control_layout.addWidget(self.file_browser_button)
        
        # Status indicator
        self.status_label = QLabel("Offline")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                color: #e74c3c;
                font-weight: bold;
            }
        """)
        
        layout.addWidget(self.info_label)
        layout.addWidget(self.image_label)
        layout.addWidget(self.full_screen_button)
        layout.addLayout(control_layout)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        self.setFixedSize(220, 320)  # Increased height for control buttons
    
    def _request_full_screen(self):
        """Request full-screen view for this client."""
        self.full_screen_requested.emit(self.client_id)
    
    def _request_reboot(self):
        """Request reboot for this client."""
        self.reboot_requested.emit(self.client_id)
    
    def _request_shutdown(self):
        """Request shutdown for this client."""
        self.shutdown_requested.emit(self.client_id)
    
    def _request_service_control(self):
        """Request service control for this client."""
        self.service_control_requested.emit(self.client_id, "restart")
    
    def _request_message(self):
        """Request to send a message to this client."""
        self.message_requested.emit(self.client_id)
    
    def _request_file_browser(self):
        """Request to open file browser for this client."""
        self.file_browser_requested.emit(self.client_id)
    
    def update_image(self, image_data: bytes, metadata: Dict[str, Any]):
        """Update the displayed image."""
        try:
            logger.info(f"Thumbnail widget updating image: {len(image_data)} bytes")
            
            # Check if the widget and its labels still exist
            if not hasattr(self, 'image_label') or not self.image_label or not hasattr(self, 'status_label') or not self.status_label:
                logger.warning(f"Widget labels not available for {self.client_id}, skipping update")
                return
            
            # Convert bytes to QPixmap
            image = QImage()
            success = image.loadFromData(image_data)
            
            if success and not image.isNull():
                logger.info(f"Image loaded successfully: {image.width()}x{image.height()}")
                
                # Scale to fit thumbnail
                scaled_image = image.scaled(
                    200, 150,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                
                self.current_image = QPixmap.fromImage(scaled_image)
                
                # Force the image label to update
                try:
                    self.image_label.clear()
                    self.image_label.setPixmap(self.current_image)
                    self.image_label.repaint()
                    
                    self.status_label.setText("Online")
                    self.status_label.setStyleSheet("""
                        QLabel {
                            color: #27ae60;
                            font-weight: bold;
                        }
                    """)
                    
                    self.last_update = datetime.now()
                    logger.info(f"Thumbnail updated successfully for {self.client_id} - Image size: {self.current_image.width()}x{self.current_image.height()}")
                    
                except RuntimeError as re:
                    if "already deleted" in str(re):
                        logger.warning(f"Widget was deleted during update for {self.client_id}, skipping")
                        return
                    else:
                        raise
                
            else:
                logger.error(f"Failed to load image data for {self.client_id} - Success: {success}, Null: {image.isNull()}")
                
        except Exception as e:
            logger.error(f"Error updating thumbnail: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")

class FullScreenViewWidget(QWidget):
    """Widget for displaying a client's screen capture in full-screen mode."""
    
    # Signal to return to grid view
    return_to_grid_requested = Signal()
    
    def __init__(self, client_id: str, hostname: str, platform: str, parent=None):
        super().__init__(parent)
        self.client_id = client_id
        self.hostname = hostname
        self.platform = platform
        self.current_image = None
        self.last_update = None
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Header with client info and back button
        header_layout = QHBoxLayout()
        
        # Client info
        info_text = f"{self.hostname} ({self.platform}) - Client ID: {self.client_id}"
        self.info_label = QLabel(info_text)
        self.info_label.setStyleSheet("""
            QLabel {
                background-color: #2c3e50;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        
        # Back to List button
        self.back_button = QPushButton("← Back to List")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:pressed {
                background-color: #a93226;
            }
        """)
        self.back_button.clicked.connect(self._request_return_to_grid)
        
        header_layout.addWidget(self.info_label)
        header_layout.addStretch()
        header_layout.addWidget(self.back_button)
        
        # Full-screen image display
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet("""
            QLabel {
                background-color: #2c3e50;
                border: 3px solid #34495e;
                border-radius: 10px;
            }
        """)
        self.image_label.setText("No Image Available")
        
        # Status indicator
        self.status_label = QLabel("Offline")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                color: #e74c3c;
                font-weight: bold;
                font-size: 16px;
                padding: 10px;
            }
        """)
        
        layout.addLayout(header_layout)
        layout.addWidget(self.image_label, 1)  # Take up remaining space
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        # Separate top-level window that stays on top of the main window
        try:
            self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowStaysOnTopHint)
            self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        except Exception:
            pass
        # Capture input events for remote control
        self.setMouseTracking(True)
        self.image_label.setMouseTracking(True)
        self.image_label.installEventFilter(self)
        self.installEventFilter(self)
    
    def _request_return_to_grid(self):
        """Request to return to the grid view."""
        self.return_to_grid_requested.emit()
    
    def update_image(self, image_data: bytes, metadata: Dict[str, Any]):
        """Update the displayed image in full-screen mode."""
        try:
            logger.info(f"Full-screen widget updating image: {len(image_data)} bytes")
            
            # Check if the widget and its labels still exist
            if not hasattr(self, 'image_label') or not self.image_label or not hasattr(self, 'status_label') or not self.status_label:
                logger.warning(f"Full-screen widget labels not available for {self.client_id}, skipping update")
                return
            
            # Convert bytes to QPixmap
            image = QImage()
            success = image.loadFromData(image_data)
            
            if success and not image.isNull():
                logger.info(f"Full-screen image loaded successfully: {image.width()}x{image.height()}")
                
                # Get the widget size for scaling
                widget_size = self.image_label.size()
                if widget_size.width() > 0 and widget_size.height() > 0:
                    # Scale to fit the widget while maintaining aspect ratio
                    scaled_image = image.scaled(
                        widget_size.width(), widget_size.height(),
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation
                    )
                    
                    self.current_image = QPixmap.fromImage(scaled_image)
                    
                    try:
                        self.image_label.setPixmap(self.current_image)
                        self.status_label.setText("Online")
                        self.status_label.setStyleSheet("""
                            QLabel {
                                color: #27ae60;
                                font-weight: bold;
                                font-size: 16px;
                                padding: 10px;
                            }
                        """)
                        
                        self.last_update = datetime.now()
                        logger.info(f"Full-screen image updated successfully for {self.client_id}")
                        
                    except RuntimeError as re:
                        if "already deleted" in str(re):
                            logger.warning(f"Full-screen widget was deleted during update for {self.client_id}, skipping")
                            return
                        else:
                            raise
                    
                else:
                    logger.warning(f"Widget size not available for {self.client_id}")
                    
            else:
                logger.error(f"Failed to load full-screen image data for {self.client_id}")
                
        except Exception as e:
            logger.error(f"Error updating full-screen image: {e}")

    def eventFilter(self, obj, event):
        try:
            if obj is self.image_label or obj is self:
                et = event.type()
                # Mouse move
                if et == QEvent.Type.MouseMove:
                    pos = event.position() if hasattr(event, 'position') else event.pos()
                    x = int(pos.x())
                    y = int(pos.y())
                    # Map to client screen coordinates best-effort (assume 1:1 for now)
                    if hasattr(self.parent(), 'server'):
                        self.parent().server.send_remote_input(self.client_id, 'mouse_move', x=x, y=y, duration=0)
                    return True
                # Mouse press/release
                if et in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease):
                    btn = event.button()
                    if btn == Qt.MouseButton.LeftButton:
                        button = 'left'
                    elif btn == Qt.MouseButton.RightButton:
                        button = 'right'
                    elif btn == Qt.MouseButton.MiddleButton:
                        button = 'middle'
                    else:
                        button = 'middle'
                    clicks = 1
                    if hasattr(self.parent(), 'server') and et == QEvent.Type.MouseButtonPress:
                        self.parent().server.send_remote_input(self.client_id, 'mouse_click', button=button, clicks=clicks, interval=0)
                    return True
                # Wheel
                if et == QEvent.Type.Wheel:
                    delta = event.angleDelta().y() if hasattr(event, 'angleDelta') else 0
                    amount = int(delta / 120)
                    if hasattr(self.parent(), 'server'):
                        self.parent().server.send_remote_input(self.client_id, 'mouse_scroll', amount=amount, axis='vertical')
                    return True
                # Key events
                if et in (QEvent.Type.KeyPress, QEvent.Type.KeyRelease):
                    from PySide6.QtGui import QKeySequence
                    key = event.key()
                    text = event.text() if hasattr(event, 'text') else ''
                    ev = 'down' if et == QEvent.Type.KeyPress else 'up'
                    if text and text.isprintable() and ev == 'down':
                        if hasattr(self.parent(), 'server'):
                            self.parent().server.send_remote_input(self.client_id, 'key_type', text=text)
                    else:
                        # Map Qt key to a generic string (best-effort)
                        key_name = QKeySequence(key).toString() or str(key)
                        if hasattr(self.parent(), 'server'):
                            self.parent().server.send_remote_input(self.client_id, 'key_event', key=key_name.lower(), event=ev)
                    return True
        except Exception as e:
            logger.error(f"Event filter error: {e}")
            try:
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
            except Exception:
                pass
        return super().eventFilter(obj, event)
    
    def resizeEvent(self, event):
        """Handle resize events to update image scaling."""
        super().resizeEvent(event)
        # If we have a current image, update it to fit the new size
        if self.current_image:
            self.update_image_from_current()
    
    def update_image_from_current(self):
        """Update the image display using the current stored image data."""
        if hasattr(self, '_last_image_data') and self._last_image_data:
            self.update_image(self._last_image_data, {})
    
    def store_image_data(self, image_data: bytes):
        """Store the raw image data for resize operations."""
        self._last_image_data = image_data


class MessagingPopupWidget(QWidget):
    """Popup widget for sending messages to clients (now mirrors client IM)."""
    
    message_sent = Signal(str, str)  # client_id, message
    
    def __init__(self, client_id: str, hostname: str, parent=None):
        super().__init__(parent)
        self.client_id = client_id
        self.hostname = hostname
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle(f"Message to {self.hostname}")
        # Persistent, floating tool window that stays above but doesn't auto-close
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)
        # Make the popup taller similar to client popup
        self.setFixedSize(360, 520)
        
        # Set position at bottom of screen
        screen = QApplication.primaryScreen()
        geometry = screen.availableGeometry() if screen else self.geometry()
        self.move(geometry.right() - self.width() - 24, geometry.bottom() - self.height() - 140)
        
        # Apply style to match client popup
        self.setStyleSheet(
            """
            QFrame { background-color: #FFFFFF; border: 2px solid #00BFFF; border-radius: 15px; }
            QLabel { color: #2C3E50; font-weight: bold; }
            QTextEdit { color: #2C3E50; font-size: 11px; padding: 10px; background-color: #F8F9FA; border-radius: 8px; border: 1px solid #DEE2E6; }
            QPushButton { background-color: #00BFFF; color: #FFFFFF; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 12px; }
            QPushButton:hover { background-color: #0099CC; }
            QPushButton:pressed { background-color: #007399; }
            """
        )
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header bar with title and window controls (like client)
        header_bar = QFrame()
        header_bar.setStyleSheet("QFrame { background-color: #00BFFF; border-radius: 8px; }")
        header_h = QHBoxLayout(header_bar)
        header_h.setContentsMargins(10, 6, 6, 6)
        header_h.setSpacing(6)
        header_title = QLabel(f"💬 Message to {self.hostname}")
        header_title.setStyleSheet("QLabel { color: #FFFFFF; font-weight: bold; font-size: 14px; }")
        header_h.addWidget(header_title)
        header_h.addStretch(1)
        self.minimize_button = QPushButton("_")
        self.minimize_button.setFixedSize(22, 22)
        self.minimize_button.setStyleSheet("QPushButton { background-color: #f39c12; color: #fff; border: none; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #e67e22; }")
        self.minimize_button.clicked.connect(lambda: self._toggle_minimize(content_container))
        header_h.addWidget(self.minimize_button)
        self.close_button = QPushButton("×")
        self.close_button.setFixedSize(22, 22)
        self.close_button.setStyleSheet("QPushButton { background-color: #e74c3c; color: #fff; border: none; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #c0392b; }")
        self.close_button.clicked.connect(self.close)
        header_h.addWidget(self.close_button)
        
        # Message input area + conversation
        self.history = QTextEdit()
        self.history.setReadOnly(True)
        self.history.setMaximumHeight(280)
        self.history.setStyleSheet("QTextEdit { border: 1px solid #DEE2E6; border-radius: 5px; background: #F8F9FA; }")
        message_label = QLabel("Message:")
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(80)
        self.message_input.setPlaceholderText("Type your message here...")
        
        # Send button
        self.send_button = QPushButton("Send Message")
        self.send_button.clicked.connect(self._send_message)
        
        # Close button
        self.close_button = QPushButton("Close")
        self.close_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: #FFFFFF;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        self.close_button.clicked.connect(self.close)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.send_button)
        
        # Content container (to minimize like client)
        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(12, 12, 12, 12)
        content_layout.addWidget(self.history)
        content_layout.addWidget(message_label)
        content_layout.addWidget(self.message_input)
        content_layout.addLayout(button_layout)
        # Status checks label (match client)
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.status_label.setStyleSheet("QLabel { color: rgba(255,0,0,0.7); font-size: 11px; }")
        content_layout.addWidget(self.status_label)
        
        layout.addWidget(header_bar)
        layout.addWidget(content_container)
        
        self.setLayout(layout)

        # Make popup draggable (frameless window needs custom drag)
        self._dragging = False
        self._drag_position = None
        
    def _send_message(self):
        """Send the message to the client."""
        message = self.message_input.toPlainText().strip()
        if message:
            self.message_sent.emit(self.client_id, message)
            # Append to local history and keep window open
            timestamp = datetime.now().strftime("%H:%M")
            current = self.history.toPlainText()
            new_text = (current + ("\n\n" if current else "")) + f"[{timestamp}] You: {message}"
            self.history.setPlainText(new_text)
            self.history.verticalScrollBar().setValue(self.history.verticalScrollBar().maximum())
            self.message_input.clear()

    def _toggle_minimize(self, content_widget: QWidget):
        if content_widget.isVisible():
            content_widget.hide()
            self.minimize_button.setText("□")
        else:
            content_widget.show()
            self.minimize_button.setText("_")

    # Dragging handlers for frameless window
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            try:
                self._drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            except Exception:
                self._drag_position = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.MouseButton.LeftButton and self._dragging and self._drag_position is not None:
            try:
                self.move(event.globalPosition().toPoint() - self._drag_position)
            except Exception:
                self.move(event.globalPos() - self._drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._dragging = False
            event.accept()


class FileBrowserWidget(QWidget):
    """Widget for browsing client file systems."""
    
    file_operation_requested = Signal(str, str, str, dict)  # client_id, operation, file_path, params
    
    def __init__(self, client_id: str, hostname: str, parent=None):
        super().__init__(parent)
        self.client_id = client_id
        self.hostname = hostname
        self.current_path = "/"
        self.file_list = []
        self.directory_list = []
        self._init_ui()
        
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Header
        header_label = QLabel(f"📁 File Browser - {self.hostname}")
        header_label.setStyleSheet("""
            QLabel {
                background-color: #00BFFF;
                color: #FFFFFF;
                padding: 15px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 16px;
            }
        """)
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Path display and navigation
        path_layout = QHBoxLayout()
        
        # Back button
        self.back_button = QPushButton("⬅")
        self.back_button.setToolTip("Go back to parent directory")
        self.back_button.clicked.connect(self._go_back)
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #17a2b8;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 5px;
                font-size: 16px;
                min-width: 40px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #138496;
            }
            QPushButton:pressed {
                background-color: #0f6674;
            }
        """)
        
        self.path_label = QLabel("Path: /")
        self.path_label.setStyleSheet("""
            QLabel {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                padding: 8px 12px;
                border-radius: 5px;
                color: #212529;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
            }
        """)
        
        self.refresh_button = QPushButton("🔄")
        self.refresh_button.setToolTip("Refresh")
        self.refresh_button.clicked.connect(self._refresh_current_directory)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 5px;
                font-size: 16px;
                min-width: 40px;
                min-height: 40px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:pressed {
                background-color: #495057;
            }
        """)
        
        path_layout.addWidget(self.back_button)
        path_layout.addWidget(self.path_label)
        path_layout.addWidget(self.refresh_button)
        
        # Initially disable back button since we start at root
        self.back_button.setEnabled(False)
        
        # File list
        self.file_list_widget = QTableWidget()
        self.file_list_widget.setColumnCount(4)
        self.file_list_widget.setHorizontalHeaderLabels(["Name", "Type", "Size", "Modified"])
        self.file_list_widget.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_list_widget.itemDoubleClicked.connect(self._on_item_double_clicked)
        
        # Set column widths
        self.file_list_widget.setColumnWidth(0, 300)  # Name
        self.file_list_widget.setColumnWidth(1, 100)  # Type
        self.file_list_widget.setColumnWidth(2, 100)  # Size
        self.file_list_widget.setColumnWidth(3, 200)  # Modified
        
        # Style the table
        self.file_list_widget.setStyleSheet("""
            QTableWidget {
                border: 2px solid #dee2e6;
                border-radius: 5px;
                background-color: #ffffff;
                gridline-color: #dee2e6;
                color: #212529;
                alternate-background-color: #f8f9fa;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f8f9fa;
                color: #212529;
            }
            QTableWidget::item:selected {
                background-color: #00BFFF;
                color: white;
            }
            QTableWidget::item:hover {
                background-color: #e9ecef;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #dee2e6;
                font-weight: bold;
                color: #495057;
            }
        """)
        
        # Enable alternating row colors for better readability
        self.file_list_widget.setAlternatingRowColors(True)
        
        # File operations
        operation_layout = QHBoxLayout()
        
        self.view_button = QPushButton("View")
        self.view_button.clicked.connect(self._view_file)
        self.view_button.setStyleSheet("""
            QPushButton {
                background-color: #00BFFF;
                color: #FFFFFF;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0099CC;
            }
        """)
        
        self.download_button = QPushButton("Download")
        self.download_button.clicked.connect(self._download_file)
        self.download_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: #FFFFFF;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self._delete_file)
        self.delete_button.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: #FFFFFF;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        
        operation_layout.addWidget(self.view_button)
        operation_layout.addWidget(self.download_button)
        operation_layout.addWidget(self.delete_button)
        
        # Add close button
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        self.close_button.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        operation_layout.addWidget(self.close_button)
        
        layout.addWidget(header_label)
        layout.addLayout(path_layout)
        layout.addWidget(self.file_list_widget)
        layout.addLayout(operation_layout)
        
        self.setLayout(layout)
        
    def update_file_list(self, directory_path: str, files: list, directories: list):
        """Update the file list display."""
        try:
            logger.info(f"FileBrowserWidget.update_file_list called: {directory_path}")
            logger.info(f"Files: {len(files)}, Directories: {len(directories)}")
            
            self.current_path = directory_path
            self.file_list = files
            self.directory_list = directories
            
            self.path_label.setText(f"Path: {directory_path}")
            
            # Enable/disable back button based on current path
            can_go_back = directory_path != "/" and directory_path != "\\" and directory_path != ""
            self.back_button.setEnabled(can_go_back)
            
            # Clear and populate table
            self.file_list_widget.setRowCount(0)
            
            # Add directories first
            for directory in directories:
                row = self.file_list_widget.rowCount()
                self.file_list_widget.insertRow(row)
                
                # Create items with proper styling
                dir_item = QTableWidgetItem(f"📁 {directory}")
                dir_item.setForeground(QColor("#2E86AB"))  # Blue color for directories
                self.file_list_widget.setItem(row, 0, dir_item)
                
                type_item = QTableWidgetItem("Directory")
                type_item.setForeground(QColor("#495057"))
                self.file_list_widget.setItem(row, 1, type_item)
                
                size_item = QTableWidgetItem("")
                size_item.setForeground(QColor("#6C757D"))
                self.file_list_widget.setItem(row, 2, size_item)
                
                mod_item = QTableWidgetItem("")
                mod_item.setForeground(QColor("#6C757D"))
                self.file_list_widget.setItem(row, 3, mod_item)
            
            # Add files
            for file_info in files:
                row = self.file_list_widget.rowCount()
                self.file_list_widget.insertRow(row)
                
                # Create items with proper styling
                file_item = QTableWidgetItem(f"📄 {file_info.get('name', 'Unknown')}")
                file_item.setForeground(QColor("#212529"))  # Dark color for files
                self.file_list_widget.setItem(row, 0, file_item)
                
                type_item = QTableWidgetItem(file_info.get('type', 'Unknown'))
                type_item.setForeground(QColor("#495057"))
                self.file_list_widget.setItem(row, 1, type_item)
                
                size_item = QTableWidgetItem(str(file_info.get('size', 0)))
                size_item.setForeground(QColor("#6C757D"))
                self.file_list_widget.setItem(row, 2, size_item)
                
                mod_item = QTableWidgetItem(str(file_info.get('modified', '')))
                mod_item.setForeground(QColor("#6C757D"))
                self.file_list_widget.setItem(row, 3, mod_item)
            
            logger.info(f"File list updated successfully: {self.file_list_widget.rowCount()} total items")
            
        except Exception as e:
            logger.error(f"Error in update_file_list: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _refresh_current_directory(self):
        """Refresh the current directory listing."""
        self.file_operation_requested.emit(self.client_id, "list_directory", self.current_path, {})
    
    def _go_back(self):
        """Navigate to the parent directory."""
        try:
            if self.current_path == "/" or self.current_path == "\\":
                # Already at root, can't go back
                return
            
            # Get parent directory
            parent_path = os.path.dirname(self.current_path)
            if not parent_path:
                parent_path = "/" if "/" in self.current_path else "\\"
            
            logger.info(f"Going back from {self.current_path} to {parent_path}")
            
            # Request the parent directory listing
            self.file_operation_requested.emit(self.client_id, "list_directory", parent_path, {})
            
        except Exception as e:
            logger.error(f"Error going back to parent directory: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _on_item_double_clicked(self, item):
        """Handle double-click on file/directory item."""
        row = item.row()
        name_item = self.file_list_widget.item(row, 0)
        if name_item:
            name = name_item.text().replace("📁 ", "").replace("📄 ", "")
            if row < len(self.directory_list):
                # Directory - navigate into it
                new_path = os.path.join(self.current_path, name).replace("\\", "/")
                self.file_operation_requested.emit(self.client_id, "list_directory", new_path, {})
            else:
                # File - view it
                file_path = os.path.join(self.current_path, name).replace("\\", "/")
                self.file_operation_requested.emit(self.client_id, "view_file", file_path, {})
    
    def _view_file(self):
        """View the selected file."""
        current_row = self.file_list_widget.currentRow()
        if current_row >= 0:
            name_item = self.file_list_widget.item(current_row, 0)
            if name_item:
                name = name_item.text().replace("📁 ", "").replace("📄 ", "")
                if current_row >= len(self.directory_list):
                    # Only view files, not directories
                    file_path = os.path.join(self.current_path, name).replace("\\", "/")
                    self.file_operation_requested.emit(self.client_id, "view_file", file_path, {})
    
    def _download_file(self):
        """Download the selected file."""
        current_row = self.file_list_widget.currentRow()
        if current_row >= 0:
            name_item = self.file_list_widget.item(current_row, 0)
            if name_item:
                name = name_item.text().replace("📁 ", "").replace("📄 ", "")
                if current_row >= len(self.directory_list):
                    # Only download files, not directories
                    file_path = os.path.join(self.current_path, name).replace("\\", "/")
                    self.file_operation_requested.emit(self.client_id, "download_file", file_path, {})
    
    def _delete_file(self):
        """Delete the selected file."""
        current_row = self.file_list_widget.currentRow()
        if current_row >= 0:
            name_item = self.file_list_widget.item(current_row, 0)
            if name_item:
                name = name_item.text().replace("📁 ", "").replace("📄 ", "")
                if current_row >= len(self.directory_list):
                    # Only delete files, not directories
                    file_path = os.path.join(self.current_path, name).replace("\\", "/")
                    self.file_operation_requested.emit(self.client_id, "delete_file", file_path, {"force": True})


class MonitoringServerGUI(QMainWindow):
    """Main GUI window for the monitoring server."""
    
    # Define signals for thread-safe GUI updates
    client_registered_signal = Signal(str, str, str)  # client_id, hostname, platform
    screen_capture_signal = Signal(str, bytes, dict)  # client_id, image_data, metadata
    client_disconnected_signal = Signal(str)  # client_id
    chat_message_signal = Signal(str, str, str)  # client_id, message, timestamp
    chat_response_signal = Signal(str, str, str)  # client_id, message, timestamp
    file_list_response_signal = Signal(str, str, list, list)  # client_id, directory_path, files, directories
    file_content_response_signal = Signal(str, str, str, int, bool)  # client_id, file_path, content, file_size, is_binary
    file_operation_response_signal = Signal(str, str, str, str, str)  # client_id, operation, file_path, status, message
    
    def __init__(self, server: MonitoringServer):
        super().__init__()
        self.server = server
        self.client_widgets: Dict[str, ClientThumbnailWidget] = {}
        self.client_info: Dict[str, Dict[str, str]] = {}  # Store client info separately
        self.full_screen_widget = None
        self.current_full_screen_client = None
        
        # Store file browsers per client
        self.file_browsers = {}
        
        # Set the GUI callback in the server
        self.server.set_gui_callback(self._handle_server_update)
        
        # Connect signals to slots
        self.client_registered_signal.connect(self._add_client_widget_safe)
        self.screen_capture_signal.connect(self._update_client_image_safe)
        self.client_disconnected_signal.connect(self._remove_client_widget_safe)
        self.chat_message_signal.connect(self._handle_chat_message_safe)
        self.chat_response_signal.connect(self._handle_chat_response_safe)
        self.file_list_response_signal.connect(self._handle_file_list_response_safe)
        self.file_content_response_signal.connect(self._handle_file_content_response_safe)
        self.file_operation_response_signal.connect(self._handle_file_operation_response_safe)
        
        # Verify environment/dependencies early; log warnings only.
        self._verify_environment()
        self._init_ui()
        self._setup_timers()
        
        logger.info("GUI initialized successfully")

    def _verify_environment(self) -> None:
        """Verify critical environment aspects and optional dependencies; log warnings only.

        - Warn if running headless (no DISPLAY) on Linux; UI may not show.
        - Warn if PySide6 platform plugin is overridden.
        - Warn if database path is not writable.
        """
        try:
            import platform as _plat
            system = _plat.system().lower() if isinstance(_plat.system(), str) else 'unknown'
            if system == 'linux':
                if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
                    logger.warning("Headless environment detected (no DISPLAY/WAYLAND_DISPLAY). UI will require offscreen.")
            if os.environ.get('QT_QPA_PLATFORM'):
                logger.warning(f"QT_QPA_PLATFORM={os.environ.get('QT_QPA_PLATFORM')} — ensure platform plugin is available.")
            # Check DB path writability
            try:
                db_path = self.server.database.db_path if hasattr(self.server, 'database') else 'monitoring.db'
                db_dir = os.path.dirname(db_path) or '.'
                test_path = os.path.join(db_dir, '.writetest.tmp')
                with open(test_path, 'w') as f:
                    f.write('ok')
                os.remove(test_path)
            except Exception:
                logger.warning(f"Database directory not writable: {db_dir}")
        except Exception as e:
            logger.debug(f"Environment verification encountered an error: {e}")
    
    def _init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Employee Monitoring System - Server")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set application icon (if available)
        try:
            self.setWindowIcon(QIcon("icon.png"))
        except:
            pass
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create toolbar
        self._create_toolbar()
        
        # Create main content area with tabs
        self.tab_widget = QTabWidget()
        
        # Tab 1: Monitoring Dashboard
        monitoring_tab = QWidget()
        monitoring_layout = QVBoxLayout(monitoring_tab)
        
        # Create content splitter for monitoring
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Client grid
        self._create_client_panel(content_splitter)
        
        # Right panel - Information and controls
        self._create_info_panel(content_splitter)
        
        content_splitter.setSizes([1000, 400])
        monitoring_layout.addWidget(content_splitter)
        
        # Tab 2: Database Viewer
        database_tab = QWidget()
        self._create_database_tab(database_tab)
        
        # Add tabs to tab widget
        self.tab_widget.addTab(monitoring_tab, "🖥️ Monitoring Dashboard")
        self.tab_widget.addTab(database_tab, "🗄️ Database Viewer")
        
        main_layout.addWidget(self.tab_widget)
        
        # Connect tab change handler to refresh client list when switching between tabs
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Server ready")
    
    def _create_menu_bar(self):
        """Create the application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = file_menu.addAction('Export Data')
        export_action.triggered.connect(self._export_data)
        
        settings_action = file_menu.addAction('Settings')
        settings_action.triggered.connect(self._show_settings)
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction('Exit')
        exit_action.triggered.connect(self.close)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        refresh_action = view_menu.addAction('Refresh')
        refresh_action.triggered.connect(self._refresh_view)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = help_menu.addAction('About')
        about_action.triggered.connect(self._show_about)
    
    def _create_toolbar(self):
        """Create the application toolbar."""
        toolbar = self.addToolBar('Main Toolbar')
        
        # Start/Stop server button
        self.start_stop_button = QPushButton('Start Server')
        self.start_stop_button.setCheckable(True)
        self.start_stop_button.clicked.connect(self._toggle_server)
        toolbar.addWidget(self.start_stop_button)
        
        toolbar.addSeparator()
        
        # Refresh button
        refresh_button = QPushButton('Refresh')
        refresh_button.clicked.connect(self._refresh_view)
        toolbar.addWidget(refresh_button)
        
        toolbar.addSeparator()
        
        # Status indicator
        self.status_indicator = QLabel('●')
        self.status_indicator.setStyleSheet("""
            QLabel {
                color: #e74c3c;
                font-size: 20px;
                font-weight: bold;
            }
        """)
        toolbar.addWidget(self.status_indicator)
        
        status_label = QLabel('Server Status')
        toolbar.addWidget(status_label)
        
        toolbar.addSeparator()
        
        # Broadcast control buttons
        broadcast_label = QLabel('Broadcast:')
        toolbar.addWidget(broadcast_label)
        
        # Broadcast reboot button
        self.broadcast_reboot_button = QPushButton('🔄 All')
        self.broadcast_reboot_button.setToolTip('Reboot All Clients')
        self.broadcast_reboot_button.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e67e22;
            }
        """)
        self.broadcast_reboot_button.clicked.connect(self._broadcast_reboot_all)
        toolbar.addWidget(self.broadcast_reboot_button)
        
        # Broadcast service restart button
        self.broadcast_service_button = QPushButton('⚙ All')
        self.broadcast_service_button.setToolTip('Restart All Services')
        self.broadcast_service_button.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
        """)
        self.broadcast_service_button.clicked.connect(self._broadcast_service_restart_all)
        toolbar.addWidget(self.broadcast_service_button)
    
    def _create_client_panel(self, parent):
        """Create the client monitoring panel."""
        client_group = QGroupBox("Client Monitors")
        client_layout = QVBoxLayout(client_group)
        
        # Create scroll area for client grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Create client grid widget
        self.client_grid_widget = QWidget()
        self.client_grid_layout = QGridLayout(self.client_grid_widget)
        self.client_grid_layout.setSpacing(10)
        
        scroll_area.setWidget(self.client_grid_widget)
        client_layout.addWidget(scroll_area)
        
        parent.addWidget(client_group)
    
    def _create_info_panel(self, parent):
        """Create the information and control panel."""
        info_group = QGroupBox("Server Information")
        info_layout = QVBoxLayout(info_group)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Overview tab
        overview_tab = QWidget()
        overview_layout = QVBoxLayout(overview_tab)
        
        # Server stats
        stats_group = QGroupBox("Server Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_labels = {}
        stats_fields = [
            'active_clients', 'total_connections', 'uptime_seconds',
            'total_data_received', 'database_size_mb'
        ]
        
        for field in stats_fields:
            label = QLabel(f"{field.replace('_', ' ').title()}: 0")
            self.stats_labels[field] = label
            stats_layout.addWidget(label)
        
        stats_group.setLayout(stats_layout)
        overview_layout.addWidget(stats_group)
        
        # Client list
        clients_group = QGroupBox("Connected Clients")
        clients_layout = QVBoxLayout(clients_group)
        
        self.client_table = QTableWidget()
        self.client_table.setColumnCount(4)
        self.client_table.setHorizontalHeaderLabels(['Client ID', 'Hostname', 'Platform', 'Status'])
        self.client_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        
        clients_layout.addWidget(self.client_table)
        clients_group.setLayout(clients_layout)
        overview_layout.addWidget(clients_group)
        
        overview_tab.setLayout(overview_layout)
        tab_widget.addTab(overview_tab, "Overview")
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Capture interval slider
        interval_group = QGroupBox("Capture Settings")
        interval_layout = QVBoxLayout(interval_group)
        
        interval_label = QLabel("Screen Capture Interval (seconds):")
        self.interval_slider = QSlider(Qt.Orientation.Horizontal)
        self.interval_slider.setRange(1, 60)
        self.interval_slider.setValue(5)
        self.interval_slider.valueChanged.connect(self._update_capture_interval)
        
        self.interval_value_label = QLabel("5 seconds")
        
        interval_layout.addWidget(interval_label)
        interval_layout.addWidget(self.interval_slider)
        interval_layout.addWidget(self.interval_value_label)
        
        interval_group.setLayout(interval_layout)
        settings_layout.addWidget(interval_group)
        
        settings_tab.setLayout(settings_layout)
        tab_widget.addTab(settings_tab, "Settings")
        
        info_layout.addWidget(tab_widget)
        info_group.setLayout(info_layout)
        
        parent.addWidget(info_group)
    
    def _create_database_tab(self, parent):
        """Create the database viewer and management tab."""
        layout = QVBoxLayout(parent)
        
        # Database control panel
        control_group = QGroupBox("Database Controls")
        control_layout = QHBoxLayout(control_group)
        
        # Refresh button
        self.refresh_db_button = QPushButton("🔄 Refresh")
        self.refresh_db_button.clicked.connect(self._refresh_database_view)
        control_layout.addWidget(self.refresh_db_button)
        
        # Add new entry button
        self.add_entry_button = QPushButton("➕ Add Entry")
        self.add_entry_button.clicked.connect(self._add_database_entry)
        control_layout.addWidget(self.add_entry_button)
        
        # Delete selected button
        self.delete_entry_button = QPushButton("🗑️ Delete Selected")
        self.delete_entry_button.clicked.connect(self._delete_database_entry)
        control_layout.addWidget(self.delete_entry_button)
        
        # Export database button
        self.export_db_button = QPushButton("📤 Export Database")
        self.export_db_button.clicked.connect(self._export_database)
        control_layout.addWidget(self.export_db_button)
        
        control_layout.addStretch()
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Database tables tab widget
        self.db_tab_widget = QTabWidget()
        
        # Clients table
        self._create_clients_table_tab()
        
        # Sessions table
        self._create_sessions_table_tab()
        
        # Screen captures table
        self._create_screen_captures_table_tab()
        
        # Chat messages table
        self._create_chat_messages_table_tab()
        
        # File operations table
        self._create_file_operations_table_tab()
        
        # Security logs table
        self._create_security_logs_table_tab()
        
        layout.addWidget(self.db_tab_widget)
        parent.setLayout(layout)
    
    def _create_clients_table_tab(self):
        """Create the clients table tab."""
        clients_tab = QWidget()
        layout = QVBoxLayout(clients_tab)
        
        # Search and filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Search:"))
        self.client_search = QTextEdit()
        self.client_search.setMaximumHeight(30)
        self.client_search.textChanged.connect(self._filter_clients_table)
        filter_layout.addWidget(self.client_search)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Clients table
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(7)
        self.clients_table.setHorizontalHeaderLabels([
            'Client ID', 'Hostname', 'Platform', 'Status', 'Last Seen', 'IP Address', 'Actions'
        ])
        self.clients_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.clients_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.clients_table.itemDoubleClicked.connect(self._edit_client_entry)
        
        layout.addWidget(self.clients_table)
        clients_tab.setLayout(layout)
        self.db_tab_widget.addTab(clients_tab, "👥 Clients")
    
    def _create_sessions_table_tab(self):
        """Create the sessions table tab."""
        sessions_tab = QWidget()
        layout = QVBoxLayout(sessions_tab)
        
        # Sessions table
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(6)
        self.sessions_table.setHorizontalHeaderLabels([
            'ID', 'Client ID', 'Created At', 'Expires At', 'Last Activity', 'Actions'
        ])
        self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.sessions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sessions_table.itemDoubleClicked.connect(self._edit_session_entry)
        
        layout.addWidget(self.sessions_table)
        sessions_tab.setLayout(layout)
        self.db_tab_widget.addTab(sessions_tab, "⏱️ Sessions")
    
    def _create_screen_captures_table_tab(self):
        """Create the screen captures table tab."""
        captures_tab = QWidget()
        layout = QVBoxLayout(captures_tab)
        
        # Screen captures table
        self.captures_table = QTableWidget()
        self.captures_table.setColumnCount(7)
        self.captures_table.setHorizontalHeaderLabels([
            'ID', 'Client ID', 'Timestamp', 'Image Size', 'Compression', 'Processing Time', 'Actions'
        ])
        self.captures_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.captures_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.captures_table.itemDoubleClicked.connect(self._open_capture_fullscreen)
        
        layout.addWidget(self.captures_table)
        captures_tab.setLayout(layout)
        self.db_tab_widget.addTab(captures_tab, "🖼️ Screen Captures")
    
    def _create_chat_messages_table_tab(self):
        """Create the chat messages table tab."""
        messages_tab = QWidget()
        layout = QVBoxLayout(messages_tab)
        
        # Chat messages table
        self.messages_table = QTableWidget()
        self.messages_table.setColumnCount(6)
        self.messages_table.setHorizontalHeaderLabels([
            'ID', 'Client ID', 'Direction', 'Message', 'Timestamp', 'Actions'
        ])
        self.messages_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.messages_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.messages_table.itemDoubleClicked.connect(self._edit_message_entry)
        
        layout.addWidget(self.messages_table)
        messages_tab.setLayout(layout)
        self.db_tab_widget.addTab(messages_tab, "💬 Chat Messages")
    
    def _create_file_operations_table_tab(self):
        """Create the file operations table tab."""
        files_tab = QWidget()
        layout = QVBoxLayout(files_tab)
        
        # File operations table
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(7)
        self.files_table.setHorizontalHeaderLabels([
            'ID', 'Client ID', 'Operation Type', 'File Path', 'Details', 'Created At', 'Actions'
        ])
        self.files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.itemDoubleClicked.connect(self._edit_file_operation_entry)
        
        layout.addWidget(self.files_table)
        files_tab.setLayout(layout)
        self.db_tab_widget.addTab(files_tab, "📁 File Operations")
    
    def _create_security_logs_table_tab(self):
        """Create the security logs table tab."""
        security_tab = QWidget()
        layout = QVBoxLayout(security_tab)
        
        # Security logs table
        self.security_table = QTableWidget()
        self.security_table.setColumnCount(6)
        self.security_table.setHorizontalHeaderLabels([
            'Log ID', 'Event Type', 'Client ID', 'Details', 'Timestamp', 'Actions'
        ])
        self.security_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.security_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.security_table.itemDoubleClicked.connect(self._view_security_log_details)
        
        layout.addWidget(self.security_table)
        security_tab.setLayout(layout)
        self.db_tab_widget.addTab(security_tab, "🔒 Security Logs")
    
    def _setup_timers(self):
        """Setup timers for periodic updates."""
        # Update stats every 5 seconds
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(5000)
        
        # Update client table every 10 seconds
        self.client_timer = QTimer()
        self.client_timer.timeout.connect(self._update_client_table)
        self.client_timer.start(10000)
        
        # Update database view every 30 seconds
        self.database_timer = QTimer()
        self.database_timer.timeout.connect(self._refresh_database_view)
        self.database_timer.start(30000)
        
        # Send heartbeat to clients every 10 seconds
        self.heartbeat_timer = QTimer()
        self.heartbeat_timer.timeout.connect(self._send_heartbeat_to_clients)
        self.heartbeat_timer.start(10000)
    
    def _toggle_server(self):
        """Toggle server start/stop."""
        if self.start_stop_button.isChecked():
            # Start server
            try:
                self.server.start()
                self.start_stop_button.setText('Stop Server')
                self.status_indicator.setStyleSheet("""
                    QLabel {
                        color: #27ae60;
                        font-size: 20px;
                        font-weight: bold;
                    }
                """)
                self.status_bar.showMessage("Server running")
                logger.info("Server started via GUI")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to start server: {e}")
                self.start_stop_button.setChecked(False)
        else:
            # Stop server
            try:
                self.server.stop()
                self.start_stop_button.setText('Start Server')
                self.status_indicator.setStyleSheet("""
                    QLabel {
                        color: #e74c3c;
                        font-size: 20px;
                        font-weight: bold;
                    }
                """)
                self.status_bar.showMessage("Server stopped")
                logger.info("Server stopped via GUI")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to stop server: {e}")
                self.start_stop_button.setChecked(True)
    
    def _update_stats(self):
        """Update server statistics display."""
        try:
            stats = self.server.get_server_stats()
            
            for field, label in self.stats_labels.items():
                if field in stats:
                    value = stats[field]
                    if field == 'uptime_seconds':
                        # Format uptime
                        hours = int(value // 3600)
                        minutes = int((value % 3600) // 60)
                        seconds = int(value % 60)
                        formatted_value = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                    elif field == 'total_data_received':
                        # Format data size
                        if value > 1024 * 1024:
                            formatted_value = f"{value / (1024*1024):.2f} MB"
                        elif value > 1024:
                            formatted_value = f"{value / 1024:.2f} KB"
                        else:
                            formatted_value = f"{value} bytes"
                    else:
                        formatted_value = str(value)
                    
                    label.setText(f"{field.replace('_', ' ').title()}: {formatted_value}")
            
        except Exception as e:
            logger.error(f"Error updating stats: {e}")
    
    def _send_heartbeat_to_clients(self):
        """Send heartbeat commands to all connected clients."""
        try:
            if not self.server.is_running:
                return
                
            active_clients = list(self.server.clients.values())
            for client_conn in active_clients:
                try:
                    heartbeat_command = {
                        'type': 'heartbeat',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.server._send_data(client_conn.socket, heartbeat_command)
                    logger.debug(f"Sent heartbeat to client {client_conn.client_id}")
                except Exception as e:
                    logger.warning(f"Failed to send heartbeat to client {client_conn.client_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error sending heartbeat to clients: {e}")
    
    def _update_client_table(self):
        """Update the client table display."""
        try:
            # Get currently connected clients from server memory
            connected_clients = list(self.server.clients.values())
            
            self.client_table.setRowCount(len(connected_clients))
            
            for row, client_conn in enumerate(connected_clients):
                self.client_table.setItem(row, 0, QTableWidgetItem(client_conn.client_id or ''))
                self.client_table.setItem(row, 1, QTableWidgetItem(client_conn.hostname or ''))
                self.client_table.setItem(row, 2, QTableWidgetItem(client_conn.platform or ''))
                self.client_table.setItem(row, 3, QTableWidgetItem('Connected'))
            
        except Exception as e:
            logger.error(f"Error updating client table: {e}")
    
    def add_client_widget(self, client_id: str, hostname: str, platform: str):
        """Add a new client widget to the grid."""
        try:
            # Store client information separately
            self.client_info[client_id] = {
                'hostname': hostname,
                'platform': platform
            }
            
            # Create client widget
            client_widget = ClientThumbnailWidget(client_id, hostname, platform)
            self.client_widgets[client_id] = client_widget
            
            # Connect signals
            client_widget.full_screen_requested.connect(self._show_full_screen)
            client_widget.reboot_requested.connect(self._reboot_client)
            client_widget.shutdown_requested.connect(self._shutdown_client)
            client_widget.service_control_requested.connect(self._service_control_client)
            client_widget.message_requested.connect(self._show_messaging_popup)
            client_widget.file_browser_requested.connect(self._show_file_browser)
            
            # Add to grid
            row = len(self.client_widgets) // 6  # 6 columns
            col = len(self.client_widgets) % 6
            
            self.client_grid_layout.addWidget(client_widget, row, col)
            
            logger.info(f"Added client widget: {client_id}")
            
        except Exception as e:
            logger.error(f"Error adding client widget: {e}")
    
    def _reboot_client(self, client_id: str):
        """Reboot a specific client."""
        try:
            from PySide6.QtWidgets import QMessageBox
            
            reply = QMessageBox.question(
                self, "Confirm Reboot",
                f"Are you sure you want to reboot client {client_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.send_reboot_command(client_id)
                if success:
                    QMessageBox.information(self, "Success", f"Reboot command sent to client {client_id}")
                else:
                    QMessageBox.critical(self, "Error", f"Failed to send reboot command to client {client_id}")
                    
        except Exception as e:
            logger.error(f"Error rebooting client {client_id}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to reboot client: {e}")
    
    def _shutdown_client(self, client_id: str):
        """Shutdown a specific client."""
        try:
            from PySide6.QtWidgets import QMessageBox
            
            reply = QMessageBox.question(
                self, "Confirm Shutdown",
                f"Are you sure you want to shutdown client {client_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.send_shutdown_command(client_id)
                if success:
                    QMessageBox.information(self, "Success", f"Shutdown command sent to client {client_id}")
                else:
                    QMessageBox.critical(self, "Error", f"Failed to send shutdown command to client {client_id}")
                    
        except Exception as e:
            logger.error(f"Error shutting down client {client_id}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to shutdown client: {e}")
    
    def _service_control_client(self, client_id: str, action: str):
        """Control service for a specific client."""
        try:
            from PySide6.QtWidgets import QMessageBox
            
            action_text = action.replace('_', ' ').title()
            reply = QMessageBox.question(
                self, f"Confirm {action_text}",
                f"Are you sure you want to {action} the service for client {client_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.send_service_control_command(client_id, action)
                if success:
                    QMessageBox.information(self, "Success", f"{action_text} command sent to client {client_id}")
                else:
                    QMessageBox.critical(self, "Error", f"Failed to send {action} command to client {client_id}")
                    
        except Exception as e:
            logger.error(f"Error controlling service for client {client_id}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to control service: {e}")
    
    def _show_messaging_popup(self, client_id: str):
        """Show messaging popup for a specific client."""
        try:
            if client_id in self.client_info:
                hostname = self.client_info[client_id].get('hostname', 'Unknown')
                
                # Create or reuse persistent popup per client
                if not hasattr(self, 'messaging_popups'):
                    self.messaging_popups = {}
                if client_id not in self.messaging_popups:
                    self.messaging_popups[client_id] = MessagingPopupWidget(client_id, hostname, self)
                    self.messaging_popups[client_id].message_sent.connect(self._send_message_to_client)
                popup = self.messaging_popups[client_id]
                popup.show()
                popup.raise_()
                popup.activateWindow()
                
                logger.info(f"Messaging popup opened for client {client_id}")
            else:
                logger.error(f"Client info not found for {client_id}")
                
        except Exception as e:
            logger.error(f"Error showing messaging popup for client {client_id}: {e}")
    
    def _show_file_browser(self, client_id: str):
        """Show file browser for a specific client."""
        try:
            if client_id in self.client_info:
                hostname = self.client_info[client_id].get('hostname', 'Unknown')
                
                # Create file browser for this client as a separate window
                self.file_browsers[client_id] = FileBrowserWidget(client_id, hostname)
                self.file_browsers[client_id].file_operation_requested.connect(self._handle_file_operation)
                
                # Set window properties to make it a proper window
                self.file_browsers[client_id].setWindowTitle(f"File Browser - {hostname} (Client: {client_id})")
                self.file_browsers[client_id].setWindowFlags(Qt.WindowType.Window)
                self.file_browsers[client_id].resize(800, 600)
                
                # Position the window relative to the main server window
                if self.isVisible():
                    main_geometry = self.geometry()
                    file_browser_geometry = self.file_browsers[client_id].geometry()
                    x = main_geometry.x() + (main_geometry.width() - file_browser_geometry.width()) // 2
                    y = main_geometry.y() + (main_geometry.height() - file_browser_geometry.height()) // 2
                    self.file_browsers[client_id].move(x, y)
                
                # Show the file browser window
                self.file_browsers[client_id].show()
                self.file_browsers[client_id].raise_()
                self.file_browsers[client_id].activateWindow()
                
                # Request initial directory listing
                self.server.request_file_list(client_id, "/")
                
                logger.info(f"File browser opened for client {client_id}")
            else:
                logger.error(f"Client info not found for {client_id}")
                
        except Exception as e:
            logger.error(f"Error showing file browser for client {client_id}: {e}")
    
    def _send_message_to_client(self, client_id: str, message: str):
        """Send a message to a specific client."""
        try:
            # Ensure persistent popup exists for this client
            try:
                self._show_messaging_popup(client_id)
            except Exception:
                pass

            success, message_id = self.server.send_chat_message(client_id, message)
            if success:
                # Append to popup history and keep window open
                timestamp = datetime.now().strftime("%H:%M")
                if hasattr(self, 'messaging_popups') and client_id in self.messaging_popups:
                    popup = self.messaging_popups[client_id]
                    current = popup.history.toPlainText()
                    new_text = (current + ("\n\n" if current else "")) + f"[{timestamp}] Server: {message}"
                    popup.history.setPlainText(new_text)
                    popup.history.verticalScrollBar().setValue(popup.history.verticalScrollBar().maximum())
                    # Show 'sent' indicator immediately
                    try:
                        if hasattr(popup, 'status_label'):
                            popup.status_label.setText("<span style='color:rgba(255,0,0,0.7)'>◯✓</span>")
                    except Exception:
                        pass
                logger.info(f"Message sent to client {client_id}: {message}")
                # Optimistically mark as sent in DB (already done by store); GUI indicator could show ◯✓ here
            else:
                QMessageBox.critical(self, "Error", f"Failed to send message to client {client_id}")
                
        except Exception as e:
            logger.error(f"Error sending message to client {client_id}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to send message: {e}")
    
    def _handle_file_operation(self, client_id: str, operation: str, file_path: str, params: dict):
        """Handle file operation requests from the file browser."""
        try:
            if operation == "list_directory":
                success = self.server.request_file_list(client_id, file_path)
                if not success:
                    QMessageBox.critical(self, "Error", f"Failed to request file list for {file_path}")
            elif operation == "view_file":
                success = self.server.request_file_content(client_id, file_path)
                if not success:
                    QMessageBox.critical(self, "Error", f"Failed to request file content for {file_path}")
            elif operation == "download_file":
                success = self.server.send_file_operation(client_id, "download", file_path, params)
                if not success:
                    QMessageBox.critical(self, "Error", f"Failed to request file download for {file_path}")
            elif operation == "delete_file":
                reply = QMessageBox.question(
                    self, "Confirm Delete",
                    f"Are you sure you want to delete {file_path}?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    success = self.server.send_file_operation(client_id, "delete", file_path, params)
                    if not success:
                        QMessageBox.critical(self, "Error", f"Failed to delete file {file_path}")
            else:
                logger.warning(f"Unknown file operation: {operation}")
                
        except Exception as e:
            logger.error(f"Error handling file operation {operation} for client {client_id}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to handle file operation: {e}")
    
    def _broadcast_reboot_all(self):
        """Reboot all connected clients."""
        try:
            from PySide6.QtWidgets import QMessageBox
            
            if not self.server.clients:
                QMessageBox.information(self, "Info", "No clients connected to reboot.")
                return
            
            reply = QMessageBox.question(
                self, "Confirm Broadcast Reboot",
                f"Are you sure you want to reboot ALL {len(self.server.clients)} connected clients?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                results = self.server.broadcast_command('reboot')
                success_count = sum(1 for success in results.values() if success)
                total_count = len(results)
                
                QMessageBox.information(
                    self, "Broadcast Reboot Complete",
                    f"Reboot commands sent to {total_count} clients.\n"
                    f"Successful: {success_count}\n"
                    f"Failed: {total_count - success_count}"
                )
                
        except Exception as e:
            logger.error(f"Error broadcasting reboot: {e}")
            QMessageBox.critical(self, "Error", f"Failed to broadcast reboot: {e}")
    
    def _broadcast_service_restart_all(self):
        """Restart services on all connected clients."""
        try:
            from PySide6.QtWidgets import QMessageBox
            
            if not self.server.clients:
                QMessageBox.information(self, "Info", "No clients connected to restart services.")
                return
            
            reply = QMessageBox.question(
                self, "Confirm Broadcast Service Restart",
                f"Are you sure you want to restart services on ALL {len(self.server.clients)} connected clients?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                results = self.server.broadcast_command('service_control', action='restart')
                success_count = sum(1 for success in results.values() if success)
                total_count = len(results)
                
                QMessageBox.information(
                    self, "Broadcast Service Restart Complete",
                    f"Service restart commands sent to {total_count} clients.\n"
                    f"Successful: {success_count}\n"
                    f"Failed: {total_count - success_count}"
                )
                
        except Exception as e:
            logger.error(f"Error broadcasting service restart: {e}")
            QMessageBox.critical(self, "Error", f"Failed to broadcast service restart: {e}")
    
    def _show_full_screen(self, client_id: str):
        """Show a client's screen capture in full-screen mode."""
        try:
            if client_id not in self.client_widgets:
                logger.error(f"Client {client_id} not found for full-screen view")
                return
            
            client_widget = self.client_widgets[client_id]
            hostname = client_widget.hostname
            platform = client_widget.platform
            
            # Create full-screen widget as a separate window to avoid central widget churn
            self.full_screen_widget = FullScreenViewWidget(client_id, hostname, platform, parent=self)
            self.current_full_screen_client = client_id
            # Connect return signal
            self.full_screen_widget.return_to_grid_requested.connect(self._return_to_grid)
            # Show the full-screen window without replacing the main central widget
            self.full_screen_widget.show()
            
            # Update the full-screen widget with current image if available
            if client_widget.current_image:
                # We need to get the original image data to pass to full-screen
                # For now, we'll just show the current pixmap
                self.full_screen_widget.image_label.setPixmap(client_widget.current_image)
                self.full_screen_widget.status_label.setText("Online")
                self.full_screen_widget.status_label.setStyleSheet("""
                    QLabel {
                        color: #27ae60;
                        font-weight: bold;
                        font-size: 16px;
                        padding: 10px;
                    }
                """)
            
            logger.info(f"Switched to full-screen view for client {client_id}")
            self._debug_view_state()
            
        except Exception as e:
            logger.error(f"Error showing full-screen view: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _return_to_grid(self):
        """Return from full-screen view to grid view."""
        try:
            logger.info("Attempting to return to grid view...")
            self._debug_view_state()
            
            if self.full_screen_widget:
                # Clean up full-screen widget
                try:
                    self.full_screen_widget.close()
                except Exception:
                    pass
                self.full_screen_widget.deleteLater()
                self.full_screen_widget = None
                self.current_full_screen_client = None

                # Do NOT recreate the entire grid; just restore the original central widget
                if hasattr(self, 'main_content_widget') and self.main_content_widget is not None:
                    self.setCentralWidget(self.main_content_widget)
                # Refresh data-driven tables and thumbnails without destroying widgets
                if hasattr(self, '_refresh_view'):
                    self._refresh_view()
                
                logger.info("Returned to grid view successfully")
                self._debug_view_state()
            
        except Exception as e:
            logger.error(f"Error returning to grid view: {e}")
            # Last resort: fall back to main content rebuild once
            try:
                if hasattr(self, 'build_main_content'):
                    logger.info("Rebuilding main content as fallback...")
                    self.build_main_content()
                    if hasattr(self, '_refresh_view'):
                        self._refresh_view()
            except Exception as recreate_error:
                logger.error(f"Failed to rebuild main content: {recreate_error}")
    
    def _debug_view_state(self):
        """Debug method to check the current view state."""
        try:
            logger.info("=== View State Debug ===")
            logger.info(f"Full screen widget exists: {self.full_screen_widget is not None}")
            logger.info(f"Current full screen client: {self.current_full_screen_client}")
            logger.info(f"Number of client widgets: {len(self.client_widgets)}")
            logger.info(f"Central widget type: {type(self.centralWidget())}")
            logger.info("=== End Debug ===")
            
        except Exception as e:
            logger.error(f"Error in debug view state: {e}")
    
    # _verify_signal_connections removed: PySide6 SignalInstance has no receivers(); debug utility not reliable
    
    # Removed unnecessary view switching methods - handling directly in show/return methods
    
    # _recreate_grid_view removed: widget destruction caused deleted QObject access; avoid full rebuilds at runtime
    
    def _handle_server_update(self, update_type: str, client_id: str, *args):
        """Handle updates from the server."""
        try:
            logger.info(f"GUI update received: {update_type} for client {client_id}")
            
            if update_type == 'client_registered':
                hostname, platform = args
                # Emit signal for thread-safe GUI update
                self.client_registered_signal.emit(client_id, hostname, platform)
            elif update_type == 'screen_capture':
                image_data, metadata = args
                # Emit signal for thread-safe GUI update
                self.screen_capture_signal.emit(client_id, image_data, metadata)
                logger.info(f"Screen capture signal emitted for client {client_id}")
            elif update_type == 'client_disconnected':
                # Emit signal for thread-safe GUI update
                self.client_disconnected_signal.emit(client_id)
            elif update_type == 'file_list_response':
                directory_path, files, directories = args
                # Emit signal for thread-safe GUI update
                self.file_list_response_signal.emit(client_id, directory_path, files, directories)
                logger.info(f"File list response signal emitted for client {client_id}")
            elif update_type == 'file_content_response':
                file_path, content, file_size, is_binary = args
                # Emit signal for thread-safe GUI update
                self.file_content_response_signal.emit(client_id, file_path, content, file_size, is_binary)
                logger.info(f"File content response signal emitted for client {client_id}")
            elif update_type == 'file_operation_response':
                operation, file_path, status, message = args
                # Emit signal for thread-safe GUI update
                self.file_operation_response_signal.emit(client_id, operation, file_path, status, message)
                logger.info(f"File operation response signal emitted for client {client_id}")
            elif update_type == 'chat_message':
                message, timestamp = args
                # Emit signal for thread-safe GUI update
                self.chat_message_signal.emit(client_id, message, timestamp)
                logger.info(f"Chat message signal emitted for client {client_id}")
            elif update_type == 'chat_response':
                message, timestamp = args
                self.chat_response_signal.emit(client_id, message, timestamp)
                logger.info(f"Chat response signal emitted for client {client_id}")
            elif update_type == 'message_status':
                status, message_id = args
                # Update any open messaging popup's status label to reflect state
                try:
                    if hasattr(self, 'messaging_popups') and client_id in self.messaging_popups:
                        popup = self.messaging_popups[client_id]
                        if status == 'delivered':
                            html = "<span style='color:rgba(255,0,0,0.7)'>◯✓ ◯✓</span>"
                        elif status == 'read':
                            html = "<span style='color:rgba(255,0,0,0.7)'>●✓ ●✓</span>"
                        else:
                            html = "<span style='color:rgba(255,0,0,0.7)'>◯✓</span>"
                        if hasattr(popup, 'status_label'):
                            popup.status_label.setText(html)
                except Exception as pe:
                    logger.debug(f"Failed to update popup status UI: {pe}")
            else:
                logger.warning(f"Unknown update type: {update_type}")
                
        except Exception as e:
            logger.error(f"Error handling server update: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _add_client_widget_safe(self, client_id: str, hostname: str, platform: str):
        """Thread-safe method to add client widget (called by signal)."""
        try:
            logger.info(f"Adding client widget safely: {client_id}")
            self.add_client_widget(client_id, hostname, platform)
        except Exception as e:
            logger.error(f"Error in safe add_client_widget: {e}")
    
    def _update_client_image_safe(self, client_id: str, image_data: bytes, metadata: dict):
        """Thread-safe method to update client image (called by signal)."""
        try:
            logger.info(f"Updating client image safely: {client_id}")
            self.update_client_image(client_id, image_data, metadata)
        except Exception as e:
            logger.error(f"Error in safe update_client_image: {e}")
    
    def _remove_client_widget_safe(self, client_id: str):
        """Thread-safe method to remove client widget (called by signal)."""
        try:
            logger.info(f"Removing client widget safely: {client_id}")
            self.remove_client_widget(client_id)
        except Exception as e:
            logger.error(f"Error in safe remove_client_widget: {e}")
    
    def _handle_chat_message_safe(self, client_id: str, message: str, timestamp: str):
        """Thread-safe method to handle chat messages (called by signal)."""
        try:
            logger.info(f"Handling chat message safely: {client_id} - {message}")
            # Update popup history if open
            if hasattr(self, 'messaging_popups') and client_id in self.messaging_popups:
                popup = self.messaging_popups[client_id]
                current = popup.history.toPlainText()
                new_text = (current + ("\n\n" if current else "")) + f"[{timestamp}] Client: {message}"
                popup.history.setPlainText(new_text)
                popup.history.verticalScrollBar().setValue(popup.history.verticalScrollBar().maximum())
            # Also reflect in status bar
            self.status_bar.showMessage(f"Message from {client_id}: {message}")
        except Exception as e:
            logger.error(f"Error in safe handle_chat_message: {e}")

    def _handle_chat_response_safe(self, client_id: str, message: str, timestamp: str):
        """Thread-safe method to handle chat responses (called by signal)."""
        try:
            logger.info(f"Handling chat response safely: {client_id} - {message}")
            if hasattr(self, 'messaging_popups') and client_id in self.messaging_popups:
                popup = self.messaging_popups[client_id]
                current = popup.history.toPlainText()
                new_text = (current + ("\n\n" if current else "")) + f"[{timestamp}] Client: {message}"
                popup.history.setPlainText(new_text)
                popup.history.verticalScrollBar().setValue(popup.history.verticalScrollBar().maximum())
            self.status_bar.showMessage(f"Response from {client_id}: {message}")
        except Exception as e:
            logger.error(f"Error in safe handle_chat_response: {e}")
    
    def _handle_file_list_response_safe(self, client_id: str, directory_path: str, files: list, directories: list):
        """Thread-safe method to handle file list responses (called by signal)."""
        try:
            logger.info(f"Handling file list response safely: {client_id} - {directory_path}")
            logger.info(f"Files: {len(files)}, Directories: {len(directories)}")
            
            # Check if file browser exists for this client
            if client_id in self.file_browsers and self.file_browsers[client_id]:
                logger.info(f"Updating file browser for client {client_id}")
                self.file_browsers[client_id].update_file_list(directory_path, files, directories)
                
                # Show success message in status bar
                self.status_bar.showMessage(f"File list updated for {client_id}: {len(files)} files, {len(directories)} directories")
            else:
                logger.warning(f"File browser not available for client {client_id}")
                logger.warning(f"Available file browsers: {list(self.file_browsers.keys())}")
                
                # Show error message in status bar
                self.status_bar.showMessage(f"File browser not available for client {client_id}")
                
        except Exception as e:
            logger.error(f"Error in safe handle_file_list_response: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            self.status_bar.showMessage(f"Error updating file list: {str(e)}")
    
    def _handle_file_content_response_safe(self, client_id: str, file_path: str, content: str, file_size: int, is_binary: bool):
        """Thread-safe method to handle file content responses (called by signal)."""
        try:
            logger.info(f"Handling file content response safely: {client_id} - {file_path}")
            # For now, just log the response. In the future, this could open a file viewer
            self.status_bar.showMessage(f"File content received from {client_id}: {file_path} ({file_size} bytes)")
            
            # TODO: Open file viewer for this client if available
            if client_id in self.file_browsers and self.file_browsers[client_id]:
                logger.info(f"File content received for client {client_id} with active file browser")
                
        except Exception as e:
            logger.error(f"Error in safe handle_file_content_response: {e}")
    
    def _handle_file_operation_response_safe(self, client_id: str, operation: str, file_path: str, status: str, message: str):
        """Thread-safe method to handle file operation responses (called by signal)."""
        try:
            logger.info(f"Handling file operation response safely: {client_id} - {operation} on {file_path}")
            self.status_bar.showMessage(f"File operation {operation} on {file_path}: {status} - {message}")
        except Exception as e:
            logger.error(f"Error in safe handle_file_operation_response: {e}")
    
    def remove_client_widget(self, client_id: str):
        """Remove a client widget from the grid."""
        try:
            if client_id in self.client_widgets:
                widget = self.client_widgets[client_id]
                self.client_grid_layout.removeWidget(widget)
                widget.deleteLater()
                del self.client_widgets[client_id]
                
                # Remove from client info
                if client_id in self.client_info:
                    del self.client_info[client_id]
                
                # If this client was in full-screen view, return to grid
                if (self.full_screen_widget and 
                    self.current_full_screen_client == client_id):
                    self._return_to_grid()
                
                # Clean up file browser for this client
                if client_id in self.file_browsers:
                    try:
                        self.file_browsers[client_id].close()
                        del self.file_browsers[client_id]
                        logger.info(f"Closed file browser for client {client_id}")
                    except Exception as e:
                        logger.warning(f"Error closing file browser for client {client_id}: {e}")
                
                logger.info(f"Removed client widget: {client_id}")
                
        except Exception as e:
            logger.error(f"Error removing client widget: {e}")
    
    def update_client_image(self, client_id: str, image_data: bytes, metadata: Dict[str, Any]):
        """Update a client's screen capture image."""
        try:
            logger.info(f"Updating image for client {client_id}, data size: {len(image_data)} bytes")
            
            if client_id in self.client_widgets:
                widget = self.client_widgets[client_id]
                
                # Check if widget is still valid
                if widget and hasattr(widget, 'update_image'):
                    try:
                        widget.update_image(image_data, metadata)
                        logger.info(f"Image updated successfully for client {client_id}")
                    except RuntimeError as re:
                        if "already deleted" in str(re):
                            logger.warning(f"Widget for {client_id} was deleted, removing from client_widgets")
                            del self.client_widgets[client_id]
                            return
                        else:
                            raise
                else:
                    logger.warning(f"Widget for {client_id} is invalid, removing from client_widgets")
                    del self.client_widgets[client_id]
                    return
                
                # If this client is currently in full-screen view, update it too
                if (self.full_screen_widget and 
                    self.current_full_screen_client == client_id):
                    try:
                        self.full_screen_widget.update_image(image_data, metadata)
                        logger.info(f"Full-screen view updated for client {client_id}")
                    except RuntimeError as re:
                        if "already deleted" in str(re):
                            logger.warning(f"Full-screen widget was deleted for {client_id}")
                            self.full_screen_widget = None
                            self.current_full_screen_client = None
                        else:
                            raise
            else:
                logger.warning(f"Client widget not found for {client_id}")
            
        except Exception as e:
            logger.error(f"Error updating client image: {e}")
    
    # Database Management Methods
    def _refresh_database_view(self):
        """Refresh all database tables."""
        try:
            self._refresh_clients_table()
            self._refresh_sessions_table()
            self._refresh_screen_captures_table()
            self._refresh_chat_messages_table()
            self._refresh_file_operations_table()
            self._refresh_security_logs_table()
            self.status_bar.showMessage("Database view refreshed")
        except Exception as e:
            logger.error(f"Error refreshing database view: {e}")
    
    def _refresh_clients_table(self):
        """Refresh the clients table."""
        try:
            clients = self.server.database.get_all_clients()
            self.clients_table.setRowCount(len(clients))
            
            for row, client in enumerate(clients):
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                
                # Keep existing edit/delete from before
                edit_btn = QPushButton("✏️")
                edit_btn.setMaximumSize(25, 25)
                edit_btn.clicked.connect(lambda checked, c=client: self._edit_client_entry(c))
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setMaximumSize(25, 25)
                delete_btn.clicked.connect(lambda checked, c=client: self._delete_client_entry(c))
                
                actions_layout.addWidget(edit_btn)
                actions_layout.addWidget(delete_btn)
                actions_layout.addStretch()
                
                self.clients_table.setItem(row, 0, QTableWidgetItem(client.get('client_id', '')))
                self.clients_table.setItem(row, 1, QTableWidgetItem(client.get('hostname', '')))
                self.clients_table.setItem(row, 2, QTableWidgetItem(client.get('platform', '')))
                self.clients_table.setItem(row, 3, QTableWidgetItem(client.get('status', '')))
                self.clients_table.setItem(row, 4, QTableWidgetItem(str(client.get('last_seen', ''))))
                self.clients_table.setItem(row, 5, QTableWidgetItem(client.get('ip_address', '')))
                self.clients_table.setCellWidget(row, 6, actions_widget)
                
        except Exception as e:
            logger.error(f"Error refreshing clients table: {e}")
    
    def _refresh_sessions_table(self):
        """Refresh the sessions table."""
        try:
            sessions = self.server.database.get_all_sessions()
            self.sessions_table.setRowCount(len(sessions))
            
            for row, session in enumerate(sessions):
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                
                edit_btn = QPushButton("✏️")
                edit_btn.setMaximumSize(25, 25)
                edit_btn.clicked.connect(lambda checked, s=session: self._edit_session_entry(s))
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setMaximumSize(25, 25)
                delete_btn.clicked.connect(lambda checked, s=session: self._delete_session_entry(s))
                
                actions_layout.addWidget(edit_btn)
                actions_layout.addWidget(delete_btn)
                actions_layout.addStretch()
                
                self.sessions_table.setItem(row, 0, QTableWidgetItem(str(session.get('id', ''))))
                self.sessions_table.setItem(row, 1, QTableWidgetItem(session.get('client_id', '')))
                self.sessions_table.setItem(row, 2, QTableWidgetItem(str(session.get('created_at', ''))))
                self.sessions_table.setItem(row, 3, QTableWidgetItem(str(session.get('expires_at', ''))))
                self.sessions_table.setItem(row, 4, QTableWidgetItem(str(session.get('last_activity', ''))))
                self.sessions_table.setCellWidget(row, 5, actions_widget)
                
        except Exception as e:
            logger.error(f"Error refreshing sessions table: {e}")
    
    def _refresh_screen_captures_table(self):
        """Refresh the screen captures table."""
        try:
            captures = self.server.database.get_all_screen_captures()
            self.captures_table.setRowCount(len(captures))
            
            for row, capture in enumerate(captures):
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                
                view_btn = QPushButton("👁️")
                view_btn.setMaximumSize(25, 25)
                view_btn.clicked.connect(lambda checked, c=capture: self._view_capture_details(c))
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setMaximumSize(25, 25)
                delete_btn.clicked.connect(lambda checked, c=capture: self._delete_capture_entry(c))
                
                actions_layout.addWidget(view_btn)
                actions_layout.addWidget(delete_btn)
                actions_layout.addStretch()
                
                self.captures_table.setItem(row, 0, QTableWidgetItem(str(capture.get('id', ''))))
                self.captures_table.setItem(row, 1, QTableWidgetItem(capture.get('client_id', '')))
                self.captures_table.setItem(row, 2, QTableWidgetItem(str(capture.get('capture_timestamp', ''))))
                self.captures_table.setItem(row, 3, QTableWidgetItem(str(capture.get('image_size', ''))))
                self.captures_table.setItem(row, 4, QTableWidgetItem(str(capture.get('compression_ratio', ''))))
                self.captures_table.setItem(row, 5, QTableWidgetItem(str(capture.get('processing_time_ms', ''))))
                self.captures_table.setCellWidget(row, 6, actions_widget)
                
        except Exception as e:
            logger.error(f"Error refreshing screen captures table: {e}")
    
    def _refresh_chat_messages_table(self):
        """Refresh the chat messages table."""
        try:
            messages = self.server.database.get_all_chat_messages()
            self.messages_table.setRowCount(len(messages))
            
            for row, message in enumerate(messages):
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                
                edit_btn = QPushButton("✏️")
                edit_btn.setMaximumSize(25, 25)
                edit_btn.clicked.connect(lambda checked, m=message: self._edit_message_entry(m))
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setMaximumSize(25, 25)
                delete_btn.clicked.connect(lambda checked, m=message: self._delete_message_entry(m))
                
                actions_layout.addWidget(edit_btn)
                actions_layout.addWidget(delete_btn)
                actions_layout.addStretch()
                
                self.messages_table.setItem(row, 0, QTableWidgetItem(str(message.get('id', ''))))
                self.messages_table.setItem(row, 1, QTableWidgetItem(message.get('client_id', '')))
                self.messages_table.setItem(row, 2, QTableWidgetItem(message.get('direction', '')))
                self.messages_table.setItem(row, 3, QTableWidgetItem(message.get('message', '')[:50] + '...' if len(message.get('message', '')) > 50 else message.get('message', '')))
                self.messages_table.setItem(row, 4, QTableWidgetItem(str(message.get('timestamp', ''))))
                self.messages_table.setCellWidget(row, 5, actions_widget)
                
        except Exception as e:
            logger.error(f"Error refreshing chat messages table: {e}")
    
    def _refresh_file_operations_table(self):
        """Refresh the file operations table."""
        try:
            operations = self.server.database.get_all_file_operations()
            self.files_table.setRowCount(len(operations))
            
            for row, operation in enumerate(operations):
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                
                edit_btn = QPushButton("✏️")
                edit_btn.setMaximumSize(25, 25)
                edit_btn.clicked.connect(lambda checked, o=operation: self._edit_file_operation_entry(o))
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setMaximumSize(25, 25)
                delete_btn.clicked.connect(lambda checked, o=operation: self._delete_file_operation_entry(o))
                
                actions_layout.addWidget(edit_btn)
                actions_layout.addWidget(delete_btn)
                actions_layout.addStretch()
                
                self.files_table.setItem(row, 0, QTableWidgetItem(str(operation.get('id', ''))))
                self.files_table.setItem(row, 1, QTableWidgetItem(operation.get('client_id', '')))
                self.files_table.setItem(row, 2, QTableWidgetItem(operation.get('operation_type', '')))
                self.files_table.setItem(row, 3, QTableWidgetItem(operation.get('file_path', '')[:50] + '...' if len(operation.get('file_path', '')) > 50 else operation.get('file_path', '')))
                self.files_table.setItem(row, 4, QTableWidgetItem(operation.get('details', '')))
                self.files_table.setItem(row, 5, QTableWidgetItem(str(operation.get('created_at', ''))))
                self.files_table.setCellWidget(row, 6, actions_widget)
                
        except Exception as e:
            logger.error(f"Error refreshing file operations table: {e}")
    
    def _refresh_security_logs_table(self):
        """Refresh the security logs table."""
        try:
            logs = self.server.database.get_all_security_logs()
            self.security_table.setRowCount(len(logs))
            
            for row, log in enumerate(logs):
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                
                view_btn = QPushButton("👁️")
                view_btn.setMaximumSize(25, 25)
                view_btn.clicked.connect(lambda checked, l=log: self._view_security_log_details(l))
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setMaximumSize(25, 25)
                delete_btn.clicked.connect(lambda checked, l=log: self._delete_security_log_entry(l))
                
                actions_layout.addWidget(view_btn)
                actions_layout.addWidget(delete_btn)
                actions_layout.addStretch()
                
                self.security_table.setItem(row, 0, QTableWidgetItem(str(log.get('id', ''))))
                self.security_table.setItem(row, 1, QTableWidgetItem(log.get('event_type', '')))
                self.security_table.setItem(row, 2, QTableWidgetItem(log.get('client_id', '')))
                self.security_table.setItem(row, 3, QTableWidgetItem(log.get('description', '')[:50] + '...' if len(log.get('description', '')) > 50 else log.get('description', '')))
                self.security_table.setItem(row, 4, QTableWidgetItem(str(log.get('timestamp', ''))))
                self.security_table.setCellWidget(row, 5, actions_widget)
                
        except Exception as e:
            logger.error(f"Error refreshing security logs table: {e}")
    
    def _filter_clients_table(self):
        """Filter the clients table based on search text."""
        try:
            search_text = self.client_search.toPlainText().lower()
            for row in range(self.clients_table.rowCount()):
                match = False
                for col in range(self.clients_table.columnCount() - 1):  # Exclude actions column
                    item = self.clients_table.item(row, col)
                    if item and search_text in item.text().lower():
                        match = True
                        break
                self.clients_table.setRowHidden(row, not match)
        except Exception as e:
            logger.error(f"Error filtering clients table: {e}")
    
    def _add_database_entry(self):
        """Add a new database entry."""
        try:
            # Get current tab to determine which table to add to
            current_tab = self.db_tab_widget.currentIndex()
            tab_name = self.db_tab_widget.tabText(current_tab)
            
            if "Clients" in tab_name:
                self._add_client_entry()
            elif "Sessions" in tab_name:
                self._add_session_entry()
            elif "Chat Messages" in tab_name:
                self._add_chat_message_entry()
            elif "File Operations" in tab_name:
                self._add_file_operation_entry()
            else:
                QMessageBox.information(self, "Info", f"Adding entries to {tab_name} is not supported yet.")
                
        except Exception as e:
            logger.error(f"Error adding database entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add entry: {e}")
    
    def _delete_database_entry(self):
        """Delete selected database entry."""
        try:
            # Get current tab to determine which table to delete from
            current_tab = self.db_tab_widget.currentIndex()
            tab_name = self.db_tab_widget.tabText(current_tab)
            
            if "Clients" in tab_name:
                self._delete_selected_client()
            elif "Sessions" in tab_name:
                self._delete_selected_session()
            elif "Screen Captures" in tab_name:
                self._delete_selected_capture()
            elif "Chat Messages" in tab_name:
                self._delete_selected_message()
            elif "File Operations" in tab_name:
                self._delete_selected_file_operation()
            elif "Security Logs" in tab_name:
                self._delete_selected_security_log()
            else:
                QMessageBox.information(self, "Info", f"Deleting from {tab_name} is not supported yet.")
                
        except Exception as e:
            logger.error(f"Error deleting database entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete entry: {e}")
    
    def _export_database(self):
        """Export the entire database."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Database", "", "SQLite Files (*.db);;JSON Files (*.json)"
            )
            
            if file_path:
                if file_path.endswith('.json'):
                    # Export as JSON
                    data = {
                        'clients': self.server.database.get_all_clients(),
                        'sessions': self.server.database.get_all_sessions(),
                        'screen_captures': self.server.database.get_all_screen_captures(),
                        'chat_messages': self.server.database.get_all_chat_messages(),
                        'file_operations': self.server.database.get_all_file_operations(),
                        'security_logs': self.server.database.get_all_security_logs()
                    }
                    
                    with open(file_path, 'w') as f:
                        json.dump(data, f, indent=2, default=str)
                else:
                    # Export as SQLite
                    import shutil
                    shutil.copy2(self.server.database.db_path, file_path)
                
                QMessageBox.information(self, "Success", f"Database exported to {file_path}")
                
        except Exception as e:
            logger.error(f"Error exporting database: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export database: {e}")
    
    # Individual Entry Management Methods
    def _add_client_entry(self):
        """Add a new client entry."""
        try:
            from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Add New Client")
            dialog.setModal(True)
            
            layout = QFormLayout(dialog)
            
            # Form fields
            client_id = QLineEdit()
            client_id.setText(str(uuid.uuid4())[:16])
            layout.addRow("Client ID:", client_id)
            
            hostname = QLineEdit()
            layout.addRow("Hostname:", hostname)
            
            platform = QComboBox()
            platform.addItems(["windows", "linux", "darwin", "unknown"])
            layout.addRow("Platform:", platform)
            
            status = QComboBox()
            status.addItems(["active", "inactive", "suspended"])
            layout.addRow("Status:", status)
            
            ip_address = QLineEdit()
            layout.addRow("IP Address:", ip_address)
            
            # Buttons
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                client_data = {
                    'client_id': client_id.text(),
                    'hostname': hostname.text(),
                    'platform': platform.currentText(),
                    'status': status.currentText(),
                    'ip_address': ip_address.text(),
                    'last_seen': datetime.now().isoformat()
                }
                
                success = self.server.database.add_client(client_data)
                if success:
                    self._refresh_clients_table()
                    QMessageBox.information(self, "Success", "Client added successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to add client")
                    
        except Exception as e:
            logger.error(f"Error adding client entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add client: {e}")
    
    def _add_session_entry(self):
        """Add a new session entry."""
        try:
            from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Add New Session")
            dialog.setModal(True)
            
            layout = QFormLayout(dialog)
            
            # Form fields
            session_id = QLineEdit()
            session_id.setText(str(uuid.uuid4())[:16])
            layout.addRow("Session ID:", session_id)
            
            client_id = QLineEdit()
            layout.addRow("Client ID:", client_id)
            
            start_time = QLineEdit()
            start_time.setText(datetime.now().isoformat())
            layout.addRow("Start Time:", start_time)
            
            end_time = QLineEdit()
            layout.addRow("End Time:", end_time)
            
            duration = QLineEdit()
            layout.addRow("Duration:", duration)
            
            # Buttons
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                session_data = {
                    'session_id': session_id.text(),
                    'client_id': client_id.text(),
                    'start_time': start_time.text(),
                    'end_time': end_time.text(),
                    'duration': duration.text()
                }
                
                success = self.server.database.add_session(session_data)
                if success:
                    self._refresh_sessions_table()
                    QMessageBox.information(self, "Success", "Session added successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to add session")
                    
        except Exception as e:
            logger.error(f"Error adding session entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add session: {e}")
    
    def _add_chat_message_entry(self):
        """Add a new chat message entry."""
        try:
            from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QComboBox, QTextEdit, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Add New Chat Message")
            dialog.setModal(True)
            
            layout = QFormLayout(dialog)
            
            # Form fields
            message_id = QLineEdit()
            message_id.setText(str(uuid.uuid4())[:16])
            layout.addRow("Message ID:", message_id)
            
            client_id = QLineEdit()
            layout.addRow("Client ID:", client_id)
            
            direction = QComboBox()
            direction.addItems(["server_to_client", "client_to_server"])
            layout.addRow("Direction:", direction)
            
            message = QTextEdit()
            message.setMaximumHeight(100)
            layout.addRow("Message:", message)
            
            # Buttons
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                message_data = {
                    'message_id': message_id.text(),
                    'client_id': client_id.text(),
                    'direction': direction.currentText(),
                    'message': message.toPlainText(),
                    'timestamp': datetime.now().isoformat()
                }
                
                success = self.server.database.add_chat_message(message_data)
                if success:
                    self._refresh_chat_messages_table()
                    QMessageBox.information(self, "Success", "Chat message added successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to add chat message")
                    
        except Exception as e:
            logger.error(f"Error adding chat message entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add chat message: {e}")
    
    def _add_file_operation_entry(self):
        """Add a new file operation entry."""
        try:
            from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Add New File Operation")
            dialog.setModal(True)
            
            layout = QFormLayout(dialog)
            
            # Form fields
            operation_id = QLineEdit()
            operation_id.setText(str(uuid.uuid4())[:16])
            layout.addRow("Operation ID:", operation_id)
            
            client_id = QLineEdit()
            layout.addRow("Client ID:", client_id)
            
            operation = QComboBox()
            operation.addItems(["list", "read", "write", "delete", "copy", "move", "create"])
            layout.addRow("Operation:", operation)
            
            file_path = QLineEdit()
            layout.addRow("File Path:", file_path)
            
            status = QComboBox()
            status.addItems(["success", "error", "pending"])
            layout.addRow("Status:", status)
            
            # Buttons
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                operation_data = {
                    'operation_id': operation_id.text(),
                    'client_id': client_id.text(),
                    'operation': operation.currentText(),
                    'file_path': file_path.text(),
                    'status': status.currentText(),
                    'timestamp': datetime.now().isoformat()
                }
                
                success = self.server.database.add_file_operation(operation_data)
                if success:
                    self._refresh_file_operations_table()
                    QMessageBox.information(self, "Success", "File operation added successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to add file operation")
                    
        except Exception as e:
            logger.error(f"Error adding file operation entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add file operation: {e}")
    
    def _edit_client_entry(self, client=None):
        """Edit a client entry."""
        # If invoked via itemDoubleClicked, PySide passes a QTableWidgetItem.
        # Normalize it to a client dict by resolving the selected row.
        try:
            if isinstance(client, QTableWidgetItem):
                row = client.row()
                if row is not None and row >= 0:
                    client_id = self.clients_table.item(row, 0).text()
                    client = self.server.database.get_client(client_id)
                else:
                    client = None
        except Exception:
            client = None

        if not client:
            # Get selected row
            current_row = self.clients_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select a client to edit")
                return
            
            client_id = self.clients_table.item(current_row, 0).text()
            client = self.server.database.get_client(client_id)
        
        if not client:
            QMessageBox.critical(self, "Error", "Client not found")
            return
        
        try:
            from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Client")
            dialog.setModal(True)
            
            layout = QFormLayout(dialog)
            
            # Form fields
            client_id_edit = QLineEdit(client.get('client_id', ''))
            client_id_edit.setReadOnly(True)
            layout.addRow("Client ID:", client_id_edit)
            
            hostname = QLineEdit(client.get('hostname', ''))
            layout.addRow("Hostname:", hostname)
            
            platform = QComboBox()
            platform.addItems(["windows", "linux", "darwin", "unknown"])
            platform.setCurrentText(client.get('platform', 'unknown'))
            layout.addRow("Platform:", platform)
            
            status = QComboBox()
            status.addItems(["active", "inactive", "suspended"])
            status.setCurrentText(client.get('status', 'inactive'))
            layout.addRow("Status:", status)
            
            ip_address = QLineEdit(client.get('ip_address', ''))
            layout.addRow("IP Address:", ip_address)
            
            # Buttons
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)
            
            if dialog.exec() == QDialog.DialogCode.Accepted:
                updated_data = {
                    'hostname': hostname.text(),
                    'platform': platform.currentText(),
                    'status': status.currentText(),
                    'ip_address': ip_address.text()
                }
                
                success = self.server.database.update_client(client.get('client_id'), updated_data)
                if success:
                    self._refresh_clients_table()
                    QMessageBox.information(self, "Success", "Client updated successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to update client")
                    
        except Exception as e:
            logger.error(f"Error editing client entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to edit client: {e}")
    
    def _delete_client_entry(self, client=None):
        """Delete a client entry."""
        # Normalize QTableWidgetItem to client dict if needed
        try:
            if isinstance(client, QTableWidgetItem):
                row = client.row()
                if row is not None and row >= 0:
                    client_id = self.clients_table.item(row, 0).text()
                    client = self.server.database.get_client(client_id)
                else:
                    client = None
        except Exception:
            client = None

        if not client:
            # Get selected row
            current_row = self.clients_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select a client to delete")
                return
            
            client_id = self.clients_table.item(current_row, 0).text()
            client = self.server.database.get_client(client_id)
        
        if not client:
            QMessageBox.critical(self, "Error", "Client not found")
            return
        
        try:
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to delete client {client.get('client_id')}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.database.delete_client(client.get('client_id'))
                if success:
                    self._refresh_clients_table()
                    QMessageBox.information(self, "Success", "Client deleted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete client")
                    
        except Exception as e:
            logger.error(f"Error deleting client entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete client: {e}")
    
    def _delete_selected_client(self):
        """Delete the selected client."""
        self._delete_client_entry()
    
    def _delete_selected_session(self):
        """Delete the selected session."""
        current_row = self.sessions_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a session to delete")
            return
        
        session_id = self.sessions_table.item(current_row, 0).text()
        try:
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to delete session {session_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.database.delete_session(session_id)
                if success:
                    self._refresh_sessions_table()
                    QMessageBox.information(self, "Success", "Session deleted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete session")
                    
        except Exception as e:
            logger.error(f"Error deleting session: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete session: {e}")
    
    def _delete_selected_capture(self):
        """Delete the selected screen capture."""
        current_row = self.captures_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a capture to delete")
            return
        
        capture_id = self.captures_table.item(current_row, 0).text()
        try:
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to delete capture {capture_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.database.delete_screen_capture(capture_id)
                if success:
                    self._refresh_screen_captures_table()
                    QMessageBox.information(self, "Success", "Capture deleted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete capture")
                    
        except Exception as e:
            logger.error(f"Error deleting capture: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete capture: {e}")
    
    def _delete_selected_message(self):
        """Delete the selected chat message."""
        current_row = self.messages_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a message to delete")
            return
        
        message_id = self.messages_table.item(current_row, 0).text()
        try:
            reply = QMessageBox.question(
                self, "Warning",
                f"Are you sure you want to delete message {message_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.database.delete_chat_message(message_id)
                if success:
                    self._refresh_chat_messages_table()
                    QMessageBox.information(self, "Success", "Message deleted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete message")
                    
        except Exception as e:
            logger.error(f"Error deleting message: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete message: {e}")
    
    def _delete_selected_file_operation(self):
        """Delete the selected file operation."""
        current_row = self.files_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a file operation to delete")
            return
        
        operation_id = self.files_table.item(current_row, 0).text()
        try:
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to delete file operation {operation_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.database.delete_file_operation(operation_id)
                if success:
                    self._refresh_file_operations_table()
                    QMessageBox.information(self, "Success", "File operation deleted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete file operation")
                    
        except Exception as e:
            logger.error(f"Error deleting file operation: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete file operation: {e}")
    
    def _delete_selected_security_log(self):
        """Delete the selected security log."""
        current_row = self.security_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a security log to delete")
            return
        
        log_id = self.security_table.item(current_row, 0).text()
        try:
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to delete security log {log_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                success = self.server.database.delete_security_log(log_id)
                if success:
                    self._refresh_security_logs_table()
                    QMessageBox.information(self, "Success", "Security log deleted successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete security log")
                    
        except Exception as e:
            logger.error(f"Error deleting security log: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete security log: {e}")
    
    def _view_capture_details(self, capture=None):
        """View screen capture details."""
        # Resolve capture dict regardless of input type
        if not capture:
            current_row = self.captures_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select a capture to view")
                return
            capture_id = self.captures_table.item(current_row, 0).text()
            capture = self.server.database.get_screen_capture(capture_id)
        else:
            # If called with a table item or id, resolve to dict
            if isinstance(capture, dict):
                pass
            else:
                try:
                    # QTableWidgetItem
                    if hasattr(capture, 'text') and callable(capture.text):
                        capture_id = capture.text()
                    else:
                        capture_id = str(capture)
                    capture = self.server.database.get_screen_capture(capture_id)
                except Exception:
                    capture = None

        if not capture or not isinstance(capture, dict):
            QMessageBox.critical(self, "Error", "Capture not found")
            return

        try:
            details = f"Capture ID: {capture.get('id')}\n"
            details += f"Client ID: {capture.get('client_id')}\n"
            details += f"Timestamp: {capture.get('capture_timestamp')}\n"
            details += f"Size: {capture.get('image_size', 'Unknown')}\n"
            details += f"Compression: {capture.get('compression_ratio', 'Unknown')}\n"
            details += f"Processing Time: {capture.get('processing_time_ms', 'Unknown')} ms\n"
            details += f"Metadata: {capture.get('metadata', 'None')}"

            QMessageBox.information(self, "Capture Details", details)

        except Exception as e:
            logger.error(f"Error viewing capture details: {e}")
            QMessageBox.critical(self, "Error", f"Failed to view capture details: {e}")

    def _open_capture_fullscreen(self, item):
        """Open the selected capture image in a separate window on double-click.

        This avoids replacing the main central widget, preserving tabs like
        the Database Viewer. The viewer can be closed independently.
        """
        try:
            row = item.row() if hasattr(item, 'row') else self.captures_table.currentRow()
            if row is None or row < 0:
                return
            capture_id_item = self.captures_table.item(row, 0)
            client_id_item = self.captures_table.item(row, 1)
            if not capture_id_item or not client_id_item:
                return
            capture_id = capture_id_item.text()
            client_id = client_id_item.text()
            # Resolve client info for header text
            client = self.server.database.get_client(client_id) or {'hostname': client_id, 'platform': ''}
            hostname = client.get('hostname', client_id)
            platform = client.get('platform', '')
            # Fetch image bytes; decrypts if stored encrypted
            image_bytes = self.server.database.get_screen_capture_image(capture_id)
            if not image_bytes:
                QMessageBox.information(self, "Info", "No image data available for this capture.")
                return
            # Create a top-level viewer window and keep a strong reference
            if not hasattr(self, '_capture_windows'):
                self._capture_windows = []
            viewer = FullScreenViewWidget(client_id, hostname, platform)
            viewer.setWindowFlags(Qt.Window)
            viewer.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
            # Repurpose the back button to close the viewer window
            try:
                viewer.return_to_grid_requested.disconnect()
            except Exception:
                pass
            viewer.return_to_grid_requested.connect(viewer.close)
            # Load and show image
            viewer.store_image_data(image_bytes)
            viewer.update_image(image_bytes, {})
            viewer.showMaximized()
            self._capture_windows.append(viewer)
            # Cleanup list entry when window is destroyed
            viewer.destroyed.connect(lambda *_: self._capture_windows.remove(viewer) if viewer in self._capture_windows else None)
        except Exception as e:
            logger.error(f"Failed to open capture window: {e}")
            QMessageBox.critical(self, "Error", f"Failed to open image: {e}")
    
    def _view_security_log_details(self, log=None):
        """View security log details."""
        if not log:
            current_row = self.security_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "Warning", "Please select a security log to view")
                return
            log_id = self.security_table.item(current_row, 0).text()
            log = self.server.database.get_security_log(log_id)
        else:
            if isinstance(log, dict):
                pass
            else:
                try:
                    if hasattr(log, 'text') and callable(log.text):
                        log_id = log.text()
                    else:
                        log_id = str(log)
                    log = self.server.database.get_security_log(log_id)
                except Exception:
                    log = None

        if not log or not isinstance(log, dict):
            QMessageBox.critical(self, "Error", "Security log not found")
            return

        try:
            details = f"Log ID: {log.get('id')}\n"
            details += f"Event Type: {log.get('event_type')}\n"
            details += f"Client ID: {log.get('client_id')}\n"
            details += f"Timestamp: {log.get('timestamp')}\n"
            details += f"Description: {log.get('description')}"

            QMessageBox.information(self, "Security Log Details", details)

        except Exception as e:
            logger.error(f"Error viewing security log details: {e}")
            QMessageBox.critical(self, "Error", f"Failed to view security log details: {e}")
    
    def _edit_session_entry(self, session):
        """Edit a session entry."""
        QMessageBox.information(self, "Info", "Session editing not implemented yet.")
    
    def _edit_message_entry(self, message):
        """Edit a chat message entry."""
        QMessageBox.information(self, "Info", "Message editing not implemented yet.")
    
    def _edit_file_operation_entry(self, operation):
        """Edit a file operation entry."""
        QMessageBox.information(self, "Info", "File operation editing not implemented yet.")
    
    def _delete_session_entry(self, session):
        """Delete a session entry."""
        try:
            session_id = session.get('id')
            success = self.server.database.delete_session(session_id)
            if success:
                self._refresh_sessions_table()
                QMessageBox.information(self, "Success", "Session deleted successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to delete session")
        except Exception as e:
            logger.error(f"Error deleting session entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete session: {e}")
    
    def _delete_capture_entry(self, capture):
        """Delete a capture entry."""
        try:
            capture_id = capture.get('id')
            success = self.server.database.delete_screen_capture(capture_id)
            if success:
                self._refresh_screen_captures_table()
                QMessageBox.information(self, "Success", "Capture deleted successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to delete capture")
        except Exception as e:
            logger.error(f"Error deleting capture entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete capture: {e}")
    
    def _delete_message_entry(self, message):
        """Delete a message entry."""
        try:
            message_id = message.get('id')
            success = self.server.database.delete_chat_message(message_id)
            if success:
                self._refresh_chat_messages_table()
                QMessageBox.information(self, "Success", "Message deleted successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to delete message")
        except Exception as e:
            logger.error(f"Error deleting message entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete message: {e}")
    
    def _delete_file_operation_entry(self, operation):
        """Delete a file operation entry."""
        try:
            operation_id = operation.get('id')
            success = self.server.database.delete_file_operation(operation_id)
            if success:
                self._refresh_file_operations_table()
                QMessageBox.information(self, "Success", "File operation deleted successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to delete file operation")
        except Exception as e:
            logger.error(f"Error deleting file operation entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete file operation: {e}")
    
    def _delete_security_log_entry(self, log):
        """Delete a security log entry."""
        try:
            log_id = log.get('id')
            success = self.server.database.delete_security_log(log_id)
            if success:
                self._refresh_security_logs_table()
                QMessageBox.information(self, "Success", "Security log deleted successfully")
            else:
                QMessageBox.critical(self, "Error", "Failed to delete security log")
        except Exception as e:
            logger.error(f"Error deleting security log entry: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete security log: {e}")
    
    def _refresh_view(self):
        """Refresh the current view."""
        self._update_stats()
        self._update_client_table()
        self.status_bar.showMessage("View refreshed")
    
    def _on_tab_changed(self, index):
        """Handle tab change events to refresh client list from in-memory connections."""
        try:
            # Always repopulate clients from in-memory connections when tab changes
            self._update_client_table()
            logger.debug(f"Tab changed to index {index}, client table refreshed")
        except Exception as e:
            logger.error(f"Error handling tab change: {e}")
    
    def _export_data(self):
        """Export monitoring data."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Data", "", "JSON Files (*.json)"
            )
            
            if file_path:
                # Export client data
                clients = self.server.database.get_active_clients()
                
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'clients': clients
                }
                
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                QMessageBox.information(self, "Success", f"Data exported to {file_path}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export data: {e}")
    
    def _show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog not implemented yet.")
    
    def _show_about(self):
        """Show about dialog."""
        try:
            ver = get_version()
        except Exception:
            ver = "unknown"
        QMessageBox.about(self, "About",
                         "Employee Monitoring System\n\n"
                         "A secure monitoring solution for enterprise environments.\n"
                         f"Version {ver}\n"
                         "Built with Python.\n"
                         "Copyright 2025, C0ldSoft Technologies\n"
                         "All rights reserved.\n"
                         "Coded by: Andrew Gurklies")
    
    def _update_capture_interval(self, value: int):
        """Update the capture interval setting."""
        self.interval_value_label.setText(f"{value} seconds")
        # TODO: Send this setting to connected clients
    
    def closeEvent(self, event):
        """Handle application close event."""
        try:
            # Stop server if running
            if self.server.is_running:
                reply = QMessageBox.question(
                    self, "Confirm Exit",
                    "Server is running. Do you want to stop it and exit?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    self.server.stop()
                    event.accept()
                else:
                    event.ignore()
            else:
                event.accept()
                
        except Exception as e:
            logger.error(f"Error during close: {e}")
            event.accept()

def main():
    """Main entry point for the monitoring server."""
    try:
        # Create Qt application
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Create server instance
        server = MonitoringServer()
        
        # Create and show GUI
        gui = MonitoringServerGUI(server)
        gui.show()
        
        # Start event loop
        sys.exit(app.exec())
        
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
