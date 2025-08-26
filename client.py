#!/usr/bin/env python3
"""
Client Program for Employee Monitoring System
Captures screen data and system information, sends to monitoring server.
"""

import os
import sys
import time
import json
import socket
import threading
import struct
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
try:
    import pyautogui
    pyautogui.FAILSAFE = False
except Exception:
    pyautogui = None
import io
from updater.service import UpdaterService  # type: ignore
from version import get_version

# Import our custom logging system
try:
    from logging_config import get_logger
    logger = get_logger('client')
except ImportError as e:
    # Fallback to basic logging if custom system not available
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('client.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)

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
        
        # Service management
        self.is_service = self._check_if_running_as_service()
        self.service_name = "EmployeeMonitoringClient"
        self.service_display_name = "Employee Monitoring Client"
        self.service_description = "Monitors employee computer activity for security purposes"
        
        # Platform-specific settings
        self.platform = platform.system()
        if isinstance(self.platform, str):
            self.platform = self.platform.lower()
        
        # Signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"Monitoring client initialized: {self.client_id}")
        logger.info(f"Platform: {self.platform}")

        # Install a logging handler that forwards log records to the server
        try:
            self._install_remote_log_handler()
        except Exception as e:
            logger.debug(f"Remote log handler not installed: {e}")
        logger.info(f"Running as service: {self.is_service}")
        # Perform environment and dependency verification at startup.
        # This logs actionable warnings but never crashes the client.
        self._verify_environment()
        
        # Updater: simple local check stub
        def _check_local_update():
            try:
                meta_path = os.path.join(os.getcwd(), 'update_meta_client.json')
                if os.path.exists(meta_path):
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except Exception:
                return None
            return None
        self.updater = UpdaterService(current_version=get_version(), check_func=_check_local_update, poll_seconds=20)
        self.updater.start()

    def _verify_environment(self) -> None:
        """Verify optional dependencies and environment; log warnings only.

        - Warn if running headless on Linux/macOS where screen capture may fail.
        - Warn if pyautogui is not available (remote input disabled).
        - Warn if server host cannot be resolved.
        """
        try:
            # Headless warning for capture
            if self.platform in ['linux', 'darwin']:
                has_display = bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))
                if not has_display:
                    logger.warning("No DISPLAY/WAYLAND_DISPLAY detected; ImageGrab may fail in headless mode.")
            # Remote control dependency
            if pyautogui is None:
                logger.warning("pyautogui not available; remote keyboard/mouse control will be disabled.")
            # DNS reachability for server host
            try:
                socket.getaddrinfo(self.server_host, self.server_port)
            except Exception:
                logger.warning(f"Cannot resolve server host '{self.server_host}:{self.server_port}'. Check network/DNS.")
        except Exception as e:
            logger.debug(f"Environment verification encountered an error: {e}")
    
    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        if os.path.exists(config_file):
            config.read(config_file)
            logger.info(f"Configuration loaded from {config_file}")
        else:
            logger.warning(f"Configuration file {config_file} not found, using defaults")
        
        return config
    
    def _check_if_running_as_service(self) -> bool:
        """Check if the client is running as a system service."""
        try:
            # Check if running in a service context
            if self.platform == 'windows':
                # Windows service check
                import win32serviceutil
                import win32service
                return True
            elif self.platform in ['linux', 'darwin']:
                # Linux/macOS service check
                return os.environ.get('SERVICE_NAME') is not None or 'systemd' in os.environ.get('PATH', '')
            else:
                return False
        except ImportError:
            # win32service not available, not running as Windows service
            return False
        except Exception:
            return False
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start the monitoring client."""
        try:
            self.is_running = True
            logger.info("Starting monitoring client...")
            
            # Main connection loop
            while self.is_running:
                try:
                    if not self.connected:
                        self._connect_to_server()
                    
                    if self.connected:
                        self._main_loop()
                    
                except Exception as e:
                    logger.error(f"Connection error: {e}")
                    self.connected = False
                    
                    if self.auto_reconnect and self.is_running:
                        logger.info(f"Reconnecting in {self.reconnect_delay} seconds...")
                        time.sleep(self.reconnect_delay)
                    else:
                        break
            
        except KeyboardInterrupt:
            logger.info("Client stopped by user")
        except Exception as e:
            logger.error(f"Client error: {e}")
        finally:
            self.stop()
    
    def _connect_to_server(self):
        """Connect to the monitoring server."""
        try:
            logger.info(f"Connecting to server: {self.server_host}:{self.server_port}")
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            # Connect to server
            self.socket.connect((self.server_host, self.server_port))
            
            # Configure TCP keepalive and low-latency
            try:
                self._configure_keepalive(self.socket)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception as e:
                logger.warning(f"Could not configure socket options: {e}")

            # Register with server
            if self._register_with_server():
                self.connected = True
                logger.info("Successfully connected to server")
            else:
                logger.error("Failed to register with server")
                self.socket.close()
                self.socket = None
                
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            if self.socket:
                self.socket.close()
                self.socket = None
    
    def _register_with_server(self) -> bool:
        """Register this client with the server."""
        try:
            # Gather system information
            system_info = self._gather_system_info()
            
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
                logger.error(f"Registration rejected: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return False
    
    def _gather_system_info(self) -> Dict[str, Any]:
        """Gather comprehensive system information."""
        try:
            # Basic system info
            info = {
                'hostname': platform.node(),
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'logged_in_user': None,
                'capabilities': {
                    'screen_capture': True,
                    'remote_reboot': True,
                    'service_management': True
                }
            }
            
            # Network information
            try:
                import uuid as uuid_module
                mac_address = ':'.join(['{:02x}'.format((uuid_module.getnode() >> elements) & 0xff) 
                                      for elements in range(0,2*6,2)][::-1])
                info['network_info'] = {
                    'mac_address': mac_address,
                    'hostname': platform.node()
                }
                # External IP best-effort
                try:
                    import urllib.request
                    ip = urllib.request.urlopen('https://api.ipify.org/', timeout=3).read().decode('utf-8').strip()
                    if ip and len(ip) < 64:
                        info['external_ip'] = ip
                except Exception:
                    info['external_ip'] = None
            except Exception as e:
                logger.warning(f"Could not get network info: {e}")
                info['network_info'] = {}
            
            # System resources
            try:
                info['system_resources'] = {
                    'cpu_count': psutil.cpu_count(),
                    'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                    'disk_total_gb': round(psutil.disk_usage('/').total / (1024**3), 2) if self.platform != 'windows' else 
                                    round(psutil.disk_usage('C:\\').total / (1024**3), 2)
                }
            except Exception as e:
                logger.warning(f"Could not get system resources: {e}")
                info['system_resources'] = {}
            # Uptime seconds
            try:
                info['uptime_seconds'] = int(time.time() - psutil.boot_time())
            except Exception:
                info['uptime_seconds'] = None
            # Logged in user detection
            try:
                user = None
                if self.platform == 'windows':
                    user = os.getlogin()
                else:
                    import getpass
                    user = getpass.getuser()
                info['logged_in_user'] = user
            except Exception as e:
                logger.debug(f"Could not get logged in user: {e}")
            
            # Service status
            info['service_status'] = {
                'running_as_service': self.is_service,
                'service_name': self.service_name,
                'auto_startup': self._check_auto_startup()
            }
            
            return info
            
        except Exception as e:
            logger.error(f"Error gathering system info: {e}")
            return {
                'hostname': 'Unknown',
                'platform': 'Unknown',
                'capabilities': {'screen_capture': True}
            }
    
    def _check_auto_startup(self) -> bool:
        """Check if the client is configured to start automatically on boot."""
        try:
            if self.platform == 'windows':
                # Check Windows registry for startup entry
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                       r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                       0, winreg.KEY_READ)
                    winreg.QueryValueEx(key, self.service_display_name)
                    winreg.CloseKey(key)
                    return True
                except FileNotFoundError:
                    return False
            elif self.platform in ['linux', 'darwin']:
                # Check systemd service or launchd
                if self.platform == 'linux':
                    return os.path.exists(f"/etc/systemd/system/{self.service_name}.service")
                else:
                    return os.path.exists(f"~/Library/LaunchAgents/{self.service_name}.plist")
            else:
                return False
        except Exception as e:
            logger.warning(f"Could not check auto startup: {e}")
            return False
    
    def _main_loop(self):
        """Main client loop for handling server communication."""
        try:
            while self.connected and self.is_running:
                # Send heartbeat
                if time.time() - self.last_heartbeat > self.heartbeat_interval:
                    self._send_heartbeat()
                    self.last_heartbeat = time.time()
                
                # Check for server commands
                if self._check_for_commands():
                    continue
                
                # Capture and send screen
                self._capture_and_send_screen()
                
                # Small delay to prevent excessive CPU usage
                time.sleep(self.screen_capture_interval)
                
        except Exception as e:
            logger.error(f"Main loop error: {e}")
            self.connected = False
    
    def _check_for_commands(self) -> bool:
        """Check for incoming commands from the server."""
        try:
            # Set socket timeout for non-blocking check
            self.socket.settimeout(0.1)
            
            # Try to receive data
            data = self._receive_data()
            if data:
                return self._handle_server_command(data)
            
            # Reset timeout
            self.socket.settimeout(None)
            return False
            
        except socket.timeout:
            # No data available
            self.socket.settimeout(None)
            return False
        except Exception as e:
            logger.error(f"Error checking for commands: {e}")
            self.socket.settimeout(None)
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
            elif command_type == 'remote_input':
                return self._handle_remote_input_command(command)
            elif command_type == 'exec':
                return self._handle_exec_command(command)
            else:
                logger.warning(f"Unknown command type: {command_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling server command: {e}")
            return False

    def _handle_remote_input_command(self, command: Dict[str, Any]) -> bool:
        """Handle remote input commands from the server (mouse/keyboard)."""
        try:
            if pyautogui is None:
                logger.warning("pyautogui not available; remote input ignored")
                return False

            action = command.get('action')
            if action == 'mouse_move':
                x = int(command.get('x', 0))
                y = int(command.get('y', 0))
                duration = float(command.get('duration', 0))
                # Clamp within screen bounds
                try:
                    scr_w, scr_h = pyautogui.size()
                    x = max(0, min(x, scr_w - 1))
                    y = max(0, min(y, scr_h - 1))
                except Exception:
                    pass
                pyautogui.moveTo(x, y, duration=max(0.0, duration))
                return True
            if action == 'mouse_click':
                x = command.get('x')
                y = command.get('y')
                button = command.get('button', 'left')
                clicks = int(command.get('clicks', 1))
                interval = float(command.get('interval', 0.0))
                if x is not None and y is not None:
                    xi, yi = int(x), int(y)
                    try:
                        scr_w, scr_h = pyautogui.size()
                        xi = max(0, min(xi, scr_w - 1))
                        yi = max(0, min(yi, scr_h - 1))
                    except Exception:
                        pass
                    pyautogui.click(xi, yi, clicks=clicks, interval=interval, button=button)
                else:
                    pyautogui.click(clicks=clicks, interval=interval, button=button)
                return True
            if action == 'mouse_scroll':
                amount = int(command.get('amount', 0))
                axis = command.get('axis', 'vertical')
                if axis == 'horizontal':
                    try:
                        pyautogui.hscroll(amount)
                    except Exception:
                        # fallback: simulate with shift+scroll
                        pyautogui.keyDown('shift')
                        pyautogui.scroll(amount)
                        pyautogui.keyUp('shift')
                else:
                    pyautogui.scroll(amount)
                return True
            if action == 'key_event':
                key = str(command.get('key', ''))
                ev = command.get('event', 'press')
                if not key:
                    return False
                if ev == 'down':
                    pyautogui.keyDown(key)
                elif ev == 'up':
                    pyautogui.keyUp(key)
                else:
                    pyautogui.press(key)
                return True
            if action == 'key_type':
                text = command.get('text', '')
                if text:
                    pyautogui.typewrite(text, interval=float(command.get('interval', 0.0)))
                return True
            if action == 'start_fullscreen_control':
                # Optional: could dim screen or show overlay to indicate remote control
                logger.info("Remote control session started")
                return True
            if action == 'stop_fullscreen_control':
                logger.info("Remote control session ended")
                return True
            logger.warning(f"Unknown remote_input action: {action}")
            return False
        except Exception as e:
            logger.error(f"Remote input handling failed: {e}")
            return False

    def _handle_exec_command(self, command: Dict[str, Any]) -> bool:
        """Execute a system command securely with optional allowlist and admin gating.
        Command schema: {
          'type': 'exec', 'command_id': str, 'cmd': str|list, 'args': list[str],
          'as_admin': bool, 'timeout': int, 'cwd': str, 'env': dict[str,str]
        }
        """
        try:
            cmd_id = command.get('command_id') or str(uuid.uuid4())
            raw_cmd = command.get('cmd')
            args = command.get('args') or []
            as_admin = bool(command.get('as_admin', False))
            timeout = int(command.get('timeout', 30))
            cwd = command.get('cwd') or None
            env = command.get('env') or {}

            # Config gates
            allow_exec = self.config.getboolean('Interpreter', 'allow_exec', fallback=False)
            if not allow_exec:
                raise PermissionError('exec disabled by policy')

            # Allowlist / denylist patterns (simple prefix match)
            allow_patterns = [p.strip() for p in self.config.get('Interpreter', 'allowlist', fallback='').split(',') if p.strip()]
            deny_patterns = [p.strip() for p in self.config.get('Interpreter', 'denylist', fallback='').split(',') if p.strip()]

            # Normalize command vector without shell
            if isinstance(raw_cmd, str):
                cmd_vec = [raw_cmd] + [str(a) for a in args]
            elif isinstance(raw_cmd, list):
                cmd_vec = [str(x) for x in raw_cmd + args]
            else:
                raise ValueError('invalid cmd')

            exe = os.path.basename(cmd_vec[0]).lower()
            # Deny takes precedence
            for pat in deny_patterns:
                if exe.startswith(pat.lower()):
                    raise PermissionError('command denied by policy')
            if allow_patterns:
                if not any(exe.startswith(p.lower()) for p in allow_patterns):
                    raise PermissionError('command not in allowlist')

            # Admin/elevation gating
            if as_admin:
                allow_admin = self.config.getboolean('Interpreter', 'allow_admin_exec', fallback=False)
                if not allow_admin:
                    raise PermissionError('admin exec disabled by policy')
                # Only proceed if already elevated (service/root)
                try:
                    if self.platform == 'windows':
                        # Heuristic: running as service implies elevation
                        if not self.is_service:
                            raise PermissionError('not elevated')
                    else:
                        if hasattr(os, 'geteuid') and os.geteuid() != 0:
                            raise PermissionError('not elevated')
                except Exception as _:
                    raise PermissionError('elevation status unknown')

            # Constrain environment passthrough to a safe subset
            safe_env = os.environ.copy()
            for k, v in list(env.items())[:20]:
                if isinstance(k, str) and isinstance(v, str) and len(k) <= 64 and len(v) <= 4096:
                    if k.upper() not in {'PATH', 'TMP', 'TEMP', 'HOME', 'USERPROFILE', 'SYSTEMROOT'}:
                        safe_env[k] = v

            logger.info(f"Executing command (id={cmd_id}): {cmd_vec}")
            try:
                proc = subprocess.run(
                    cmd_vec,
                    cwd=cwd,
                    env=safe_env,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=max(1, min(timeout, 600))
                )
                rc = proc.returncode
                out = (proc.stdout or '')[:16384]
                err = (proc.stderr or '')[:16384]
            except subprocess.TimeoutExpired as te:
                rc = -1
                out = (te.stdout or '')[:8192]
                err = f"timeout after {timeout}s"
            except Exception as ex:
                rc = -2
                out = ''
                err = str(ex)[:4096]

            # Send result back
            result = {
                'type': 'exec_result',
                'command_id': cmd_id,
                'client_id': self.client_id,
                'cmd': cmd_vec[:1],
                'args': cmd_vec[1:10],
                'exit_code': rc,
                'stdout': out,
                'stderr': err,
                'timestamp': datetime.now().isoformat()
            }
            self._send_data(result)
            return True
        except Exception as e:
            logger.error(f"Exec command failed: {e}")
            try:
                self._send_data({
                    'type': 'exec_result',
                    'command_id': command.get('command_id') or '',
                    'client_id': self.client_id,
                    'exit_code': -3,
                    'stdout': '',
                    'stderr': str(e)[:4096],
                    'timestamp': datetime.now().isoformat()
                })
            except Exception:
                pass
            return False
    
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
            action = command.get('action')
            logger.info(f"Executing service control command: {action}")
            
            if action == 'start':
                success = self._start_service()
            elif action == 'stop':
                success = self._stop_service()
            elif action == 'restart':
                success = self._restart_service()
            elif action == 'install':
                success = self._install_service()
            elif action == 'uninstall':
                success = self._uninstall_service()
            else:
                logger.error(f"Unknown service action: {action}")
                return False
            
            # Send response
            response = {
                'type': 'command_response',
                'command_id': command.get('command_id'),
                'status': 'success' if success else 'error',
                'message': f'Service {action} {"completed" if success else "failed"}'
            }
            self._send_data(response)
            
            return success
            
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
            message_id = command.get('message_id')
            logger.info(f"Received chat message from server: {message}")
            
            # Immediately acknowledge delivery to server (popup shown is handled by GUI client variant)
            try:
                if message_id:
                    status_msg = {
                        'type': 'message_status',
                        'status': 'delivered',
                        'message_id': message_id,
                        'timestamp': datetime.now().isoformat()
                    }
                    self._send_data(status_msg)
            except Exception:
                pass
            
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
                    for item in os.listdir(directory_path):
                        item_path = os.path.join(directory_path, item)
                        try:
                            if os.path.isdir(item_path):
                                directories.append(item)
                            else:
                                # Get file info
                                stat = os.stat(item_path)
                                files.append({
                                    'name': item,
                                    'type': 'file',
                                    'size': stat.st_size,
                                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                })
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
                self._send_data(response)
                
                logger.info(f"File list sent: {len(files)} files, {len(directories)} directories")
                logger.info(f"Response data: {response}")
                return True
                
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
                'operation': command.get('operation', 'unknown'),
                'file_path': command.get('file_path', ''),
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
    
    def _start_service(self) -> bool:
        """Start the monitoring service."""
        try:
            if self.platform == 'windows':
                subprocess.run(['sc', 'start', self.service_name], check=True)
            elif self.platform == 'linux':
                subprocess.run(['systemctl', 'start', self.service_name], check=True)
            elif self.platform == 'darwin':
                subprocess.run(['launchctl', 'load', f"~/Library/LaunchAgents/{self.service_name}.plist"], check=True)
            else:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start service: {e}")
            return False
    
    def _stop_service(self) -> bool:
        """Stop the monitoring service."""
        try:
            if self.platform == 'windows':
                subprocess.run(['sc', 'stop', self.service_name], check=True)
            elif self.platform == 'linux':
                subprocess.run(['systemctl', 'stop', self.service_name], check=True)
            elif self.platform == 'darwin':
                subprocess.run(['launchctl', 'unload', f"~/Library/LaunchAgents/{self.service_name}.plist"], check=True)
            else:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop service: {e}")
            return False
    
    def _restart_service(self) -> bool:
        """Restart the monitoring service."""
        try:
            if self._stop_service():
                time.sleep(2)  # Wait for service to stop
                return self._start_service()
            return False
            
        except Exception as e:
            logger.error(f"Failed to restart service: {e}")
            return False
    
    def _install_service(self) -> bool:
        """Install the monitoring service."""
        try:
            if self.platform == 'windows':
                return self._install_windows_service()
            elif self.platform == 'linux':
                return self._install_linux_service()
            elif self.platform == 'darwin':
                return self._install_macos_service()
            else:
                return False
                
        except Exception as e:
            logger.error(f"Failed to install service: {e}")
            return False
    
    def _install_windows_service(self) -> bool:
        """Install Windows service using NSSM."""
        try:
            # Check if NSSM is available
            nssm_path = shutil.which('nssm')
            if not nssm_path:
                logger.error("NSSM not found. Please install NSSM to create Windows services.")
                return False
            
            # Get current executable path
            exe_path = sys.executable
            script_path = os.path.abspath(__file__)
            
            # Install service using NSSM
            subprocess.run([
                nssm_path, 'install', self.service_name, exe_path, script_path
            ], check=True)
            
            # Set service description
            subprocess.run([
                nssm_path, 'set', self.service_name, 'Description', self.service_description
            ], check=True)
            
            # Set startup type to automatic
            subprocess.run([
                nssm_path, 'set', self.service_name, 'Start', 'SERVICE_AUTO_START'
            ], check=True)
            
            logger.info("Windows service installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install Windows service: {e}")
            return False
    
    def _install_linux_service(self) -> bool:
        """Install Linux systemd service."""
        try:
            # Create systemd service file
            service_content = f"""[Unit]
Description={self.service_description}
After=network.target

[Service]
Type=simple
User=root
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=always
RestartSec=10
Environment=SERVICE_NAME={self.service_name}

[Install]
WantedBy=multi-user.target
"""
            
            # Write service file
            service_path = f"/etc/systemd/system/{self.service_name}.service"
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Reload systemd and enable service
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', self.service_name], check=True)
            
            logger.info("Linux systemd service installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install Linux service: {e}")
            return False
    
    def _install_macos_service(self) -> bool:
        """Install macOS launchd service."""
        try:
            # Create launchd plist file
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{self.service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/{self.service_name}.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/{self.service_name}.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SERVICE_NAME</key>
        <string>{self.service_name}</string>
    </dict>
</dict>
</plist>
"""
            
            # Write plist file
            plist_path = f"~/Library/LaunchAgents/{self.service_name}.plist"
            plist_path = os.path.expanduser(plist_path)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(plist_path), exist_ok=True)
            
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            # Load the service
            subprocess.run(['launchctl', 'load', plist_path], check=True)
            
            logger.info("macOS launchd service installed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install macOS service: {e}")
            return False
    
    def _uninstall_service(self) -> bool:
        """Uninstall the monitoring service."""
        try:
            if self.platform == 'windows':
                return self._uninstall_windows_service()
            elif self.platform == 'linux':
                return self._uninstall_linux_service()
            elif self.platform == 'darwin':
                return self._uninstall_macos_service()
            else:
                return False
                
        except Exception as e:
            logger.error(f"Failed to uninstall service: {e}")
            return False
    
    def _uninstall_windows_service(self) -> bool:
        """Uninstall Windows service."""
        try:
            # Stop service first
            try:
                subprocess.run(['sc', 'stop', self.service_name], check=True)
                time.sleep(2)
            except:
                pass
            
            # Delete service
            nssm_path = shutil.which('nssm')
            if nssm_path:
                subprocess.run([nssm_path, 'remove', self.service_name, 'confirm'], check=True)
            else:
                subprocess.run(['sc', 'delete', self.service_name], check=True)
            
            logger.info("Windows service uninstalled successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall Windows service: {e}")
            return False
    
    def _uninstall_linux_service(self) -> bool:
        """Uninstall Linux systemd service."""
        try:
            # Stop and disable service
            try:
                subprocess.run(['systemctl', 'stop', self.service_name], check=True)
                subprocess.run(['systemctl', 'disable', self.service_name], check=True)
            except:
                pass
            
            # Remove service file
            service_path = f"/etc/systemd/system/{self.service_name}.service"
            if os.path.exists(service_path):
                os.remove(service_path)
            
            # Reload systemd
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            
            logger.info("Linux systemd service uninstalled successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall Linux service: {e}")
            return False
    
    def _uninstall_macos_service(self) -> bool:
        """Uninstall macOS launchd service."""
        try:
            # Unload service
            plist_path = f"~/Library/LaunchAgents/{self.service_name}.plist"
            plist_path = os.path.expanduser(plist_path)
            
            try:
                subprocess.run(['launchctl', 'unload', plist_path], check=True)
            except:
                pass
            
            # Remove plist file
            if os.path.exists(plist_path):
                os.remove(plist_path)
            
            logger.info("macOS launchd service uninstalled successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall macOS service: {e}")
            return False
    
    def _send_heartbeat(self):
        """Send heartbeat to server."""
        try:
            heartbeat = {
                'type': 'heartbeat',
                'client_id': self.client_id,
                'timestamp': datetime.now().isoformat(),
                'system_status': self._get_system_status()
            }
            self._send_data(heartbeat)
            
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {e}")

    def _configure_keepalive(self, sock: socket.socket) -> None:
        """Enable cross-platform TCP keepalive with sensible defaults."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'SIO_KEEPALIVE_VALS') and sys.platform.startswith('win'):
                sock.ioctl(socket.SIO_KEEPALIVE_VALS, struct.pack('III', 1, 10000, 3000))
            else:
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
                if hasattr(socket, 'TCP_KEEPCNT'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except Exception as e:
            logger.warning(f"Keepalive configuration failed: {e}")
    
    def _get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        try:
            status = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent if self.platform != 'windows' else 
                               psutil.disk_usage('C:\\').percent,
                'uptime_seconds': time.time() - psutil.boot_time(),
                'process_count': len(psutil.pids())
            }
            return status
            
        except Exception as e:
            logger.warning(f"Could not get system status: {e}")
            return {}
    
    def _capture_and_send_screen(self):
        """Capture screen and send to server."""
        try:
            # Capture screen
            screenshot = ImageGrab.grab()
            
            # Resize if needed
            max_width, max_height = map(int, self.max_image_size.split('x'))
            if screenshot.width > max_width or screenshot.height > max_height:
                screenshot.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            
            # Convert to bytes (PNG does not use JPEG quality parameter)
            img_byte_arr = io.BytesIO()
            screenshot.save(img_byte_arr, format='PNG', optimize=True)
            img_byte_arr = img_byte_arr.getvalue()
            
            # Create capture message
            capture = {
                'type': 'screen_capture',
                'client_id': self.client_id,
                'image_data': base64.b64encode(img_byte_arr).decode('utf-8'),
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'resolution': f"{screenshot.width}x{screenshot.height}",
                    'format': 'PNG',
                    'size_bytes': len(img_byte_arr),
                    'compression_level': self.compression_level
                }
            }
            
            # Send to server
            self._send_data(capture)
            
        except Exception as e:
            logger.error(f"Screen capture failed: {e}")
    
    def _send_data(self, data: Dict[str, Any]):
        """Send data to server."""
        try:
            if not self.socket:
                return
            # Convert to JSON and encrypt all transport data
            json_bytes = json.dumps(data, default=str).encode('utf-8')
            try:
                from security import SecurityManager
                if not hasattr(self, '_transport_security'):
                    self._transport_security = SecurityManager(self.config)
                sec = self._transport_security
                nonce = os.urandom(12)
                ct = sec.db_aead.encrypt(nonce, json_bytes, b'TRANSv1')
                payload = b'TRV1' + nonce + ct
            except Exception:
                payload = json_bytes
            length_bytes = len(payload).to_bytes(4, byteorder='big')
            self.socket.sendall(length_bytes + payload)
            
        except Exception as e:
            logger.error(f"Failed to send data: {e}")
            self.connected = False

    def _install_remote_log_handler(self) -> None:
        """Attach a handler that forwards client logs to the server safely."""
        class _ServerLogHandler(logging.Handler):
            def __init__(self, client_ref: 'MonitoringClient'):
                super().__init__()
                self.client_ref = client_ref
            def emit(self, record: logging.LogRecord) -> None:
                try:
                    client = self.client_ref
                    # Avoid recursion: never forward logs originating from this handler/module
                    if record.name in ('client', __name__):
                        pass
                    # Only attempt when connected
                    if not getattr(client, 'connected', False) or not getattr(client, 'socket', None):
                        return
                    msg = {
                        'type': 'client_log',
                        'client_id': getattr(client, 'client_id', ''),
                        'level': record.levelname.lower(),
                        'message': record.getMessage(),
                        'logger': record.name,
                        'timestamp': datetime.now().isoformat(),
                        'module': record.module,
                        'func': record.funcName,
                        'line': record.lineno,
                    }
                    # Send without encryption errors breaking the app
                    try:
                        client._send_data(msg)
                    except Exception:
                        pass
                except Exception:
                    # Never raise from logging handler
                    pass

        # Attach once
        root_logger = logging.getLogger()
        # Prevent duplicates
        for h in root_logger.handlers:
            if isinstance(h, logging.Handler) and h.__class__.__name__ == '_ServerLogHandler':
                return
        root_logger.addHandler(_ServerLogHandler(self))
    
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
    
    def stop(self):
        """Stop the monitoring client."""
        try:
            logger.info("Stopping monitoring client...")
            self.is_running = False
            
            if self.socket:
                self.socket.close()
                self.socket = None
            
            self.connected = False
            logger.info("Monitoring client stopped")
            
        except Exception as e:
            logger.error(f"Error stopping client: {e}")

    def _get_version(self) -> str:
        return get_version()

def main():
    """Main entry point for the monitoring client."""
    try:
        # Create client instance
        client = MonitoringClient()
        
        # Start client
        client.start()
        
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
