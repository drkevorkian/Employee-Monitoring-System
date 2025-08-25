#!/usr/bin/env python3
import json
import urllib.request
import os
import sys
from pathlib import Path
import configparser
import platform
import socket
import time
import json
import getpass
from datetime import datetime

# Ensure project root is on sys.path
THIS_FILE = Path(__file__).resolve()
ROOT = THIS_FILE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Try to import SecurityManager, fall back to a minimal stub if unavailable
try:
    from security import SecurityManager  # type: ignore
except Exception:
    class SecurityManager:  # type: ignore
        def __init__(self, cfg):
            pass
        def get_system_info(self):
            return {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'python_version': sys.version.split()[0],
            }

from database import SecureDatabase  # type: ignore


def load_config(config_path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not config_path.exists():
        cfg['Server'] = {'host': '0.0.0.0', 'port': '8080'}
        cfg['Security'] = {
            'encryption_key_size': '256',
            'authentication_required': 'true',
            'max_login_attempts': '3',
            'session_timeout': '3600',
            'rate_limit_requests': '100',
            'rate_limit_window': '60',
        }
        cfg['Database'] = {'db_type': 'sqlite', 'db_path': str(ROOT / 'monitoring.db')}
    else:
        cfg.read(config_path)
        if not cfg.has_section('Database'):
            cfg['Database'] = {}
        # Ensure db_path present
        if not cfg.has_option('Database', 'db_path'):
            cfg.set('Database', 'db_path', str(ROOT / 'monitoring.db'))
    # Resolve db_path robustly
    env_db = os.environ.get('EMS_DB_PATH')
    candidates = []
    if env_db:
        candidates.append(Path(env_db))
    try:
        configured = Path(cfg.get('Database', 'db_path', fallback=str(ROOT / 'monitoring.db')))
        candidates.append(configured if configured.is_absolute() else (ROOT / configured))
    except Exception:
        candidates.append(ROOT / 'monitoring.db')
    # Parent fallbacks
    candidates.append(ROOT / 'monitoring.db')
    candidates.append(ROOT.parent / 'monitoring.db')
    candidates.append(ROOT.parent.parent / 'monitoring.db')
    for path in candidates:
        try:
            if path and Path(path).exists():
                cfg.set('Database', 'db_path', str(Path(path).resolve()))
                break
        except Exception:
            continue
    return cfg


def main():
    try:
        config_path = ROOT / 'config.ini'
        cfg = load_config(config_path)

        # Initialize security and database
        sm = SecurityManager(cfg)
        db = SecureDatabase(cfg)

        # Result size cap for web UI
        try:
            LIMIT = int(os.environ.get('EMS_WEB_LIMIT', '200'))
        except Exception:
            LIMIT = 200

        # Collect system and database information
        try:
            system_info = sm.get_system_info()
        except Exception:
            system_info = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'python_version': sys.version.split()[0],
            }

        # Server host details (best-effort, no extra deps)
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = platform.node() or 'unknown'
        # internal IPv4 best-effort
        internal_ip = ''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            internal_ip = s.getsockname()[0]
        except Exception:
            try:
                internal_ip = socket.gethostbyname(hostname)
            except Exception:
                internal_ip = ''
        finally:
            try:
                s.close()  # type: ignore
            except Exception:
                pass
        # external IPv4 via ipify (best-effort, short timeout)
        external_ip = ''
        try:
            with urllib.request.urlopen('https://api.ipify.org/', timeout=3) as resp:
                external_ip = (resp.read().decode('utf-8', errors='ignore') or '').strip()
                # basic sanity check
                if not external_ip or len(external_ip) > 64:
                    external_ip = ''
        except Exception:
            external_ip = ''

        # mac address
        try:
            mac_int = __import__('uuid').getnode()
            mac_address = ':'.join(f"{(mac_int >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
        except Exception:
            mac_address = ''
        # current user
        try:
            logged_in_user = getpass.getuser()
        except Exception:
            logged_in_user = ''
        # uptime seconds
        uptime_seconds = None
        try:
            import psutil  # type: ignore
            boot_time = getattr(psutil, 'boot_time', lambda: None)()
            if boot_time:
                uptime_seconds = int(time.time() - boot_time)
        except Exception:
            uptime_seconds = None
        try:
            db_stats = db.get_database_stats()
        except Exception:
            db_stats = {}

        # Active clients
        try:
            active_clients = db.get_active_clients()
            active_count = len(active_clients)
            sample_clients = [c.get('hostname') or c.get('client_id') for c in active_clients[:10]]
        except Exception:
            active_count = 0
            sample_clients = []

        # Full client list for UI
        try:
            clients = db.get_all_clients()[:LIMIT]
        except Exception:
            clients = []

        # Sessions
        try:
            sessions = db.get_all_sessions()[:LIMIT]
        except Exception:
            sessions = []

        # Screen captures (metadata only, no blobs here)
        try:
            screen_captures = db.get_all_screen_captures()[:LIMIT]
        except Exception:
            screen_captures = []

        # Chat messages (message field may be decrypted by db layer)
        try:
            chat_messages = db.get_all_chat_messages()[:LIMIT]
        except Exception:
            # Do not abort on decryption or retrieval errors; return an empty list
            chat_messages = []

        # File operations
        try:
            file_operations = db.get_all_file_operations()[:LIMIT]
        except Exception:
            file_operations = []

        # Security logs
        try:
            security_logs = db.get_all_security_logs()[:LIMIT]
        except Exception:
            security_logs = []

        # Recent client logs
        try:
            cur = db.conn.cursor()
            cur.execute(
                """
                SELECT client_id, level, logger_name, module, function, line, created_at, message
                FROM client_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (LIMIT,)
            )
            rows = cur.fetchall()
            client_logs = []
            for r in rows:
                try:
                    msg = db.security.decrypt_from_db(r[7]) if getattr(db, 'security', None) else r[7]
                except Exception:
                    msg = r[7]
                client_logs.append({
                    'client_id': r[0], 'level': r[1], 'logger': r[2], 'module': r[3], 'function': r[4], 'line': r[5], 'created_at': r[6], 'message': msg
                })
        except Exception:
            client_logs = []

        # Recent exec results (metadata + first bytes of output)
        try:
            cur = db.conn.cursor()
            cur.execute(
                """
                SELECT client_id, command_id, cmd, exit_code, created_at, stdout, stderr
                FROM exec_results
                ORDER BY id DESC
                LIMIT ?
                """,
                (LIMIT,)
            )
            rows = cur.fetchall()
            exec_results = []
            for r in rows:
                try:
                    out = db.security.decrypt_from_db(r[5]) if getattr(db, 'security', None) else r[5]
                except Exception:
                    out = r[5]
                try:
                    err = db.security.decrypt_from_db(r[6]) if getattr(db, 'security', None) else r[6]
                except Exception:
                    err = r[6]
                exec_results.append({
                    'client_id': r[0], 'command_id': r[1], 'cmd': r[2], 'exit_code': r[3], 'created_at': r[4],
                    'stdout': (out or '')[:512], 'stderr': (err or '')[:256]
                })
        except Exception:
            exec_results = []

        payload = {
            'ok': True,
            'system_info': system_info,
            'database': {
                'stats': db_stats,
                'active_clients_count': active_count,
                'active_clients_sample': sample_clients,
            },
            'server': {
                'hostname': hostname,
                'internal_ip': internal_ip,
                'external_ip': external_ip,
                'mac_address': mac_address,
                'logged_in_user': logged_in_user,
                'uptime_seconds': uptime_seconds,
                'status': 'online',
                'last_seen': datetime.utcnow().isoformat(timespec='seconds')+'Z',
            },
            'clients': clients,
            'sessions': sessions,
            'screen_captures': screen_captures,
            'chat_messages': chat_messages,
            'file_operations': file_operations,
            'security_logs': security_logs,
            'client_logs': client_logs,
            'exec_results': exec_results,
        }

        print(json.dumps(payload, ensure_ascii=False))
    except Exception as e:
        # Always emit JSON on error
        print(json.dumps({'ok': False, 'error': str(e)}))


if __name__ == '__main__':
    main()
