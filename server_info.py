#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
import configparser

# Ensure project root is on sys.path
THIS_FILE = Path(__file__).resolve()
ROOT = THIS_FILE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security import SecurityManager  # type: ignore
from database import SecureDatabase  # type: ignore


def load_config(config_path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not config_path.exists():
        # Provide sane defaults if missing
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
        return cfg
    cfg.read(config_path)
    return cfg


def main():
    config_path = ROOT / 'config.ini'
    cfg = load_config(config_path)

    # Initialize security and database
    sm = SecurityManager(cfg)
    db = SecureDatabase(cfg)

    # Collect system and database information
    system_info = sm.get_system_info()
    db_stats = db.get_database_stats()

    # Active clients (count + sample up to 10 hostnames)
    try:
        active_clients = db.get_active_clients()
        active_count = len(active_clients)
        sample_clients = [c.get('hostname') or c.get('client_id') for c in active_clients[:10]]
    except Exception:
        active_count = 0
        sample_clients = []

    payload = {
        'ok': True,
        'system_info': system_info,
        'database': {
            'stats': db_stats,
            'active_clients_count': active_count,
            'active_clients_sample': sample_clients,
        },
    }

    print(json.dumps(payload, ensure_ascii=False))


if __name__ == '__main__':
    main()
