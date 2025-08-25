#!/usr/bin/env python3
import os
import sys
import sqlite3
from pathlib import Path
import configparser

THIS_FILE = Path(__file__).resolve()
ROOT = THIS_FILE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security import SecurityManager  # type: ignore


def load_config(config_path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if config_path.exists():
        cfg.read(config_path)
    else:
        cfg['Database'] = {'db_path': str(ROOT / 'monitoring.db')}
        cfg['Security'] = {}
    # Honor EMS_DB_PATH env override
    env_db = os.environ.get('EMS_DB_PATH')
    if env_db:
        if not cfg.has_section('Database'):
            cfg['Database'] = {}
        cfg.set('Database', 'db_path', env_db)
    return cfg


def main():
    if len(sys.argv) < 2:
        sys.stderr.write('missing client_id\n')
        sys.exit(2)
    client_id = sys.argv[1]

    cfg = load_config(ROOT / 'config.ini')
    db_path = cfg.get('Database', 'db_path', fallback=str(ROOT / 'monitoring.db'))

    # Init security for decryption
    sm = SecurityManager(cfg)

    # Fast minimal query using sqlite3 directly (KISS)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute('PRAGMA foreign_keys = ON')
        cur = conn.cursor()
        cur.execute(
            "SELECT image_data FROM screen_captures WHERE client_id = ? ORDER BY capture_timestamp DESC LIMIT 1",
            (client_id,),
        )
        row = cur.fetchone()
        if not row or row[0] is None:
            sys.stderr.write('no frame\n')
            sys.exit(1)
        enc = row[0]
        # Decrypt if needed
        try:
            data = sm.decrypt_blob_from_db(enc)
        except Exception:
            # assume plaintext
            data = enc if isinstance(enc, (bytes, bytearray)) else bytes(enc)
        # Write binary to stdout
        if hasattr(sys.stdout, 'buffer'):
            sys.stdout.buffer.write(data)
        else:
            os.write(sys.stdout.fileno(), data)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
