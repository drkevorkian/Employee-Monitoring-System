#!/usr/bin/env python3
"""
Cleanup script for Project Asteroid Miner workspace.
- Removes logs, tmp files, cache dirs
- Optionally removes databases, exports, and virtualenvs
- Optionally removes legacy Versions/ directory

Usage:
  python scripts/cleanup.py [--all] [--purge-venv] [--purge-versions]

Defaults: keeps databases, exports, and virtualenvs unless flags are provided.
"""
import argparse
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REMOVE_DIRS_ALWAYS = [
	ROOT / 'logs',
	ROOT / '__pycache__',
]

REMOVE_GLOBS_ALWAYS = [
	'*.log',
	'*.tmp',
	'*.temp',
]

REMOVE_DIRS_OPTIONAL = [
	ROOT / 'data',
	ROOT / 'exports',
]

VENV_DIRS = [ROOT / 'venv', ROOT / '.venv']

def remove_path(p: Path):
	if not p.exists():
		return
	if p.is_dir():
		shutil.rmtree(p, ignore_errors=True)
	else:
		try:
			p.unlink()
		except Exception:
			pass

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--all', action='store_true', help='Remove optional dirs (data, exports) and database files')
	parser.add_argument('--purge-venv', action='store_true', help='Remove venv/.venv directories')
	parser.add_argument('--purge-versions', action='store_true', help='Remove legacy Versions/ directory')
	args = parser.parse_args()

	# Always remove standard noise
	for d in REMOVE_DIRS_ALWAYS:
		remove_path(d)
	for pattern in REMOVE_GLOBS_ALWAYS:
		for p in ROOT.glob(pattern):
			remove_path(p)

	# Optional removals
	if args.all:
		for d in REMOVE_DIRS_OPTIONAL:
			remove_path(d)
		for db in ROOT.glob('monitoring.db*'):
			remove_path(db)

	if args.purge_venv:
		for d in VENV_DIRS:
			remove_path(d)

	if args.purge_versions:
		remove_path(ROOT / 'Versions')

	print('Cleanup complete.')

if __name__ == '__main__':
	main()
