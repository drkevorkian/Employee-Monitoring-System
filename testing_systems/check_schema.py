#!/usr/bin/env python3
"""Check database schema to see what columns exist."""

import sqlite3

def check_schema():
    try:
        conn = sqlite3.connect('monitoring.db')
        cursor = conn.cursor()
        
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print("Tables found:")
        for table in tables:
            table_name = table[0]
            print(f"\n=== {table_name} ===")
            
            # Get table schema
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            for col in columns:
                col_id, col_name, col_type, not_null, default_val, pk = col
                print(f"  {col_name} ({col_type}) {'NOT NULL' if not_null else 'NULL'} {'PK' if pk else ''}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_schema()
