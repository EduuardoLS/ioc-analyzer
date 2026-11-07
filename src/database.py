import sqlite3
import json
from datetime import datetime

class DatabaseManager: 
    def __init__(self, db_name="data/history.db"):
        self.db_name = db_name
        self._create_table()

    def _connect(self):
        return sqlite3.connect(self.db_name)

    def _create_table(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT,
                    ioc_type TEXT,
                    risk_level TEXT,
                    raw_result TEXT,
                    timestamp TEXT
                )
            """)

    def save_analysis(self, ioc_value: str, ioc_type: str, risk_level: str, result_data: dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO analysis_history (ioc_value, ioc_type, risk_level, raw_result, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ioc_value,
                ioc_type,
                risk_level,
                json.dumps(result_data),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

    def get_history(self):
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ioc_value, ioc_type, risk_level, timestamp FROM analysis_history ORDER BY id DESC")
            return cursor.fetchall()
            
