import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Table to track file states
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_states (
                    relative_path TEXT PRIMARY KEY,
                    file_hash TEXT,
                    last_scanned TIMESTAMP
                )
            """)
            # Base rules table - we'll add columns dynamically
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    is_rule INTEGER DEFAULT 0,
                    filename TEXT,
                    relative_path TEXT
                )
            """)
            conn.commit()

    def get_columns(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(rules)")
            return [info[1] for info in cursor.fetchall()]

    def ensure_column(self, column_name):
        columns = self.get_columns()
        if column_name not in columns:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                # Use double quotes for column names to handle reserved words or spaces
                cursor.execute(f'ALTER TABLE rules ADD COLUMN "{column_name}" TEXT')
                conn.commit()

    def save_rules(self, rules_data):
        if not rules_data:
            return

        # Ensure all columns exist
        all_keys = set()
        for rule in rules_data:
            all_keys.update(rule.keys())

        for key in all_keys:
            self.ensure_column(key)

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Group by relative_path to delete once per file
            paths_to_clear = {rule['relative_path'] for rule in rules_data}
            for path in paths_to_clear:
                cursor.execute("DELETE FROM rules WHERE relative_path = ?", (path,))

            for rule in rules_data:
                cols = list(rule.keys())
                col_names = '"' + '", "'.join(cols) + '"'
                placeholders = ":" + ", :".join(cols)

                cursor.execute(f"INSERT INTO rules ({col_names}) VALUES ({placeholders})", rule)
            conn.commit()

    def update_file_state(self, relative_path, file_hash):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO file_states (relative_path, file_hash, last_scanned)
                VALUES (?, ?, ?)
            """, (relative_path, file_hash, datetime.now().isoformat()))
            conn.commit()

    def get_file_hash(self, relative_path):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_hash FROM file_states WHERE relative_path = ?", (relative_path,))
            result = cursor.fetchone()
            return result[0] if result else None

    def search_rules(self, query_str, target_columns=None):
        columns = self.get_columns()
        if not query_str:
            sql = "SELECT * FROM rules"
            params = []
        else:
            # If target_columns is provided and not empty, search only those
            search_cols = target_columns if target_columns else columns
            search_clause = " OR ".join([f'"{col}" LIKE ?' for col in search_cols])
            sql = f"SELECT * FROM rules WHERE {search_clause}"
            params = [f"%{query_str}%"] * len(search_cols)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            return cursor.fetchall(), columns
