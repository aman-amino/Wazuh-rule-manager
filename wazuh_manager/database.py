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
                    relative_path TEXT,
                    raw_xml TEXT
                )
            """)
            # Rule history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rule_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    relative_path TEXT,
                    raw_xml TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def get_columns(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(rules)")
            return [info[1] for info in cursor.fetchall()]

    def get_column_type(self, column_name):
        """Checks if a column should be treated as numeric or text."""
        # Simple heuristic for rule-related columns
        numeric_cols = ["rule_id", "level", "id", "is_rule"]
        if column_name.lower() in numeric_cols:
            return "NUMERIC"
        return "TEXT"

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
            paths_to_clear = {rule['relative_path'] for rule in rules_data if 'relative_path' in rule}
            for path in paths_to_clear:
                cursor.execute("DELETE FROM rules WHERE relative_path = ?", (path,))

            for rule in rules_data:
                cols = list(rule.keys())
                col_names = '"' + '", "'.join(cols) + '"'
                placeholders = ":" + ", :".join(cols)

                cursor.execute(f"INSERT INTO rules ({col_names}) VALUES ({placeholders})", rule)
            conn.commit()

    def add_to_history(self, rule_id, relative_path, raw_xml):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO rule_history (rule_id, relative_path, raw_xml)
                VALUES (?, ?, ?)
            """, (rule_id, relative_path, raw_xml))
            conn.commit()

    def get_history(self, rule_id, relative_path):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, raw_xml, timestamp FROM rule_history
                WHERE rule_id = ? AND relative_path = ?
                ORDER BY timestamp DESC
            """, (rule_id, relative_path))
            return cursor.fetchall()

    def delete_rule(self, rule_id, relative_path):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM rules WHERE rule_id = ? AND relative_path = ?", (rule_id, relative_path))
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

    def search_rules(self, query_str, target_columns=None, show_duplicates=False):
        columns = self.get_columns()

        if show_duplicates:
            sql = """
                SELECT * FROM rules
                WHERE rule_id IN (
                    SELECT rule_id FROM rules
                    GROUP BY rule_id HAVING COUNT(*) > 1
                )
            """
            params = []
        elif not query_str:
            sql = "SELECT * FROM rules"
            params = []
        else:
            # If target_columns is provided and not empty, search only those
            search_cols = target_columns if target_columns else columns

            clause_parts = []
            params = []
            for col in search_cols:
                col_type = self.get_column_type(col)
                if col_type == "NUMERIC" and query_str.isdigit():
                    # Exact match for numeric IDs or levels
                    clause_parts.append(f'"{col}" = ?')
                    params.append(query_str)
                else:
                    # Pattern match for text or if query isn't digits
                    clause_parts.append(f'"{col}" LIKE ?')
                    params.append(f"%{query_str}%")

            search_clause = " OR ".join(clause_parts)
            sql = f"SELECT * FROM rules WHERE {search_clause}"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            return cursor.fetchall(), columns

    def get_stats_by_level(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT level, COUNT(*) FROM rules GROUP BY level ORDER BY CAST(level AS INTEGER)")
            return cursor.fetchall()

    def get_stats_by_id_range(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Create buckets of 10,000 IDs
            cursor.execute("""
                SELECT (CAST(rule_id AS INTEGER) / 10000) * 10000 AS range_start, COUNT(*)
                FROM rules
                WHERE rule_id GLOB '[0-9]*'
                GROUP BY range_start
                ORDER BY range_start
            """)
            return cursor.fetchall()
