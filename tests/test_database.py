import unittest
import sqlite3
import os
from wazuh_manager.database import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_wazuh_rules.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_init_db(self):
        columns = self.db.get_columns()
        self.assertIn("rule_id", columns)
        self.assertIn("filename", columns)
        self.assertIn("relative_path", columns)

    def test_save_and_search_rules(self):
        rule_data = [
            {
                "rule_id": "1001",
                "filename": "test.xml",
                "relative_path": "test.xml",
                "description": "Test rule",
                "level": "5"
            }
        ]
        self.db.save_rules(rule_data)

        results, columns = self.db.search_rules("Test rule")
        self.assertEqual(len(results), 1)
        self.assertIn("description", columns)
        self.assertIn("level", columns)

    def test_file_state(self):
        self.db.update_file_state("test.xml", "hash123")
        h = self.db.get_file_hash("test.xml")
        self.assertEqual(h, "hash123")

if __name__ == "__main__":
    unittest.main()
