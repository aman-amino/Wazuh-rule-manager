import unittest
import os
import tempfile
from wazuh_manager.database import DatabaseManager

class TestSecurityDB(unittest.TestCase):
    def setUp(self):
        self.test_db = tempfile.NamedTemporaryFile(delete=False).name
        self.db = DatabaseManager(self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_column_sanitization(self):
        malicious_rule = {
            "rule_id": "999999",
            "normal_field": "value",
            "malicious\"; DROP TABLE rules; --": "exploit"
        }
        self.db.save_rules([malicious_rule])

        # Check columns
        cols = self.db.get_columns()
        # The malicious field should be sanitized
        sanitized_name = "maliciousDROPTABLErules"
        self.assertIn(sanitized_name, cols)

        # Verify rules table still exists (injection failed)
        data, _ = self.db.search_rules("")
        self.assertTrue(len(data) > 0)

if __name__ == "__main__":
    unittest.main()
