import unittest
import os
import tempfile
from wazuh_manager.parser import parse_wazuh_xml, get_file_hash

class TestParser(unittest.TestCase):
    def test_parse_wazuh_xml(self):
        xml_content = """
<group name="test_group">
  <rule id="100001" level="5">
    <description>Test description</description>
    <match>test match</match>
  </rule>
</group>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = os.path.join(tmpdir, "test_rule.xml")
            with open(xml_path, "w") as f:
                f.write(xml_content)

            rules = parse_wazuh_xml(xml_path, tmpdir)
            self.assertEqual(len(rules), 1)
            rule = rules[0]
            self.assertEqual(rule["rule_id"], "100001")
            self.assertEqual(rule["group"], "test_group")
            self.assertEqual(rule["description"], "Test description")
            self.assertEqual(rule["match"], "test match")

    def test_get_file_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test data")
            tmp_path = tmp.name

        try:
            h1 = get_file_hash(tmp_path)
            h2 = get_file_hash(tmp_path)
            self.assertEqual(h1, h2)

            with open(tmp_path, "wb") as f:
                f.write(b"new data")

            h3 = get_file_hash(tmp_path)
            self.assertNotEqual(h1, h3)
        finally:
            os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
