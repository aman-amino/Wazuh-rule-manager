import unittest
import os
import tempfile
from wazuh_manager.parser import parse_wazuh_xml, get_file_hash, parse_rules_from_csv, save_rules_to_xml, create_rule_xml

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
            self.assertEqual(rule["rule.level"], "5")

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

    def test_csv_parsing(self):
        csv_content = "rule_id,level,description,filename\n100002,7,Test CSV Rule,test.xml"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
            tmp.write(csv_content)
            tmp_path = tmp.name

        try:
            rules = parse_rules_from_csv(tmp_path)
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0]["rule_id"], "100002")
            self.assertEqual(rules[0]["level"], "7")
        finally:
            os.remove(tmp_path)

    def test_save_rules_to_xml(self):
        rules = [
            {"rule_id": "200001", "level": "3", "description": "Multi 1", "group": "g1", "raw_xml": '<rule id="200001" level="3"><description>Multi 1</description></rule>'},
            {"rule_id": "200002", "level": "10", "description": "Multi 2", "group": "g1", "raw_xml": '<rule id="200002" level="10"><description>Multi 2</description></rule>'},
            {"rule_id": "200003", "level": "5", "description": "Multi 3", "group": "g2", "raw_xml": '<rule id="200003" level="5"><description>Multi 3</description></rule>'}
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = os.path.join(tmpdir, "multi.xml")
            save_rules_to_xml(rules, xml_path)

            # Now parse it back
            parsed = parse_wazuh_xml(xml_path, tmpdir)
            self.assertEqual(len(parsed), 3)
            ids = [r["rule_id"] for r in parsed]
            self.assertIn("200001", ids)
            self.assertIn("200002", ids)
            self.assertIn("200003", ids)

    def test_multi_value_xml(self):
        # We now prioritize raw_xml, so testing creation without it
        rule_data = {"rule_id": "300001", "rule.level": "5", "info1": "link1", "info2": "link2"}
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = os.path.join(tmpdir, "multi_val.xml")
            create_rule_xml(rule_data, xml_path)

            with open(xml_path, 'r') as f:
                content = f.read()
                self.assertIn("<info>link1</info>", content)
                self.assertIn("<info>link2</info>", content)

if __name__ == "__main__":
    unittest.main()
