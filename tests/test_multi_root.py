import unittest
import os
import tempfile
import xml.etree.ElementTree as ET
from wazuh_manager.parser import parse_wazuh_xml, update_rule_xml, delete_rule_from_xml

class TestMultiRootXML(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.xml_path = os.path.join(self.test_dir.name, "multi.xml")
        self.xml_content = """<group name="group1">
  <rule id="1001" level="5">
    <description>Rule 1</description>
  </rule>
</group>
<group name="group2">
  <rule id="1002" level="10">
    <description>Rule 2</description>
  </rule>
</group>
"""
        with open(self.xml_path, 'w') as f:
            f.write(self.xml_content)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_parse_multi_root(self):
        rules = parse_wazuh_xml(self.xml_path, self.test_dir.name)
        self.assertEqual(len(rules), 2)
        ids = [r['rule_id'] for r in rules]
        self.assertIn("1001", ids)
        self.assertIn("1002", ids)

        # Verify group propagation
        r1 = next(r for r in rules if r['rule_id'] == "1001")
        self.assertEqual(r1['group'], "group1")
        r2 = next(r for r in rules if r['rule_id'] == "1002")
        self.assertEqual(r2['group'], "group2")

    def test_update_multi_root(self):
        update_rule_xml("1001", {"level": "7", "description": "Updated Rule 1"}, self.xml_path)
        rules = parse_wazuh_xml(self.xml_path, self.test_dir.name)
        r1 = next(r for r in rules if r['rule_id'] == "1001")
        self.assertEqual(r1['rule_level'], "7")
        self.assertEqual(r1['description'], "Updated Rule 1")

        # Ensure rule 2 is still there
        r2 = next(r for r in rules if r['rule_id'] == "1002")
        self.assertEqual(r2['rule_id'], "1002")

    def test_delete_multi_root(self):
        delete_rule_from_xml("1001", self.xml_path)
        rules = parse_wazuh_xml(self.xml_path, self.test_dir.name)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['rule_id'], "1002")

        # Check file structure - should still have group2
        with open(self.xml_path, 'r') as f:
            content = f.read()
        self.assertIn('group name="group2"', content)
        self.assertNotIn('Rule 1', content)

if __name__ == '__main__':
    unittest.main()
