import unittest
import os
import tempfile
from wazuh_manager.advanced_importer import csv_to_json_rules

class TestAdvancedImporter(unittest.TestCase):
    def test_csv_to_json_rules(self):
        csv_data = """: File,relative_dirname,ID,Level,Status,Details,pci_dss,gpg13,GDPR,HIPAA,nist_800_53,tsc,mitre,Groups,Description
0345-netscaler_rules.xml,ruleset/rules,80127,3,enabled,"{""if_sid"":""80100"",""match"":{""pattern"":""APPFW APPFW_STARTURL""}}","[""1.4"",""6.5""]","[""3.5""]","[""IV_35.7.d""]","[""164.312.a.1""]","[""SC.7""]","[""CC6.7""]",[],"[""netscaler-appfw"",""netscaler""]",Netscaler: Firewall violation
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
            tmp.write(csv_data)
            tmp_path = tmp.name

        try:
            rules = csv_to_json_rules(tmp_path)
            self.assertEqual(len(rules), 1)
            rule = rules[0]
            self.assertEqual(rule["rule_id"], "80127")
            self.assertEqual(rule["level"], "3")
            self.assertEqual(rule["description"], "Netscaler: Firewall violation")
            self.assertEqual(rule["filename"], "0345-netscaler_rules.xml")
            self.assertEqual(rule["group"], "netscaler-appfw, netscaler")
            self.assertEqual(rule["match"], "APPFW APPFW_STARTURL")
            self.assertEqual(rule["pci_dss"], "1.4, 6.5")
            self.assertEqual(rule["GDPR"], "IV_35.7.d")
        finally:
            os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
