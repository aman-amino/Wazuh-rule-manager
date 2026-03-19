import csv
import json
import os
import xml.etree.ElementTree as ET
from wazuh_manager.parser import _write_multi_root_xml

def csv_to_json_rules(filepath, db_columns=None):
    """
    Converts a specialized Wazuh CSV into a list of rule dictionaries (JSON-like).
    Maps CSV headers dynamically to known database columns if provided.
    """
    rules = []
    # Standard mapping for common headers
    header_map = {
        "ID": "rule_id",
        "Level": "level",
        "Description": "description",
        "File": "filename",
        "relative_dirname": "relative_path",
        "Groups": "group"
    }

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().lstrip(': ')
            lines = content.splitlines()
            if not lines: return []

            # Clean header line (remove extra colons or spaces)
            header_line = lines[0].lstrip(': ')
            lines[0] = header_line

            reader = csv.DictReader(lines)

            for row in reader:
                rule = {}
                for csv_key, val in row.items():
                    if not csv_key: continue
                    target_key = header_map.get(csv_key, csv_key) # Preserve case for compliance like GDPR
                    rule[target_key] = val

                # Fix relative_path
                if "relative_path" in rule and "filename" in rule:
                    rule["relative_path"] = os.path.join(rule["relative_path"], rule["filename"])

                # Handle 'Details' JSON
                details_key = next((k for k in rule if k.lower() == "details"), None)
                if details_key and rule[details_key]:
                    try:
                        details = json.loads(rule[details_key])
                        for k, v in details.items():
                            if isinstance(v, dict) and "pattern" in v: rule[k] = v["pattern"]
                            else: rule[k] = str(v)
                        del rule[details_key]
                    except: pass

                # Handle JSON lists (Compliance, Groups)
                for k, v in list(rule.items()):
                    if isinstance(v, str) and v.startswith("[") and v.endswith("]"):
                        try:
                            vals = json.loads(v)
                            if isinstance(vals, list): rule[k] = ", ".join(vals)
                        except: pass

                rule = {k: v for k, v in rule.items() if v and v != "None" and v != "[]" and v != "{}"}
                if rule.get("rule_id"): rules.append(rule)

    except Exception as e:
        print(f"Error in advanced CSV import: {e}")
        raise e
    return rules

def json_rules_to_xml(rules_data, output_filepath):
    from wazuh_manager.parser import save_rules_to_xml
    save_rules_to_xml(rules_data, output_filepath)
