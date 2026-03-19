import csv
import json
import os
import xml.etree.ElementTree as ET

def csv_to_json_rules(filepath):
    """
    Converts a specialized Wazuh CSV into a list of rule dictionaries.
    Handles nested JSON in 'Details', 'Groups', and compliance columns.
    Generates a basic raw_xml for database compatibility.
    """
    rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().lstrip(': ')
            lines = content.splitlines()
            if not lines:
                 return []

            reader = csv.DictReader(lines)

            for row in reader:
                rule_id = row.get("ID")
                if not rule_id:
                    continue

                rule = {
                    "rule_id": rule_id,
                    "level": row.get("Level"),
                    "description": row.get("Description"),
                    "filename": row.get("File"),
                    "relative_path": os.path.join(row.get("relative_dirname", ""), row.get("File", ""))
                }

                # Parse Groups
                groups_str = row.get("Groups", "[]")
                try:
                    groups = json.loads(groups_str)
                    if isinstance(groups, list) and groups:
                        rule["group"] = ", ".join(groups)
                except:
                    rule["group"] = groups_str if groups_str != "[]" and groups_str is not None else ""

                # Build XML
                rule_elem = ET.Element("rule")
                rule_elem.set("id", str(rule_id))
                if rule["level"]:
                    rule_elem.set("level", str(rule["level"]))

                if rule["description"]:
                    desc = ET.SubElement(rule_elem, "description")
                    desc.text = rule["description"]

                # Parse Details
                details_str = row.get("Details", "{}")
                try:
                    # Clean up escaping if it's double-serialized
                    if details_str.startswith('"') and details_str.endswith('"'):
                         details_str = json.loads(details_str)

                    details = json.loads(details_str)
                    if isinstance(details, dict):
                        for k, v in details.items():
                            if isinstance(v, list):
                                for item in v:
                                    child = ET.SubElement(rule_elem, k)
                                    if isinstance(item, dict):
                                        for sk, sv in item.items():
                                            if sk == "pattern": child.text = str(sv)
                                            else: child.set(sk, str(sv))
                                    else:
                                        child.text = str(item)
                            elif isinstance(v, dict):
                                child = ET.SubElement(rule_elem, k)
                                for sk, sv in v.items():
                                    if sk == "pattern": child.text = str(sv)
                                    else: child.set(sk, str(sv))
                            else:
                                child = ET.SubElement(rule_elem, k)
                                child.text = str(v)
                except Exception as e:
                    print(f"Warning: Details parsing failed for ID {rule_id}: {e}")

                # Parse Compliance Columns
                compliance_cols = ["pci_dss", "gpg13", "GDPR", "HIPAA", "nist_800_53", "tsc", "mitre"]
                for col in compliance_cols:
                    val_str = row.get(col, "[]")
                    try:
                        if val_str.startswith('"') and val_str.endswith('"'):
                             val_str = json.loads(val_str)

                        vals = json.loads(val_str)
                        if isinstance(vals, list):
                            for val in vals:
                                child = ET.SubElement(rule_elem, col)
                                child.text = str(val)
                        else:
                            child = ET.SubElement(rule_elem, col)
                            child.text = str(vals)
                    except:
                        if val_str and val_str != "[]" and val_str is not None:
                            child = ET.SubElement(rule_elem, col)
                            child.text = val_str

                rule["raw_xml"] = ET.tostring(rule_elem, encoding='unicode')
                rules.append(rule)

    except Exception as e:
        print(f"Error in advanced CSV import: {e}")
        raise e

    return rules
