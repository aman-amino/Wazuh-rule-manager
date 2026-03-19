import csv
import json
import os

def csv_to_json_rules(filepath):
    """
    Converts a specialized Wazuh CSV into a list of rule dictionaries.
    Handles nested JSON in 'Details', 'Groups', and compliance columns.
    """
    rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Skip potential leading colon in header if it exists (from user example ": File,...")
            content = f.read().lstrip(': ')
            f.seek(0)

            # Use DictReader with the cleaned content if necessary,
            # but standard csv.DictReader might handle the space after colon poorly.
            # Let's just read and re-parse.
            lines = content.splitlines()
            reader = csv.DictReader(lines)

            for row in reader:
                rule = {
                    "rule_id": row.get("ID"),
                    "level": row.get("Level"),
                    "description": row.get("Description"),
                    "filename": row.get("File"),
                    "relative_path": os.path.join(row.get("relative_dirname", ""), row.get("File", ""))
                }

                # Parse Groups
                groups_str = row.get("Groups", "[]")
                try:
                    groups = json.loads(groups_str)
                    if groups:
                        rule["group"] = ", ".join(groups)
                except:
                    rule["group"] = groups_str if groups_str != "[]" else ""

                # Parse Details (Flattening)
                details_str = row.get("Details", "{}")
                try:
                    details = json.loads(details_str)
                    for k, v in details.items():
                        if isinstance(v, dict):
                            # Handle common patterns like {"match": {"pattern": "..."}} -> match: "..."
                            if k == "match" and "pattern" in v:
                                rule[k] = v["pattern"]
                            elif k == "regex" and "pattern" in v:
                                rule[k] = v["pattern"]
                            else:
                                # For other dicts, maybe just stringify or pick first value
                                rule[k] = str(v)
                        else:
                            rule[k] = str(v)
                except:
                    pass

                # Parse Compliance Columns
                compliance_cols = ["pci_dss", "gpg13", "GDPR", "HIPAA", "nist_800_53", "tsc", "mitre"]
                for col in compliance_cols:
                    val_str = row.get(col, "[]")
                    try:
                        vals = json.loads(val_str)
                        if vals:
                            rule[col] = ", ".join(vals)
                    except:
                        if val_str and val_str != "[]":
                            rule[col] = val_str

                # Final cleanup: remove None or empty
                rule = {k: v for k, v in rule.items() if v and v != "None"}
                if rule.get("rule_id"):
                    rules.append(rule)

    except Exception as e:
        print(f"Error in advanced CSV import: {e}")
        raise e

    return rules
