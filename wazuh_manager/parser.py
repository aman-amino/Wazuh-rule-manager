import os
import hashlib
import xml.etree.ElementTree as ET
import re
import csv

def _parse_multi_root_xml(filepath):
    """Parses an XML file that might have multiple root elements by wrapping them."""
    with open(filepath, 'r', encoding='utf-8') as f:
        xml_content = f.read()

    # Remove XML declaration if present to avoid conflicts when wrapping
    xml_content = re.sub(r'<\?xml.*?\?>', '', xml_content)
    wrapped_xml = f"<root>{xml_content}</root>"
    return ET.fromstring(wrapped_xml)

def _write_multi_root_xml(root, filepath):
    """Writes back a multi-root structure by stripping the wrapper."""
    # Create a string representation of the root
    tree = ET.ElementTree(root)
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ", level=0)

    # Get the inner XML (children of <root>)
    inner_xmls = []
    for child in root:
        inner_xmls.append(ET.tostring(child, encoding='unicode'))

    final_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + "\n".join(inner_xmls)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(final_xml)

def get_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def parse_wazuh_xml(filepath, base_dir):
    rel_path = os.path.relpath(filepath, base_dir)
    filename = os.path.basename(filepath)

    try:
        root = _parse_multi_root_xml(filepath)
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return []

    rules_found = []

    def process_element(elem, current_group):
        group_to_use = current_group
        if elem.tag == "group":
            group_to_use = elem.attrib.get("name") or current_group

        if elem.tag == "rule":
            rule_data = {
                "rule_id": elem.attrib.get("id"),
                "is_rule": 1,
                "filename": filename,
                "relative_path": rel_path
            }
            if group_to_use:
                rule_data["group"] = group_to_use

            for attr, val in elem.attrib.items():
                if attr != "id":
                    rule_data[attr] = val

            for child in elem:
                tag_name = child.tag
                tag_value = child.text.strip() if child.text else ""

                if tag_name in rule_data:
                    if rule_data[tag_name] and tag_value:
                        rule_data[tag_name] = f"{rule_data[tag_name]}, {tag_value}"
                    elif tag_value:
                        rule_data[tag_name] = tag_value
                else:
                    rule_data[tag_name] = tag_value

                for c_attr, c_val in child.attrib.items():
                    attr_col = f"{tag_name}_{c_attr}"
                    rule_data[attr_col] = c_val

            rules_found.append(rule_data)

        for child in elem:
            if elem.tag != "rule":
                process_element(child, group_to_use)

    process_element(root, None)
    return rules_found

def create_rule_xml(rule_data, filepath):
    """
    Creates a new Wazuh XML rule file from the provided data.
    """
    root = ET.Element("group")
    if rule_data.get("group"):
        root.set("name", rule_data["group"])

    rule = ET.SubElement(root, "rule")
    rule.set("id", rule_data["rule_id"])
    if rule_data.get("level"):
        rule.set("level", rule_data["level"])

    for key, value in rule_data.items():
        if key not in ["rule_id", "level", "group", "id", "is_rule", "filename", "relative_path", "cloned_from"] and value:
            # Handle potential multi-value fields if they were joined by comma
            if isinstance(value, str) and ", " in value:
                parts = value.split(", ")
                for part in parts:
                    child = ET.SubElement(rule, key)
                    child.text = part
            else:
                child = ET.SubElement(rule, key)
                child.text = str(value)

    tree = ET.ElementTree(root)
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ", level=0)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)

def delete_rule_from_xml(rule_id, filepath):
    try:
        root = _parse_multi_root_xml(filepath)
        rules = root.findall(".//rule")
        target_rule = None
        parent_map = {c: p for p in root.iter() for c in p}

        for r in rules:
            if r.attrib.get("id") == str(rule_id):
                target_rule = r
                break

        if target_rule is not None:
            parent = parent_map.get(target_rule)
            if parent is not None:
                parent.remove(target_rule)

                # If no rules left in file, delete the file itself
                if not root.findall(".//rule"):
                    os.remove(filepath)
                else:
                    _write_multi_root_xml(root, filepath)
                return True
    except Exception as e:
        print(f"Error deleting rule {rule_id} from {filepath}: {e}")
    return False

def update_rule_xml(rule_id, updated_data, filepath):
    root = _parse_multi_root_xml(filepath)
    rules = root.findall(".//rule")
    target_rule = None
    for r in rules:
        if r.attrib.get("id") == str(rule_id):
            target_rule = r
            break

    if target_rule is None:
        raise ValueError(f"Rule with ID {rule_id} not found in {filepath}")

    if updated_data.get("level"):
        target_rule.set("level", updated_data["level"])

    for key, value in updated_data.items():
        if key not in ["rule_id", "level", "group", "id", "is_rule", "filename", "relative_path"]:
            # Simple update/replace logic
            child = target_rule.find(key)
            if child is not None:
                if value:
                    child.text = str(value)
                else:
                    target_rule.remove(child)
            elif value:
                child = ET.SubElement(target_rule, key)
                child.text = str(value)

    _write_multi_root_xml(root, filepath)

def parse_rules_from_csv(filepath):
    """Parses rules from a CSV file."""
    rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Clean up empty values
                rule = {k: v for k, v in row.items() if v}
                if 'rule_id' in rule:
                    rules.append(rule)
    except Exception as e:
        print(f"Error parsing CSV {filepath}: {e}")
    return rules

def save_rules_to_xml(rules_data, filepath):
    """Saves multiple rules to a single XML file, grouped by 'group' if possible."""
    # Group rules by their group attribute
    groups = {}
    for rule_data in rules_data:
        g_name = rule_data.get("group", "default")
        if g_name not in groups:
            groups[g_name] = []
        groups[g_name].append(rule_data)

    root = ET.Element("root") # Temporary root for multi-group/multi-rule

    for g_name, rules in groups.items():
        group_elem = ET.SubElement(root, "group")
        if g_name != "default":
            group_elem.set("name", g_name)

        for r_data in rules:
            rule = ET.SubElement(group_elem, "rule")
            rule.set("id", str(r_data.get("rule_id")))
            if r_data.get("level"):
                rule.set("level", str(r_data["level"]))

            for key, value in r_data.items():
                if key not in ["rule_id", "level", "group", "id", "is_rule", "filename", "relative_path", "cloned_from"] and value:
                    if isinstance(value, str) and ", " in value:
                        parts = value.split(", ")
                        for part in parts:
                            child = ET.SubElement(rule, key)
                            child.text = part
                    else:
                        child = ET.SubElement(rule, key)
                        child.text = str(value)

    _write_multi_root_xml(root, filepath)
