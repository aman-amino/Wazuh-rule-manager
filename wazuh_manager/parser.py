import os
import hashlib
import xml.etree.ElementTree as ET

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
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return []

    rules_found = []

    # Propagate group name if root is <group>
    root_group = None
    if root.tag == "group":
        root_group = root.attrib.get("name")

    def process_element(elem, current_group):
        # Propagation logic: if we hit a group tag, it updates the group context
        # But for Wazuh, <group> tags wrap rules.
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

            # Add other attributes from <rule> tag
            for attr, val in elem.attrib.items():
                if attr != "id":
                    rule_data[f"rule_{attr}"] = val

            # Process children of <rule>
            for child in elem:
                tag_name = child.tag
                tag_value = child.text.strip() if child.text else ""

                # Special handling for nested tags within rule
                if tag_name in rule_data:
                    # If multiple tags like <match>, concatenate values
                    if rule_data[tag_name] and tag_value:
                        rule_data[tag_name] = f"{rule_data[tag_name]}, {tag_value}"
                    elif tag_value:
                        rule_data[tag_name] = tag_value
                else:
                    rule_data[tag_name] = tag_value

                # Capture child attributes
                for c_attr, c_val in child.attrib.items():
                    attr_col = f"{tag_name}_{c_attr}"
                    rule_data[attr_col] = c_val

            rules_found.append(rule_data)

        # Recursively process children
        for child in elem:
            # If the current element is a rule, we've already handled its children as tags
            # unless there's a nested structure we didn't expect.
            if elem.tag != "rule":
                process_element(child, group_to_use)

    process_element(root, root_group)
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
        if key not in ["rule_id", "level", "group"] and value:
            child = ET.SubElement(rule, key)
            child.text = value

    tree = ET.ElementTree(root)
    # Wazuh rules often have a specific structure, here we just use basic formatting
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ", level=0)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)

def delete_rule_from_xml(rule_id, filepath):
    """
    Deletes a rule with the given ID from the XML file.
    If the file becomes empty (no rules left), it handles it accordingly.
    """
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()

        # Find the rule to delete
        rules = root.findall(".//rule")
        target_rule = None

        # Build a parent map
        parent_map = {c: p for p in root.iter() for c in p}

        for r in rules:
            if r.attrib.get("id") == str(rule_id):
                target_rule = r
                break

        if target_rule is not None:
            parent = parent_map.get(target_rule)
            if parent is not None:
                parent.remove(target_rule)

                # If the root is now empty, we might keep it or delete it.
                # For simplicity, we just save the modified tree.
                if hasattr(ET, "indent"):
                    ET.indent(tree, space="  ", level=0)
                tree.write(filepath, encoding="utf-8", xml_declaration=True)
                return True
    except Exception as e:
        print(f"Error deleting rule {rule_id} from {filepath}: {e}")
    return False

def update_rule_xml(rule_id, updated_data, filepath):
    """
    Updates an existing rule in an XML file.
    """
    tree = ET.parse(filepath)
    root = tree.getroot()

    # Support both flat and grouped rules
    rules = root.findall(".//rule")
    target_rule = None
    for r in rules:
        if r.attrib.get("id") == str(rule_id):
            target_rule = r
            break

    if target_rule is None:
        raise ValueError(f"Rule with ID {rule_id} not found in {filepath}")

    # Update attributes
    if updated_data.get("level"):
        target_rule.set("level", updated_data["level"])

    # Update children
    for key, value in updated_data.items():
        if key not in ["rule_id", "level", "group"]:
            child = target_rule.find(key)
            if child is not None:
                if value:
                    child.text = value
                else:
                    target_rule.remove(child)
            elif value:
                child = ET.SubElement(target_rule, key)
                child.text = value

    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ", level=0)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
