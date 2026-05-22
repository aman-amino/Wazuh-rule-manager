import os
import hashlib
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as det
import re
import csv

def _parse_multi_root_xml(filepath):
    """Parses an XML file that might have multiple root elements by wrapping them."""
    with open(filepath, 'r', encoding='utf-8') as f:
        xml_content = f.read()

    # Remove XML declaration if present to avoid conflicts when wrapping
    xml_content = re.sub(r'<\?xml.*?\?>', '', xml_content)
    wrapped_xml = f"<root>{xml_content}</root>"
    return det.fromstring(wrapped_xml)

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
            rule_raw_xml = ET.tostring(elem, encoding='unicode').strip()
            rule_data = {
                "rule_id": elem.attrib.get("id"),
                "is_rule": 1,
                "filename": filename,
                "relative_path": rel_path,
                "raw_xml": rule_raw_xml
            }
            if group_to_use:
                rule_data["group"] = group_to_use

            # New naming convention: tag.attr
            for attr, val in elem.attrib.items():
                if attr != "id":
                    rule_data[f"rule.{attr}"] = val

            # Keep track of tag counts for indexing
            tag_counts = {}
            for child in elem:
                tag_counts[child.tag] = tag_counts.get(child.tag, 0) + 1

            current_counts = {}
            for child in elem:
                tag = child.tag
                current_counts[tag] = current_counts.get(tag, 0) + 1

                # Determine prefix: tag1, tag2 or just tag
                if tag_counts[tag] > 1:
                    prefix = f"{tag}{current_counts[tag]}"
                else:
                    prefix = tag

                # Content
                if child.text and child.text.strip():
                    rule_data[prefix] = child.text.strip()

                # Attributes: tag.attr or tagN.attr
                for c_attr, c_val in child.attrib.items():
                    rule_data[f"{prefix}.{c_attr}"] = c_val

                # Handle nested elements (one level deep for now, e.g. <mitre><id>...</id></mitre>)
                for subchild in child:
                    subtag = subchild.tag
                    if subchild.text and subchild.text.strip():
                        rule_data[f"{prefix}.{subtag}"] = subchild.text.strip()
                    for sc_attr, sc_val in subchild.attrib.items():
                        rule_data[f"{prefix}.{subtag}.{sc_attr}"] = sc_val

            rules_found.append(rule_data)

        for child in elem:
            if elem.tag != "rule":
                process_element(child, group_to_use)

    process_element(root, None)
    return rules_found

def create_rule_xml(rule_data, filepath):
    """Creates a new Wazuh XML rule file. Prioritizes raw_xml if available."""
    if rule_data.get("raw_xml"):
        try:
            # Validate it's proper XML fragment
            rule_elem = det.fromstring(rule_data["raw_xml"])

            # Wrap in group if group is specified
            root = ET.Element("group")
            if rule_data.get("group"):
                root.set("name", rule_data["group"])
            root.append(rule_elem)

            tree = ET.ElementTree(root)
            if hasattr(ET, "indent"):
                ET.indent(tree, space="  ", level=0)
            tree.write(filepath, encoding="utf-8", xml_declaration=True)
            return
        except Exception as e:
            print(f"Warning: raw_xml invalid, falling back to field reconstruction: {e}")

    # Fallback reconstruction logic (simplified, assuming user primarily uses raw_xml editor now)
    root = ET.Element("group")
    if rule_data.get("group"):
        root.set("name", rule_data["group"])

    rule = ET.SubElement(root, "rule")
    rule.set("id", rule_data["rule_id"])

    # This part is complex due to indexed fields,
    # but the primary goal now is the raw_xml editor.
    # We will implement a basic version.
    for key, value in rule_data.items():
        if "." not in key and key not in ["rule_id", "group", "id", "is_rule", "filename", "relative_path", "raw_xml", "cloned_from"]:
            # Check if it's an indexed tag (e.g. field1, field2)
            match = re.match(r'^([a-z_]+)(\d+)$', key)
            tag = match.group(1) if match else key

            child = ET.SubElement(rule, tag)
            child.text = str(value)

            # Look for attributes for this tag
            attr_prefix = f"{key}."
            for a_key, a_val in rule_data.items():
                if a_key.startswith(attr_prefix):
                    attr_name = a_key[len(attr_prefix):]
                    if "." not in attr_name: # Simple attribute
                        child.set(attr_name, str(a_val))

    tree = ET.ElementTree(root)
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ", level=0)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)

def update_rule_xml(rule_id, updated_data, filepath):
    """Updates a rule in an XML file. Prioritizes raw_xml if provided."""
    root = _parse_multi_root_xml(filepath)
    rules = root.findall(".//rule")
    target_rule = None
    target_idx = -1
    parent_map = {c: p for p in root.iter() for c in p}

    for i, r in enumerate(rules):
        if r.attrib.get("id") == str(rule_id):
            target_rule = r
            break

    if target_rule is None:
        raise ValueError(f"Rule with ID {rule_id} not found in {filepath}")

    if updated_data.get("raw_xml"):
        try:
            new_rule_elem = det.fromstring(updated_data["raw_xml"])
            parent = parent_map[target_rule]
            # Find the actual index in parent children
            for idx, child in enumerate(parent):
                if child == target_rule:
                    parent[idx] = new_rule_elem
                    break
            _write_multi_root_xml(root, filepath)
            return
        except Exception as e:
            print(f"Error updating with raw_xml: {e}")
            # Fall back to attribute update

    # Attribute update fallback
    if updated_data.get("rule.level"):
        target_rule.set("level", updated_data["rule.level"])
    elif updated_data.get("level"):
         target_rule.set("level", updated_data["level"])

    # This fallback is less important now that we have raw_xml editing
    for key, value in updated_data.items():
        if "." not in key and key not in ["rule_id", "group", "id", "is_rule", "filename", "relative_path", "raw_xml"]:
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

                if not root.findall(".//rule"):
                    os.remove(filepath)
                else:
                    _write_multi_root_xml(root, filepath)
                return True
    except Exception as e:
        print(f"Error deleting rule {rule_id} from {filepath}: {e}")
    return False

def parse_rules_from_csv(filepath):
    rules = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rule = {k: v for k, v in row.items() if v}
                if 'rule_id' in rule:
                    rules.append(rule)
    except Exception as e:
        print(f"Error parsing CSV {filepath}: {e}")
    return rules

def save_rules_to_xml(rules_data, filepath):
    groups = {}
    for rule_data in rules_data:
        g_name = rule_data.get("group", "default")
        if g_name not in groups:
            groups[g_name] = []
        groups[g_name].append(rule_data)

    root = ET.Element("root")

    for g_name, rules in groups.items():
        group_elem = ET.SubElement(root, "group")
        if g_name != "default":
            group_elem.set("name", g_name)

        for r_data in rules:
            if r_data.get("raw_xml"):
                try:
                    rule_elem = det.fromstring(r_data["raw_xml"])
                    group_elem.append(rule_elem)
                    continue
                except:
                    pass

            rule = ET.SubElement(group_elem, "rule")
            rule.set("id", str(r_data.get("rule_id")))

            # Simple fallback reconstruction
            for key, value in r_data.items():
                 if "." not in key and key not in ["rule_id", "group", "id", "is_rule", "filename", "relative_path", "raw_xml", "cloned_from"]:
                     child = ET.SubElement(rule, key)
                     child.text = str(value)

    _write_multi_root_xml(root, filepath)
