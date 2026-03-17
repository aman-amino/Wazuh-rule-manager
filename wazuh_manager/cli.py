import os
import argparse
from .database import DatabaseManager
from .parser import get_file_hash, parse_wazuh_xml
from . import DB_NAME

def scan(folder):
    db = DatabaseManager(DB_NAME)
    if not os.path.isdir(folder):
        print(f"Error: {folder} is not a directory.")
        return

    files_to_scan = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".xml"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, folder)

                file_hash = get_file_hash(full_path)
                existing_hash = db.get_file_hash(rel_path)

                if file_hash != existing_hash:
                    files_to_scan.append((full_path, rel_path, file_hash))

    if not files_to_scan:
        print("No changes detected. Database is up to date.")
        return

    for full_path, rel_path, f_hash in files_to_scan:
        rules = parse_wazuh_xml(full_path, folder)
        db.save_rules(rules)
        db.update_file_state(rel_path, f_hash)

    print(f"Scan complete. Processed {len(files_to_scan)} files.")

def search(query, columns=None):
    db = DatabaseManager(DB_NAME)
    data, cols = db.search_rules(query, target_columns=columns)

    if not data:
        print("No rules found.")
        return

    # Simple text output
    print(f"Found {len(data)} rules:")
    for row in data:
        # row is a tuple, we might want to map it to columns for better display
        rule_dict = dict(zip(cols, row))
        print(f"ID: {rule_dict.get('rule_id')} | File: {rule_dict.get('filename')} | Description: {rule_dict.get('description', 'N/A')}")

def run_cli():
    parser = argparse.ArgumentParser(description="Wazuh Rule Manager CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a folder for rules")
    scan_parser.add_argument("folder", help="Path to the rules folder")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search for rules")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("--columns", nargs="+", help="Columns to search in")

    args = parser.parse_args()

    if args.command == "scan":
        scan(args.folder)
    elif args.command == "search":
        search(args.query, args.columns)
    else:
        parser.print_help()
