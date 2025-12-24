import os
import sqlite3
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk

# Configuration
DB_NAME = "wazuh_rules_v2.db"

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Table to track file states
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_states (
                    relative_path TEXT PRIMARY KEY,
                    file_hash TEXT,
                    last_scanned TIMESTAMP
                )
            """)
            # Base rules table - we'll add columns dynamically
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    is_rule INTEGER DEFAULT 0,
                    filename TEXT,
                    relative_path TEXT
                )
            """)
            conn.commit()

    def get_columns(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(rules)")
            return [info[1] for info in cursor.fetchall()]

    def ensure_column(self, column_name):
        columns = self.get_columns()
        if column_name not in columns:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                # Use double quotes for column names to handle reserved words or spaces
                cursor.execute(f'ALTER TABLE rules ADD COLUMN "{column_name}" TEXT')
                conn.commit()

    def save_rules(self, rules_data):
        if not rules_data:
            return
        
        # Ensure all columns exist
        all_keys = set()
        for rule in rules_data:
            all_keys.update(rule.keys())
        
        for key in all_keys:
            self.ensure_column(key)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Group by relative_path to delete once per file
            paths_to_clear = {rule['relative_path'] for rule in rules_data}
            for path in paths_to_clear:
                cursor.execute("DELETE FROM rules WHERE relative_path = ?", (path,))
            
            for rule in rules_data:
                cols = list(rule.keys())
                col_names = '"' + '", "'.join(cols) + '"'
                placeholders = ":" + ", :".join(cols)
                
                cursor.execute(f"INSERT INTO rules ({col_names}) VALUES ({placeholders})", rule)
            conn.commit()

    def update_file_state(self, relative_path, file_hash):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO file_states (relative_path, file_hash, last_scanned)
                VALUES (?, ?, ?)
            """, (relative_path, file_hash, datetime.now().isoformat()))
            conn.commit()

    def get_file_hash(self, relative_path):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_hash FROM file_states WHERE relative_path = ?", (relative_path,))
            result = cursor.fetchone()
            return result[0] if result else None

    def search_rules(self, query_str, target_columns=None):
        columns = self.get_columns()
        if not query_str:
            sql = "SELECT * FROM rules"
            params = []
        else:
            # If target_columns is provided and not empty, search only those
            search_cols = target_columns if target_columns else columns
            search_clause = " OR ".join([f'"{col}" LIKE ?' for col in search_cols])
            sql = f"SELECT * FROM rules WHERE {search_clause}"
            params = [f"%{query_str}%"] * len(search_cols)
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            return cursor.fetchall(), columns

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

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.db = DatabaseManager(DB_NAME)
        
        self.title("Wazuh Rule Manager")
        self.geometry("1400x900")
        
        # Appearance
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="Rule Manager", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.pack(pady=20, padx=20)
        
        self.select_folder_btn = ctk.CTkButton(self.sidebar, text="Select Folder", command=self.select_folder)
        self.select_folder_btn.pack(pady=10, padx=20)
        
        self.scan_btn = ctk.CTkButton(self.sidebar, text="Scan Rules", command=self.scan_rules)
        self.scan_btn.pack(pady=10, padx=20)

        # Search Filters Section
        self.filter_label = ctk.CTkLabel(self.sidebar, text="Search Columns", font=ctk.CTkFont(size=14, weight="bold"))
        self.filter_label.pack(pady=(20, 5), padx=20)
        
        self.scrollable_filters = ctk.CTkScrollableFrame(self.sidebar, label_text="")
        self.scrollable_filters.pack(pady=5, padx=10, fill="both", expand=True)
        self.column_vars = {} # Stores BooleanVars for each column
        
        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stats_frame.pack(pady=20, padx=20, side="bottom", fill="x")
        
        self.stats_label = ctk.CTkLabel(self.stats_frame, text="Rules: 0", font=ctk.CTkFont(size=14))
        self.stats_label.pack(pady=5)
        
        self.files_label = ctk.CTkLabel(self.stats_frame, text="Files: 0", font=ctk.CTkFont(size=12))
        self.files_label.pack(pady=5)

        # Main Area
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Search Bar
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Search (Auto-search while typing)...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.on_search_key)
        
        self.search_btn = ctk.CTkButton(self.search_frame, text="Search", width=100, command=self.refresh_table)
        self.search_btn.pack(side="right")

        # Table (Using standard Treeview with custom styling)
        self.tree_container = ctk.CTkFrame(self.main_frame)
        self.tree_container.grid(row=1, column=0, sticky="nsew")
        
        style = ttk.Style()
        style.theme_use("default")
        
        # Configure fonts and sizes
        table_font = ("Segoe UI", 12)
        header_font = ("Segoe UI", 13, "bold")
        
        style.configure("Treeview", 
                        background="#2b2b2b", 
                        foreground="white", 
                        fieldbackground="#2b2b2b", 
                        borderwidth=0,
                        font=table_font,
                        rowheight=35) 
        
        style.map("Treeview", background=[('selected', '#3a7ebf')])
        
        style.configure("Treeview.Heading", 
                        background="#333333", 
                        foreground="white", 
                        relief="flat",
                        font=header_font)

        self.tree = ttk.Treeview(self.tree_container, selectmode="browse", show="headings")
        self.tree.pack(side="left", fill="both", expand=True)

        self.scrollbar = ctk.CTkScrollbar(self.tree_container, orientation="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        self.h_scrollbar = ctk.CTkScrollbar(self.main_frame, orientation="horizontal", command=self.tree.xview)
        self.h_scrollbar.grid(row=2, column=0, sticky="ew")
        self.tree.configure(xscrollcommand=self.h_scrollbar.set)

        self.search_timer = None 
        self.current_folder = ""
        self.refresh_table()

    def on_search_key(self, event):
        if self.search_timer:
            self.after_cancel(self.search_timer)
        self.search_timer = self.after(400, self.refresh_table)

    def update_filter_list(self, columns):
        for widget in self.scrollable_filters.winfo_children():
            widget.destroy()
        
        new_vars = {}
        for col in columns:
            var = tk.BooleanVar(value=False)
            new_vars[col] = var
            cb = ctk.CTkCheckBox(self.scrollable_filters, text=col.replace("_", " ").title(), variable=var, 
                                 command=self.refresh_table, font=ctk.CTkFont(size=11))
            cb.pack(pady=2, padx=5, anchor="w")
        self.column_vars = new_vars

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.current_folder = folder
            messagebox.showinfo("Folder Selected", f"Selected: {folder}")

    def scan_rules(self):
        if not self.current_folder:
            messagebox.showwarning("Warning", "Please select a folder first.")
            return
        
        files_to_scan = []
        for root, _, files in os.walk(self.current_folder):
            for file in files:
                if file.endswith(".xml"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.current_folder)
                    
                    file_hash = get_file_hash(full_path)
                    existing_hash = self.db.get_file_hash(rel_path)
                    
                    if file_hash != existing_hash:
                        files_to_scan.append((full_path, rel_path, file_hash))

        if not files_to_scan:
            messagebox.showinfo("Scan Complete", "No changes detected. Database is up to date.")
            return

        for full_path, rel_path, f_hash in files_to_scan:
            rules = parse_wazuh_xml(full_path, self.current_folder)
            self.db.save_rules(rules)
            self.db.update_file_state(rel_path, f_hash)

        self.refresh_table()
        messagebox.showinfo("Scan Complete", f"Processed {len(files_to_scan)} files.")

    def refresh_table(self):
        selected_cols = [col for col, var in self.column_vars.items() if var.get()]
        search_term = self.search_entry.get()
        data, columns = self.db.search_rules(search_term, target_columns=selected_cols)
        
        if set(columns) != set(self.column_vars.keys()):
            self.update_filter_list(columns)

        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = columns
        for col in columns:
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=200, minwidth=100, stretch=False) 

        def insert_batch(start_idx):
            if not self.tree.winfo_exists(): return
            end_idx = min(start_idx + 150, len(data))
            for i in range(start_idx, end_idx):
                self.tree.insert("", "end", values=data[i])
            
            if end_idx < len(data):
                self.after(10, lambda: insert_batch(end_idx))
            else:
                self.update_stats(len(data))

        insert_batch(0)

    def update_stats(self, rule_count):
        self.stats_label.configure(text=f"Rules: {rule_count}")
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM file_states")
            file_count = cursor.fetchone()[0]
            self.files_label.configure(text=f"Files: {file_count}")

if __name__ == "__main__":
    app = App()
    app.mainloop()
