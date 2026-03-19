import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import os
import csv
from wazuh_manager.parser import parse_wazuh_xml, get_file_hash, create_rule_xml, update_rule_xml, delete_rule_from_xml, save_rules_to_xml
from wazuh_manager.advanced_importer import csv_to_json_rules
from wazuh_manager.database import DatabaseManager
from wazuh_manager import DB_NAME

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager(DB_NAME)
        self.title("Wazuh Rule Manager Dashboard")
        self.geometry("1400x900")

        # Layout Configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="Wazuh Manager", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.pack(pady=(30, 20), padx=20)

        # Action Groups
        self.action_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.action_frame.pack(pady=5, padx=10, fill="x")

        # Folder & Scan
        self.folder_btn = ctk.CTkButton(self.action_frame, text="📁 Select Folder", command=self.select_folder, height=32)
        self.folder_btn.pack(pady=4, padx=10, fill="x")

        self.scan_btn = ctk.CTkButton(self.action_frame, text="🔍 Scan Rules", command=self.scan_rules, height=32)
        self.scan_btn.pack(pady=4, padx=10, fill="x")

        # Rule Operations (Add, Edit, Clone, Delete)
        self.rule_ops_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.rule_ops_frame.pack(pady=5, padx=10, fill="x")

        self.add_btn = ctk.CTkButton(self.rule_ops_frame, text="➕ Add", command=self.add_rule, width=110, height=32)
        self.add_btn.grid(row=0, column=0, pady=4, padx=5)

        self.edit_btn = ctk.CTkButton(self.rule_ops_frame, text="📝 Edit", command=self.edit_rule, width=110, height=32)
        self.edit_btn.grid(row=0, column=1, pady=4, padx=5)

        self.clone_btn = ctk.CTkButton(self.rule_ops_frame, text="👯 Clone", command=self.clone_rule, width=110, height=32)
        self.clone_btn.grid(row=1, column=0, pady=4, padx=5)

        self.delete_btn = ctk.CTkButton(self.rule_ops_frame, text="🗑️ Delete", command=self.delete_rule, width=110, height=32,
                                        fg_color="#d9534f", hover_color="#c9302c")
        self.delete_btn.grid(row=1, column=1, pady=4, padx=5)

        # Data & Tools
        self.tools_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.tools_frame.pack(pady=5, padx=10, fill="x")

        self.dup_btn = ctk.CTkButton(self.tools_frame, text="👯 Show Duplicates", command=self.show_duplicates, height=32)
        self.dup_btn.pack(pady=4, padx=10, fill="x")

        self.export_btn = ctk.CTkButton(self.tools_frame, text="📤 Export CSV", command=self.export_to_csv, height=32)
        self.export_btn.pack(pady=4, padx=10, fill="x")
        self.import_btn = ctk.CTkButton(self.tools_frame, text="📥 Import Rules", command=self.import_rules, height=32)
        self.import_btn.pack(pady=4, padx=10, fill="x")
        self.backup_btn = ctk.CTkButton(self.tools_frame, text="📦 Full Backup", command=self.full_backup, height=32)
        self.backup_btn.pack(pady=4, padx=10, fill="x")
        self.adv_import_btn = ctk.CTkButton(self.tools_frame, text="🚀 Advanced Import", command=self.advanced_import_flow, height=32)
        self.adv_import_btn.pack(pady=4, padx=10, fill="x")

        # Appearance Mode
        self.appearance_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.appearance_frame.pack(pady=5, padx=10, fill="x")
        self.appearance_label = ctk.CTkLabel(self.appearance_frame, text="Appearance:", font=ctk.CTkFont(size=12))
        self.appearance_label.pack(side="left", padx=10)
        self.appearance_menu = ctk.CTkOptionMenu(self.appearance_frame, values=["Dark", "Light", "System"],
                                                 command=self.change_appearance_mode_event, width=120)
        self.appearance_menu.pack(side="right", padx=10)
        self.appearance_menu.set("Dark")

        # Search Filters Section (Filtering of rules)
        self.filter_label = ctk.CTkLabel(self.sidebar, text="Filter by Columns", font=ctk.CTkFont(size=14, weight="bold"))
        self.filter_label.pack(pady=(15, 5), padx=20)

        self.scrollable_filters = ctk.CTkScrollableFrame(self.sidebar, label_text="", height=300)
        self.scrollable_filters.pack(pady=5, padx=10, fill="both", expand=True)
        self.column_vars = {}

        # Stats at the very bottom
        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stats_frame.pack(pady=10, padx=20, side="bottom", fill="x")
        self.progress_bar = ctk.CTkProgressBar(self.stats_frame)
        self.progress_bar.pack(pady=5, fill="x")
        self.progress_bar.set(0)
        self.stats_label = ctk.CTkLabel(self.stats_frame, text="Rules: 0", font=ctk.CTkFont(size=13))
        self.stats_label.pack()
        self.files_label = ctk.CTkLabel(self.stats_frame, text="Files: 0", font=ctk.CTkFont(size=13))
        self.files_label.pack()

        # --- Main Area ---
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Search Bar
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Smart Search (Exact for ID, Pattern for Text)...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(10, 5))
        self.search_entry.bind("<KeyRelease>", self.on_search_key)
        self.clear_btn = ctk.CTkButton(self.search_frame, text="Clear", width=70, fg_color="transparent", border_width=1, command=self.clear_search)
        self.clear_btn.pack(side="left", padx=5)

        # Table
        self.tree_container = ctk.CTkFrame(self.main_frame)
        self.tree_container.grid(row=1, column=0, sticky="nsew", padx=10)
        self.tree = ttk.Treeview(self.tree_container, selectmode="browse", show="headings")
        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar = ctk.CTkScrollbar(self.tree_container, orientation="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # --- Status Panel (Right) ---
        self.status_panel = ctk.CTkFrame(self, width=380)
        self.status_panel.grid(row=0, column=2, sticky="nsew", padx=10, pady=20)
        self.status_panel.grid_propagate(False)

        self.status_scroll = ctk.CTkScrollableFrame(self.status_panel, label_text="Analytics & Details")
        self.status_scroll.pack(fill="both", expand=True, padx=5, pady=5)

        # Analytics sections
        self.level_frame = self.create_analytics_section("Rule Levels Distribution")
        self.range_frame = self.create_analytics_section("ID Range Analysis")

        # Details section
        self.detail_card = ctk.CTkFrame(self.status_scroll, border_width=1, border_color="#444444")
        self.detail_card.pack(fill="x", pady=10, padx=5)
        ctk.CTkLabel(self.detail_card, text="Selected Rule Details", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        self.detail_container = ctk.CTkFrame(self.detail_card, fg_color="transparent")
        self.detail_container.pack(fill="x", padx=10, pady=5)

        self.current_folder = ""
        self.search_timer = None
        self.showing_duplicates = False
        self.sort_column_id = None
        self.sort_reverse = False
        self.refresh_table()

    def create_analytics_section(self, title):
        frame = ctk.CTkFrame(self.status_scroll)
        frame.pack(fill="x", pady=5, padx=5)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=13, weight="bold")).pack(pady=5)
        container = ctk.CTkFrame(frame, fg_color="transparent")
        container.pack(fill="x", padx=10, pady=5)
        return container

    def on_search_key(self, event):
        if self.search_timer: self.after_cancel(self.search_timer)
        self.search_timer = self.after(300, self.refresh_table)

    def clear_search(self):
        self.search_entry.delete(0, tk.END)
        self.refresh_table()

    def sort_column(self, col):
        if self.sort_column_id == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column_id = col
            self.sort_reverse = False

        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]

        # Try to sort numerically if possible
        try:
            l.sort(key=lambda t: float(t[0]), reverse=self.sort_reverse)
        except ValueError:
            l.sort(reverse=self.sort_reverse)

        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        # Update header to show sort direction
        for c in self.tree["columns"]:
            self.tree.heading(c, text=c.replace("_", " ").title())

        suffix = " ↑" if self.sort_reverse else " ↓"
        self.tree.heading(col, text=col.replace("_", " ").title() + suffix)

    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        values = self.tree.item(sel[0])["values"]
        cols = self.tree["columns"]
        rule = dict(zip(cols, values))
        for w in self.detail_container.winfo_children(): w.destroy()
        for f in ["rule_id", "level", "description", "group", "filename"]:
            if f in rule:
                row = ctk.CTkFrame(self.detail_container, fg_color="transparent")
                row.pack(fill="x", pady=2)
                ctk.CTkLabel(row, text=f"{f.replace('_',' ').title()}:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#888888").pack(anchor="w")
                ctk.CTkLabel(row, text=str(rule[f]), wraplength=340, justify="left", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=5)

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

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
            self.scan_rules()

    def scan_rules(self):
        if not self.current_folder:
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

        total_files = len(files_to_scan)
        if total_files > 0:
            self.progress_bar.set(0)
            for i, (full_path, rel_path, f_hash) in enumerate(files_to_scan):
                self.files_label.configure(text=f"Scanning: {i+1}/{total_files}")
                self.progress_bar.set((i + 1) / total_files)
                self.update_idletasks()

                rules = parse_wazuh_xml(full_path, self.current_folder)
                self.db.save_rules(rules)
                self.db.update_file_state(rel_path, f_hash)
            self.progress_bar.set(1)

        self.refresh_table()
        self.update_analytics()

    def refresh_table(self):
        selected_cols = [col for col, var in self.column_vars.items() if var.get()]
        search_term = self.search_entry.get()
        data, columns = self.db.search_rules(search_term, target_columns=selected_cols, show_duplicates=self.showing_duplicates)

        if set(columns) != set(self.column_vars.keys()):
            self.update_filter_list(columns)

        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = columns
        for col in columns:
            self.tree.heading(col, text=col.replace("_", " ").title(), command=lambda _c=col: self.sort_column(_c))
            self.tree.column(col, width=150, minwidth=100, stretch=False)

        # Optimization: Insert in batches
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

    def update_analytics(self):
        # Level Stats
        for w in self.level_frame.winfo_children(): w.destroy()
        for lvl, count in self.db.get_stats_by_level():
            row = ctk.CTkFrame(self.level_frame, fg_color="transparent")
            row.pack(fill="x")
            ctk.CTkLabel(row, text=f"Level {lvl}:", font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(row, text=str(count), font=ctk.CTkFont(size=12, weight="bold")).pack(side="right")

        # Range Stats
        for w in self.range_frame.winfo_children(): w.destroy()
        for r_start, count in self.db.get_stats_by_id_range():
            row = ctk.CTkFrame(self.range_frame, fg_color="transparent")
            row.pack(fill="x")
            ctk.CTkLabel(row, text=f"{r_start}-{r_start+9999}:", font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(row, text=str(count), font=ctk.CTkFont(size=12, weight="bold")).pack(side="right")

    def import_rules(self):
        if not self.current_folder:
            messagebox.showwarning("Warning", "Please select a target folder first.")
            return

        filepath = filedialog.askopenfilename(filetypes=[("CSV or XML files", "*.csv *.xml"), ("CSV files", "*.csv"), ("XML files", "*.xml")])
        if not filepath:
            return

        imported_rules = []
        try:
            if filepath.endswith(".csv"):
                from wazuh_manager.parser import parse_rules_from_csv
                imported_rules = parse_rules_from_csv(filepath)
            elif filepath.endswith(".xml"):
                from wazuh_manager.parser import parse_wazuh_xml
                imported_rules = parse_wazuh_xml(filepath, os.path.dirname(filepath))

            if not imported_rules:
                messagebox.showinfo("Import", "No valid rules found in the selected file.")
                return

            files_to_create = {}
            for rule in imported_rules:
                fname = rule.get("filename") or rule.get("relative_path")
                if not fname or not fname.endswith(".xml"):
                    fname = f"imported_rules_{os.path.basename(filepath).split('.')[0]}.xml"

                if fname not in files_to_create:
                    files_to_create[fname] = []
                files_to_create[fname].append(rule)

            count = 0
            for fname, rules in files_to_create.items():
                dest_path = os.path.join(self.current_folder, os.path.basename(fname))
                save_rules_to_xml(rules, dest_path)
                count += len(rules)

            messagebox.showinfo("Success", f"Successfully imported {count} rules into {len(files_to_create)} files.")
            self.scan_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")

    def advanced_import_flow(self):
        if not self.current_folder:
            messagebox.showwarning("Warning", "Please select a target folder first.")
            return

        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return

        try:
            rules = csv_to_json_rules(filepath, self.db.get_columns())

            if not rules:
                messagebox.showinfo("Advanced Import", "No valid rules found in the CSV.")
                return

            dialog = AdvancedImportDialog(self, rules)
            self.wait_window(dialog)

            if dialog.approved:
                files_to_create = {}
                for rule in rules:
                    fname = rule.get("filename") or rule.get("relative_path")
                    if not fname or not fname.endswith(".xml"):
                        fname = f"adv_imported_{os.path.basename(filepath).split('.')[0]}.xml"

                    if fname not in files_to_create:
                        files_to_create[fname] = []
                    files_to_create[fname].append(rule)

                count = 0
                for fname, rules_group in files_to_create.items():
                    dest_path = os.path.join(self.current_folder, os.path.basename(fname))
                    save_rules_to_xml(rules_group, dest_path)
                    count += len(rules_group)

                messagebox.showinfo("Success", f"Advanced Import complete. Imported {count} rules into {len(files_to_create)} files.")
                self.scan_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Advanced Import failed: {e}")

    def export_to_csv(self):
        selected_cols = [col for col, var in self.column_vars.items() if var.get()]
        search_term = self.search_entry.get()
        data, columns = self.db.search_rules(search_term, target_columns=selected_cols, show_duplicates=self.showing_duplicates)

        if not data:
            messagebox.showinfo("Export", "No results to export.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(data)
            messagebox.showinfo("Success", f"Data exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {e}")

    def full_backup(self):
        data, columns = self.db.search_rules("")
        if not data:
            messagebox.showinfo("Backup", "No rules to backup.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(data)
            messagebox.showinfo("Success", f"Full backup saved to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create backup: {e}")

    def add_rule(self):
        if not self.current_folder:
            messagebox.showwarning("Warning", "Please select a target folder first.")
            return
        cols = self.db.get_columns()
        dialog = RuleDialog(self, title="Add New Rule", columns=cols, db=self.db)
        self.wait_window(dialog)
        if dialog.result:
            fname = f"custom_rule_{dialog.result['rule_id']}.xml"
            create_rule_xml(dialog.result, os.path.join(self.current_folder, fname))
            self.scan_rules()

    def edit_rule(self):
        sel = self.tree.selection()
        if not sel: return
        values = self.tree.item(sel[0])["values"]
        cols = self.tree["columns"]
        rule = dict(zip(cols, values))
        dialog = RuleDialog(self, title="Edit Rule", initial_data=rule, columns=self.db.get_columns(), db=self.db)
        self.wait_window(dialog)
        if dialog.result:
            filepath = os.path.join(self.current_folder, rule["relative_path"])
            try:
                # Save to history before updating
                old_raw = rule.get("raw_xml")
                if old_raw:
                    self.db.add_to_history(rule["rule_id"], rule["relative_path"], old_raw)

                update_rule_xml(rule["rule_id"], dialog.result, filepath)
                messagebox.showinfo("Success", "Rule updated successfully.")
                self.scan_rules()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update rule: {e}")

    def clone_rule(self):
        sel = self.tree.selection()
        if not sel: return
        values = self.tree.item(sel[0])["values"]
        cols = self.tree["columns"]
        rule = dict(zip(cols, values))
        clone = rule.copy()
        clone["rule_id"] = f"{rule['rule_id']}_clone"
        dialog = RuleDialog(self, title="Clone Rule", initial_data=clone, columns=self.db.get_columns(), db=self.db)
        self.wait_window(dialog)
        if dialog.result:
            fname = f"cloned_rule_{dialog.result['rule_id']}.xml"
            create_rule_xml(dialog.result, os.path.join(self.current_folder, fname))
            self.scan_rules()

    def delete_rule(self):
        sel = self.tree.selection()
        if not sel: return
        values = self.tree.item(sel[0])["values"]
        cols = self.tree["columns"]
        rule = dict(zip(cols, values))
        if messagebox.askyesno("Confirm", f"Delete rule {rule['rule_id']}?"):
            try:
                if delete_rule_from_xml(rule["rule_id"], os.path.join(self.current_folder, rule["relative_path"])):
                    self.db.delete_rule(rule["rule_id"], rule["relative_path"])
                    self.scan_rules()
                else:
                    messagebox.showerror("Error", f"Could not find rule {rule['rule_id']} in file.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete rule: {e}")

    def show_duplicates(self):
        self.showing_duplicates = not self.showing_duplicates
        if self.showing_duplicates:
            self.dup_btn.configure(fg_color="orange")
        else:
            self.dup_btn.configure(fg_color=["#3B8ED0", "#1F6AA5"])
        self.refresh_table()

class RuleDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Rule Dialog", initial_data=None, columns=None, db=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("800x900")
        self.result = None
        self.initial_data = initial_data or {}
        self.db = db

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # XML Editor Section (Top)
        self.xml_label = ctk.CTkLabel(self.main_container, text="Raw XML Editor", font=ctk.CTkFont(weight="bold"))
        self.xml_label.pack(side="top", anchor="w", padx=10, pady=(0, 5))

        self.xml_editor = ctk.CTkTextbox(self.main_container, height=300, font=("Courier New", 12))
        self.xml_editor.pack(side="top", fill="x", padx=10, pady=(0, 10))
        if self.initial_data.get("raw_xml"):
            self.xml_editor.insert("1.0", self.initial_data["raw_xml"])

        # Bottom frame for action buttons
        self.button_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.button_frame.pack(side="bottom", fill="x", pady=(0, 10))

        self.save_btn = ctk.CTkButton(self.button_frame, text="Save Rule", command=self.save)
        self.save_btn.pack(side="left", padx=10, pady=10)

        if self.db and self.initial_data.get("rule_id"):
             self.history_btn = ctk.CTkButton(self.button_frame, text="View History", command=self.show_history, fg_color="gray")
             self.history_btn.pack(side="left", padx=10, pady=10)

        self.custom_field_frame = ctk.CTkFrame(self.main_container)
        self.custom_field_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 10))

        self.new_field_entry = ctk.CTkEntry(self.custom_field_frame, placeholder_text="New field name")
        self.new_field_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        self.add_field_btn = ctk.CTkButton(self.custom_field_frame, text="Add Field", width=80, command=self.add_custom_field)
        self.add_field_btn.pack(side="right", padx=5, pady=5)

        self.scrollable_frame = ctk.CTkScrollableFrame(self.main_container, label_text="Rule Attributes (Auto-indexed)")
        self.scrollable_frame.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        self.scrollable_frame.grid_columnconfigure(1, weight=1)

        excluded = ["id", "is_rule", "filename", "relative_path", "raw_xml"]
        self.fields = ["rule_id", "group", "level", "description"]
        if columns:
            for col in columns:
                if col not in excluded and col not in self.fields:
                    self.fields.append(col)

        for key in self.initial_data.keys():
            if key not in excluded and key not in self.fields:
                self.fields.append(key)

        self.entries = {}
        for i, field in enumerate(self.fields):
            self.add_field_row(field, i)

    def add_field_row(self, field, row_idx, value=None):
        display_name = field.replace("_", " ").title()
        label = ctk.CTkLabel(self.scrollable_frame, text=display_name)
        label.grid(row=row_idx, column=0, padx=10, pady=5, sticky="w")

        entry = ctk.CTkEntry(self.scrollable_frame)
        entry.grid(row=row_idx, column=1, padx=10, pady=5, sticky="ew")

        if value is not None:
            entry.insert(0, str(value))
        elif field in self.initial_data:
            entry.insert(0, str(self.initial_data[field]))

        self.entries[field] = entry

    def add_custom_field(self):
        new_field = self.new_field_entry.get().strip().lower().replace(" ", "_")
        if not new_field: return
        if new_field in self.entries:
            messagebox.showwarning("Warning", f"Field '{new_field}' already exists.")
            return
        self.add_field_row(new_field, len(self.entries))
        self.new_field_entry.delete(0, tk.END)

    def show_history(self):
        if not self.db:
            return

        history = self.db.get_history(self.initial_data["rule_id"], self.initial_data["relative_path"])
        if not history:
            messagebox.showinfo("History", "No previous versions found for this rule.")
            return

        HistoryWindow(self, history, self.xml_editor)

    def save(self):
        raw_xml = self.xml_editor.get("1.0", "end").strip()
        if not raw_xml:
            messagebox.showerror("Error", "XML content cannot be empty.")
            return

        try:
            import xml.etree.ElementTree as ET
            ET.fromstring(raw_xml)
        except Exception as e:
            messagebox.showerror("XML Error", f"Invalid XML: {e}")
            return

        self.result = {k: v.get() for k, v in self.entries.items() if v.get()}
        self.result["raw_xml"] = raw_xml
        if not self.result.get("rule_id"):
            messagebox.showwarning("Warning", "Rule ID is required.")
            return

        self.destroy()

class AdvancedImportDialog(ctk.CTkToplevel):
    def __init__(self, parent, rules):
        super().__init__(parent)
        self.title("Approve Advanced Import")
        self.geometry("1000x700")
        self.rules = rules
        self.approved = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        self.label = ctk.CTkLabel(self.main_container, text=f"Previewing {len(rules)} rules. Do you want to import them?", font=ctk.CTkFont(size=14, weight="bold"))
        self.label.pack(pady=10)

        # Table for preview
        self.tree_frame = ctk.CTkFrame(self.main_container)
        self.tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        cols = ["rule_id", "level", "description", "group", "filename"]
        self.tree = ttk.Treeview(self.tree_frame, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=150)

        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar = ctk.CTkScrollbar(self.tree_frame, orientation="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        for rule in rules:
            vals = [rule.get(c, "") for c in cols]
            self.tree.insert("", "end", values=vals)

        self.button_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.button_frame.pack(pady=10)

        self.approve_btn = ctk.CTkButton(self.button_frame, text="Approve & Import", command=self.approve, fg_color="#5cb85c", hover_color="#4cae4c")
        self.approve_btn.pack(side="left", padx=10)

        self.cancel_btn = ctk.CTkButton(self.button_frame, text="Cancel", command=self.destroy, fg_color="#d9534f", hover_color="#c9302c")
        self.cancel_btn.pack(side="left", padx=10)

    def approve(self):
        self.approved = True
        self.destroy()

class HistoryWindow(ctk.CTkToplevel):
    def __init__(self, parent, history_data, editor_widget):
        super().__init__(parent)
        self.title("Rule History")
        self.geometry("900x600")
        self.history_data = history_data
        self.editor_widget = editor_widget

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.label = ctk.CTkLabel(self, text="Select a version to compare/restore", font=ctk.CTkFont(size=14, weight="bold"))
        self.label.grid(row=0, column=0, pady=10, sticky="ew")

        self.main_container = ctk.CTkFrame(self)
        self.main_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(1, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        # Left side: Version List
        self.version_frame = ctk.CTkFrame(self.main_container)
        self.version_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.tree = ttk.Treeview(self.version_frame, columns=("id", "timestamp"), show="headings")
        self.tree.heading("id", text="ID")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_version_select)

        for h in history_data:
            self.tree.insert("", "end", values=(h[0], h[2]))

        # Right side: Version Preview
        self.preview_frame = ctk.CTkFrame(self.main_container)
        self.preview_frame.grid(row=0, column=1, sticky="nsew")

        self.preview_editor = ctk.CTkTextbox(self.preview_frame, font=("Courier New", 12))
        self.preview_editor.pack(fill="both", expand=True, padx=5, pady=5)

        # Bottom: Actions
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.grid(row=2, column=0, pady=15)

        self.restore_btn = ctk.CTkButton(self.button_frame, text="Restore this version", command=self.restore, fg_color="#5cb85c", hover_color="#4cae4c")
        self.restore_btn.pack(side="left", padx=10)

        self.close_btn = ctk.CTkButton(self.button_frame, text="Close", command=self.destroy)
        self.close_btn.pack(side="left", padx=10)

    def on_version_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        idx = self.tree.index(selected[0])
        raw_xml = self.history_data[idx][1]
        self.preview_editor.delete("1.0", "end")
        self.preview_editor.insert("1.0", raw_xml)

    def restore(self):
        raw_xml = self.preview_editor.get("1.0", "end").strip()
        if not raw_xml: return
        if messagebox.askyesno("Confirm Restore", "Are you sure you want to load this version into the editor? Current changes in the editor will be overwritten."):
            self.editor_widget.delete("1.0", "end")
            self.editor_widget.insert("1.0", raw_xml)
            self.destroy()
