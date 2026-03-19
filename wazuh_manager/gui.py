import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
from .database import DatabaseManager
from .parser import get_file_hash, parse_wazuh_xml, create_rule_xml, update_rule_xml, delete_rule_from_xml
from . import DB_NAME

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.db = DatabaseManager(DB_NAME)

        self.title("Wazuh Rule Manager")
        self.geometry("1600x900")

        # Appearance
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Layout: Sidebar (0), Main (1), Detail (2)
        self.grid_columnconfigure(0, weight=0, minsize=280) # Sidebar
        self.grid_columnconfigure(1, weight=3) # Main Table
        self.grid_columnconfigure(2, weight=1, minsize=380) # Detail Panel
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="🛡️ Wazuh Manager", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.pack(pady=(20, 10), padx=20)

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
        self.progress_bar.pack(pady=5, padx=10, fill="x")
        self.progress_bar.set(0)

        self.stats_label = ctk.CTkLabel(self.stats_frame, text="Rules: 0", font=ctk.CTkFont(size=13))
        self.stats_label.pack(pady=2)

        self.files_label = ctk.CTkLabel(self.stats_frame, text="Files: 0", font=ctk.CTkFont(size=11))
        self.files_label.pack(pady=2)

        # --- Main Area (Table) ---
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # Search Bar
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Search indexed rules...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(10, 5))
        self.search_entry.bind("<KeyRelease>", self.on_search_key)

        self.clear_btn = ctk.CTkButton(self.search_frame, text="Clear", width=70, fg_color="transparent", border_width=1, command=self.clear_search)
        self.clear_btn.pack(side="left", padx=5)

        self.search_btn = ctk.CTkButton(self.search_frame, text="Search", width=80, command=self.refresh_table)
        self.search_btn.pack(side="left", padx=(5, 10))


        # Rule Summary Section (Top of Table)
        self.summary_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.summary_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))

        self.summary_label = ctk.CTkLabel(self.summary_frame, text="Select a rule to see details", font=ctk.CTkFont(size=16, weight="bold"))
        self.summary_label.pack(side="top", anchor="w", pady=(5, 5))

        self.summary_scroll = ctk.CTkScrollableFrame(self.summary_frame, height=220, label_text="Rule Details Summary")
        self.summary_scroll.pack(fill="both", expand=True)

        # Table Container
        self.tree_container = ctk.CTkFrame(self.main_frame)
        self.tree_container.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        style = ttk.Style()
        style.theme_use("default")
        table_font = ("Inter", 10)
        header_font = ("Inter", 11, "bold")

        style.configure("Treeview",
                        background="#2b2b2b",
                        foreground="white",
                        fieldbackground="#2b2b2b",
                        borderwidth=0,
                        font=table_font,
                        rowheight=35)
        style.map("Treeview", background=[('selected', '#1a75d1')])
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
        self.h_scrollbar.grid(row=3, column=0, sticky="ew", padx=10)
        self.tree.configure(xscrollcommand=self.h_scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # --- Detail Panel (Right) ---
        self.detail_frame = ctk.CTkFrame(self, width=380)
        self.detail_frame.grid(row=0, column=2, sticky="nsew", padx=10, pady=20)
        self.detail_frame.grid_columnconfigure(0, weight=1)
        self.detail_frame.grid_rowconfigure(1, weight=1)

        self.detail_header = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.detail_header.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        self.detail_label = ctk.CTkLabel(self.detail_header, text="Rule Attributes", font=ctk.CTkFont(size=16, weight="bold"))
        self.detail_label.pack(side="left")

        self.save_detail_btn = ctk.CTkButton(self.detail_header, text="💾 Save", width=80, command=self.save_detail_edits)
        self.save_detail_btn.pack(side="right", padx=5)

        self.detail_scroll = ctk.CTkScrollableFrame(self.detail_frame, label_text="Quick Editor")
        self.detail_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.detail_scroll.grid_columnconfigure(1, weight=1)

        self.detail_entries = {}
        self.current_selected_rule = None

        self.search_timer = None
        self.current_folder = ""
        self.showing_duplicates = False
        self.sort_column_id = None
        self.sort_reverse = False

        self.refresh_table()

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def on_search_key(self, event):
        if self.search_timer:
            self.after_cancel(self.search_timer)
        self.search_timer = self.after(400, self.refresh_table)

    def clear_search(self):
        self.search_entry.delete(0, tk.END)
        self.showing_duplicates = False
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

        # Update header to show sort direction (simple version)
        for c in self.tree["columns"]:
            self.tree.heading(c, text=c.replace("_", " ").title())

        suffix = " ↑" if self.sort_reverse else " ↓"
        self.tree.heading(col, text=col.replace("_", " ").title() + suffix)

    def save_detail_edits(self):
        if not self.current_selected_rule:
            messagebox.showwarning("Warning", "Please select a rule first.")
            return

        rule_data = self.current_selected_rule
        updated_data = {k: v.get() for k, v in self.detail_entries.items() if v.get()}

        if not updated_data.get("rule_id"):
             messagebox.showerror("Error", "Rule ID cannot be empty.")
             return

        filepath = os.path.join(self.current_folder, rule_data["relative_path"])
        try:
            update_rule_xml(rule_data["rule_id"], updated_data, filepath)
            messagebox.showinfo("Success", "Rule updated successfully.")
            self.scan_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update: {e}")

    def on_tree_select(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        values = self.tree.item(selected_item[0])["values"]
        columns = self.tree["columns"]
        self.current_selected_rule = dict(zip(columns, values))



        # Clear detail entries
        for widget in self.detail_scroll.winfo_children():
            widget.destroy()
        self.detail_entries = {}

        # Fill detail panel with structured entries
        # Prioritize important fields
        important = ["rule_id", "level", "description", "group", "match"]

        # Update summary section
        self.summary_label.configure(text=f"Rule: {self.current_selected_rule.get('rule_id', 'Unknown')}")
        for widget in self.summary_scroll.winfo_children():
            widget.destroy()

        # Grid container inside the scrollable frame
        summary_grid = ctk.CTkFrame(self.summary_scroll, fg_color="transparent")
        summary_grid.pack(fill="both", expand=True, padx=5, pady=5)
        for i in range(3):
            summary_grid.grid_columnconfigure(i, weight=1)

        all_display_cols = important + [c for c in columns if c not in important and c not in ["id", "is_rule", "filename", "relative_path"]]

        for idx, col in enumerate(all_display_cols):
            r, c = divmod(idx, 3)
            # Card-like frame for each attribute
            f_frame = ctk.CTkFrame(summary_grid, border_width=1, border_color="#444444", fg_color="#333333")
            f_frame.grid(row=r, column=c, sticky="nsew", padx=8, pady=8)

            # Header Area
            h_frame = ctk.CTkFrame(f_frame, fg_color="#3d3d3d", corner_radius=0, height=28)
            h_frame.pack(fill="x", side="top")
            h_frame.pack_propagate(False)

            lbl = ctk.CTkLabel(h_frame, text=col.replace("_", " ").title(),
                              font=ctk.CTkFont(size=11, weight="bold"),
                              text_color="#AAAAAA")
            lbl.pack(pady=2, padx=10, anchor="w")

            # Content Area
            val = self.current_selected_rule.get(col, "")
            if val is None or val == "": val = "None"

            val_lbl = ctk.CTkLabel(f_frame, text=str(val),
                                  font=ctk.CTkFont(size=12),
                                  anchor="nw", justify="left",
                                  wraplength=250)
            val_lbl.pack(fill="both", expand=True, padx=10, pady=8)
        fields = all_display_cols

        for i, col in enumerate(fields):
            val = self.current_selected_rule.get(col, "")
            if val is None: val = ""

            label = ctk.CTkLabel(self.detail_scroll, text=col.replace("_", " ").title(), font=ctk.CTkFont(size=11))
            label.grid(row=idx, column=0, padx=5, pady=2, sticky="w")

            entry = ctk.CTkEntry(self.detail_scroll, height=25)
            entry.grid(row=idx, column=1, padx=5, pady=2, sticky="ew")
            entry.insert(0, str(val) if val != "None" else "")
            self.detail_entries[col] = entry

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
            self.scan_rules()

    def add_rule(self):
        if not self.current_folder:
            messagebox.showwarning("Warning", "Please select a folder first.")
            return

        columns = self.db.get_columns()
        dialog = RuleDialog(self, title="Add New Rule", columns=columns)
        self.wait_window(dialog)

        if dialog.result:
            filename = f"custom_rule_{dialog.result['rule_id']}.xml"
            filepath = os.path.join(self.current_folder, filename)

            if os.path.exists(filepath):
                if not messagebox.askyesno("Confirm Overwrite", f"File {filename} already exists. Overwrite?"):
                    return

            try:
                create_rule_xml(dialog.result, filepath)
                messagebox.showinfo("Success", f"Rule saved to {filename}")
                self.scan_rules()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save rule: {e}")

    def edit_rule(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule to edit.")
            return

        values = self.tree.item(selected_item[0])["values"]
        columns = self.tree["columns"]
        rule_data = dict(zip(columns, values))

        if not rule_data.get("relative_path"):
            messagebox.showerror("Error", "Could not determine file path.")
            return

        all_cols = self.db.get_columns()
        dialog = RuleDialog(self, title="Edit Rule", initial_data=rule_data, columns=all_cols)
        self.wait_window(dialog)

        if dialog.result:
            filepath = os.path.join(self.current_folder, rule_data["relative_path"])
            try:
                update_rule_xml(rule_data["rule_id"], dialog.result, filepath)
                messagebox.showinfo("Success", "Rule updated successfully.")
                self.scan_rules()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update rule: {e}")

    def clone_rule(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule to clone.")
            return

        values = self.tree.item(selected_item[0])["values"]
        columns = self.tree["columns"]
        rule_data = dict(zip(columns, values))

        clone_data = rule_data.copy()
        clone_data["rule_id"] = f"{rule_data['rule_id']}_clone"
        clone_data["cloned_from"] = rule_data.get("relative_path")

        # Remove internal database fields
        for key in ["id", "is_rule", "filename", "relative_path"]:
            if key in clone_data: del clone_data[key]

        all_cols = self.db.get_columns()
        dialog = RuleDialog(self, title="Clone Rule", initial_data=clone_data, columns=all_cols)
        self.wait_window(dialog)

        if dialog.result:
            filename = f"cloned_rule_{dialog.result['rule_id']}.xml"
            filepath = os.path.join(self.current_folder, filename)

            if os.path.exists(filepath):
                if not messagebox.askyesno("Confirm Overwrite", f"File {filename} already exists. Overwrite?"):
                    return

            try:
                create_rule_xml(dialog.result, filepath)
                messagebox.showinfo("Success", f"Rule cloned to {filename}")
                # Explicitly wait a moment for OS to register file?
                # Should not be needed but just in case
                self.scan_rules()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clone rule: {e}")

    def delete_rule(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule to delete.")
            return

        values = self.tree.item(selected_item[0])["values"]
        columns = self.tree["columns"]
        rule_data = dict(zip(columns, values))

        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete rule {rule_data['rule_id']}?"):
            return

        filepath = os.path.join(self.current_folder, rule_data["relative_path"])
        try:
            if delete_rule_from_xml(rule_data["rule_id"], filepath):
                self.db.delete_rule(rule_data["rule_id"], rule_data["relative_path"])
                messagebox.showinfo("Success", f"Rule {rule_data['rule_id']} deleted.")
                self.scan_rules()
            else:
                messagebox.showerror("Error", f"Could not find rule {rule_data['rule_id']} in file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete rule: {e}")

    def show_duplicates(self):
        self.showing_duplicates = True
        self.refresh_table()

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
            import csv
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(data)
            messagebox.showinfo("Success", f"Data exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {e}")


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

            # Group rules by their destination filename
            # If data has relative_path or filename, use it. Otherwise use default.
            files_to_create = {}
            for rule in imported_rules:
                fname = rule.get("filename") or rule.get("relative_path")
                if not fname or not fname.endswith(".xml"):
                    fname = f"imported_rules_{os.path.basename(filepath).split('.')[0]}.xml"

                if fname not in files_to_create:
                    files_to_create[fname] = []
                files_to_create[fname].append(rule)

            from wazuh_manager.parser import save_rules_to_xml
            count = 0
            for fname, rules in files_to_create.items():
                dest_path = os.path.join(self.current_folder, os.path.basename(fname))
                save_rules_to_xml(rules, dest_path)
                count += len(rules)

            messagebox.showinfo("Success", f"Successfully imported {count} rules into {len(files_to_create)} files.")
            self.scan_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")

    def full_backup(self):
        data, columns = self.db.search_rules("")
        if not data:
            messagebox.showinfo("Backup", "No rules to backup.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return

        try:
            import csv
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(data)
            messagebox.showinfo("Success", f"Full backup saved to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create backup: {e}")

    def advanced_import_flow(self):
        if not self.current_folder:
            messagebox.showwarning("Warning", "Please select a target folder first.")
            return

        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return

        try:
            from wazuh_manager.advanced_importer import csv_to_json_rules
            rules = csv_to_json_rules(filepath)

            if not rules:
                messagebox.showinfo("Advanced Import", "No valid rules found in the CSV.")
                return

            dialog = AdvancedImportDialog(self, rules)
            self.wait_window(dialog)

            if dialog.approved:
                # Group rules by their destination filename
                files_to_create = {}
                for rule in rules:
                    fname = rule.get("filename") or rule.get("relative_path")
                    if not fname or not fname.endswith(".xml"):
                        fname = f"adv_imported_{os.path.basename(filepath).split('.')[0]}.xml"

                    if fname not in files_to_create:
                        files_to_create[fname] = []
                    files_to_create[fname].append(rule)

                from wazuh_manager.parser import save_rules_to_xml
                count = 0
                for fname, rules_group in files_to_create.items():
                    dest_path = os.path.join(self.current_folder, os.path.basename(fname))
                    save_rules_to_xml(rules_group, dest_path)
                    count += len(rules_group)

                messagebox.showinfo("Success", f"Advanced Import complete. Imported {count} rules into {len(files_to_create)} files.")
                self.scan_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Advanced Import failed: {e}")
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

class RuleDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Rule Dialog", initial_data=None, columns=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x800")
        self.result = None
        self.initial_data = initial_data or {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Bottom frame for action buttons to ensure they are always visible
        self.button_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.button_frame.pack(side="bottom", fill="x", pady=(0, 10))

        self.save_btn = ctk.CTkButton(self.button_frame, text="Save Rule", command=self.save)
        self.save_btn.pack(pady=10)

        self.custom_field_frame = ctk.CTkFrame(self.main_container)
        self.custom_field_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 10))

        self.new_field_entry = ctk.CTkEntry(self.custom_field_frame, placeholder_text="New field name")
        self.new_field_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        self.add_field_btn = ctk.CTkButton(self.custom_field_frame, text="Add Field", width=80, command=self.add_custom_field)
        self.add_field_btn.pack(side="right", padx=5, pady=5)

        self.scrollable_frame = ctk.CTkScrollableFrame(self.main_container, label_text="Rule Attributes")
        self.scrollable_frame.pack(side="top", fill="both", expand=True, padx=10, pady=10)
        self.scrollable_frame.grid_columnconfigure(1, weight=1)

        excluded = ["id", "is_rule", "filename", "relative_path"]
        self.fields = ["rule_id", "level", "description", "match", "group", "cloned_from"]
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

    def save(self):
        self.result = {k: v.get() for k, v in self.entries.items() if v.get()}
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
