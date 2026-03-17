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

        self.add_rule_btn = ctk.CTkButton(self.sidebar, text="Add New Rule", command=self.add_rule)
        self.add_rule_btn.pack(pady=10, padx=20)

        self.edit_rule_btn = ctk.CTkButton(self.sidebar, text="Edit Selected Rule", command=self.edit_rule)
        self.edit_rule_btn.pack(pady=10, padx=20)

        self.clone_rule_btn = ctk.CTkButton(self.sidebar, text="Clone Selected Rule", command=self.clone_rule)
        self.clone_rule_btn.pack(pady=10, padx=20)

        self.delete_rule_btn = ctk.CTkButton(self.sidebar, text="Delete Selected Rule", command=self.delete_rule, fg_color="#d9534f", hover_color="#c9302c")
        self.delete_rule_btn.pack(pady=10, padx=20)

        self.show_duplicates_btn = ctk.CTkButton(self.sidebar, text="Show Duplicates", command=self.show_duplicates)
        self.show_duplicates_btn.pack(pady=10, padx=20)

        self.export_csv_btn = ctk.CTkButton(self.sidebar, text="Export Results to CSV", command=self.export_to_csv)
        self.export_csv_btn.pack(pady=10, padx=20)

        # Appearance Mode
        self.appearance_label = ctk.CTkLabel(self.sidebar, text="Appearance Mode:", anchor="w")
        self.appearance_label.pack(pady=(20, 0), padx=20)
        self.appearance_optionemenu = ctk.CTkOptionMenu(self.sidebar, values=["Light", "Dark", "System"],
                                                        command=self.change_appearance_mode_event)
        self.appearance_optionemenu.pack(pady=10, padx=20)
        self.appearance_optionemenu.set("Dark")

        # Search Filters Section
        self.filter_label = ctk.CTkLabel(self.sidebar, text="Search Columns", font=ctk.CTkFont(size=14, weight="bold"))
        self.filter_label.pack(pady=(20, 5), padx=20)

        self.scrollable_filters = ctk.CTkScrollableFrame(self.sidebar, label_text="")
        self.scrollable_filters.pack(pady=5, padx=10, fill="both", expand=True)
        self.column_vars = {} # Stores BooleanVars for each column

        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stats_frame.pack(pady=20, padx=20, side="bottom", fill="x")

        self.progress_bar = ctk.CTkProgressBar(self.stats_frame)
        self.progress_bar.pack(pady=10, padx=10, fill="x")
        self.progress_bar.set(0)

        self.stats_label = ctk.CTkLabel(self.stats_frame, text="Rules: 0", font=ctk.CTkFont(size=14))
        self.stats_label.pack(pady=5)

        self.files_label = ctk.CTkLabel(self.stats_frame, text="Files: 0", font=ctk.CTkFont(size=12))
        self.files_label.pack(pady=5)

        # Main Area
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1) # Treeview
        self.main_frame.grid_rowconfigure(1, weight=0) # Detail Panel

        # Search Bar
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Search (Auto-search while typing)...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.on_search_key)

        self.clear_btn = ctk.CTkButton(self.search_frame, text="Clear", width=80, fg_color="transparent", border_width=1, command=self.clear_search)
        self.clear_btn.pack(side="right", padx=(10, 0))

        self.search_btn = ctk.CTkButton(self.search_frame, text="Search", width=100, command=self.refresh_table)
        self.search_btn.pack(side="right")

        # Detail View Panel (Moved to top & resizable)
        self.detail_frame = ctk.CTkFrame(self.main_frame)
        self.detail_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        self.detail_header = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.detail_header.pack(fill="x", padx=10, pady=5)

        self.detail_label = ctk.CTkLabel(self.detail_header, text="Rule Details & Quick Editor", font=ctk.CTkFont(size=14, weight="bold"))
        self.detail_label.pack(side="left")

        self.save_detail_btn = ctk.CTkButton(self.detail_header, text="Save Edits", width=100, command=self.save_detail_edits)
        self.save_detail_btn.pack(side="right", padx=5)

        self.height_label = ctk.CTkLabel(self.detail_header, text="Height:", font=ctk.CTkFont(size=11))
        self.height_label.pack(side="right", padx=(10, 5))

        self.height_slider = ctk.CTkSlider(self.detail_header, from_=4, to=30, number_of_steps=26, width=100, command=self.change_detail_height)
        self.height_slider.pack(side="right")
        self.height_slider.set(8)

        self.detail_text = tk.Text(self.detail_frame, height=8, bg="#2b2b2b", fg="white", font=("Segoe UI", 10), borderwidth=0, undo=True)
        self.detail_text.pack(fill="x", padx=10, pady=(0, 10))
        self.detail_text.configure(state="disabled")

        # Table (Using standard Treeview with custom styling)
        self.tree_container = ctk.CTkFrame(self.main_frame)
        self.tree_container.grid(row=2, column=0, sticky="nsew")

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
        self.h_scrollbar.grid(row=3, column=0, sticky="ew")
        self.tree.configure(xscrollcommand=self.h_scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.search_timer = None
        self.current_folder = ""
        self.showing_duplicates = False
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

    def change_detail_height(self, value):
        self.detail_text.configure(height=int(value))

    def save_detail_edits(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule first.")
            return

        values = self.tree.item(selected_item[0])["values"]
        columns = self.tree["columns"]
        rule_data = dict(zip(columns, values))

        content = self.detail_text.get("1.0", tk.END).strip()
        updated_data = {}

        for line in content.split("\n"):
            if ":" in line:
                key_raw, val = line.split(":", 1)
                key = key_raw.strip().lower().replace(" ", "_")
                updated_data[key] = val.strip()

        if not updated_data.get("rule_id"):
             messagebox.showerror("Error", "Rule ID cannot be empty in edits.")
             return

        filepath = os.path.join(self.current_folder, rule_data["relative_path"])
        try:
            update_rule_xml(rule_data["rule_id"], updated_data, filepath)
            messagebox.showinfo("Success", "Rule updated from details panel.")
            self.scan_rules()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update: {e}")

    def on_tree_select(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        values = self.tree.item(selected_item[0])["values"]
        columns = self.tree["columns"]

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)

        for col, val in zip(columns, values):
            if val is not None and val != "":
                self.detail_text.insert(tk.END, f"{col.replace('_', ' ').title()}: ", "bold")
                self.detail_text.insert(tk.END, f"{val}\n")

        self.detail_text.tag_configure("bold", font=("Segoe UI", 10, "bold"))
        self.detail_text.configure(state="normal")

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
                self.scan_rules() # Refresh list
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
            messagebox.showerror("Error", "Could not determine file path for rule.")
            return

        all_cols = self.db.get_columns()
        dialog = RuleDialog(self, title="Edit Rule", initial_data=rule_data, columns=all_cols)
        self.wait_window(dialog)

        if dialog.result:
            filepath = os.path.join(self.current_folder, rule_data["relative_path"])
            try:
                update_rule_xml(rule_data["rule_id"], dialog.result, filepath)
                messagebox.showinfo("Success", "Rule updated successfully.")
                self.scan_rules() # Refresh list
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

        # Prepare clone data
        clone_data = rule_data.copy()
        clone_data["rule_id"] = f"{rule_data['rule_id']}_clone"
        clone_data["cloned_from"] = rule_data.get("relative_path")

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
                self.scan_rules() # Refresh list
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
                self.scan_rules() # Refresh list
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

        total_files = len(files_to_scan)
        self.progress_bar.set(0)
        for i, (full_path, rel_path, f_hash) in enumerate(files_to_scan):
            self.files_label.configure(text=f"Scanning: {i+1}/{total_files}")
            self.progress_bar.set((i + 1) / total_files)
            self.update_idletasks()

            rules = parse_wazuh_xml(full_path, self.current_folder)
            self.db.save_rules(rules)
            self.db.update_file_state(rel_path, f_hash)

        self.refresh_table()
        self.progress_bar.set(1)
        messagebox.showinfo("Scan Complete", f"Processed {len(files_to_scan)} files.")

    def refresh_table(self):
        selected_cols = [col for col, var in self.column_vars.items() if var.get()]
        search_term = self.search_entry.get()
        data, columns = self.db.search_rules(search_term, target_columns=selected_cols, show_duplicates=self.showing_duplicates)

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
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

        self.scrollable_frame = ctk.CTkScrollableFrame(self.main_container, label_text="Rule Attributes")
        self.scrollable_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.scrollable_frame.grid_columnconfigure(1, weight=1)

        # Exclude internal/read-only columns
        excluded = ["id", "is_rule", "filename", "relative_path"]

        # Determine fields to show
        self.fields = ["rule_id", "level", "description", "match", "group", "cloned_from"]
        if columns:
            for col in columns:
                if col not in excluded and col not in self.fields:
                    self.fields.append(col)

        # Ensure all initial data keys are also included if they aren't in columns
        for key in self.initial_data.keys():
            if key not in excluded and key not in self.fields:
                self.fields.append(key)

        self.entries = {}
        for i, field in enumerate(self.fields):
            self.add_field_row(field, i)

        # Custom Field Section
        self.custom_field_frame = ctk.CTkFrame(self.main_container)
        self.custom_field_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))

        self.new_field_entry = ctk.CTkEntry(self.custom_field_frame, placeholder_text="New field name (e.g. mitre_id)")
        self.new_field_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        self.add_field_btn = ctk.CTkButton(self.custom_field_frame, text="Add Field", width=80, command=self.add_custom_field)
        self.add_field_btn.pack(side="right", padx=5, pady=5)

        self.save_btn = ctk.CTkButton(self.main_container, text="Save Rule", command=self.save)
        self.save_btn.grid(row=2, column=0, pady=10)

    def add_field_row(self, field, row_idx, value=None):
        display_name = field.replace("_", " ").title()
        label = ctk.CTkLabel(self.scrollable_frame, text=display_name)
        label.grid(row=row_idx, column=0, padx=10, pady=5, sticky="w")

        entry = ctk.CTkEntry(self.scrollable_frame)
        entry.grid(row=row_idx, column=1, padx=10, pady=5, sticky="ew")

        # Pre-fill value
        if value is not None:
            entry.insert(0, str(value))
        elif field in self.initial_data:
            entry.insert(0, str(self.initial_data[field]))
        elif field == "level" and "rule_level" in self.initial_data:
            entry.insert(0, str(self.initial_data["rule_level"]))

        self.entries[field] = entry

    def add_custom_field(self):
        new_field = self.new_field_entry.get().strip().lower().replace(" ", "_")
        if not new_field:
            return
        if new_field in self.entries:
            messagebox.showwarning("Warning", f"Field '{new_field}' already exists.")
            return

        row_idx = len(self.entries)
        self.add_field_row(new_field, row_idx)
        self.new_field_entry.delete(0, tk.END)
        self.fields.append(new_field)

    def save(self):
        self.result = {k: v.get() for k, v in self.entries.items() if v.get()}
        if not self.result.get("rule_id"):
            messagebox.showwarning("Warning", "Rule ID is required.")
            return
        self.destroy()
