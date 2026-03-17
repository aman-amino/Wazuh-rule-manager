import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
from .database import DatabaseManager
from .parser import get_file_hash, parse_wazuh_xml
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
        self.main_frame.grid_rowconfigure(3, weight=0)

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
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        # Detail View Panel
        self.detail_frame = ctk.CTkFrame(self.main_frame)
        self.detail_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))

        self.detail_label = ctk.CTkLabel(self.detail_frame, text="Rule Details", font=ctk.CTkFont(size=14, weight="bold"))
        self.detail_label.pack(anchor="w", padx=10, pady=5)

        self.detail_text = tk.Text(self.detail_frame, height=8, bg="#2b2b2b", fg="white", font=("Segoe UI", 10), borderwidth=0)
        self.detail_text.pack(fill="x", padx=10, pady=(0, 10))
        self.detail_text.configure(state="disabled")

        self.search_timer = None
        self.current_folder = ""
        self.refresh_table()

    def on_search_key(self, event):
        if self.search_timer:
            self.after_cancel(self.search_timer)
        self.search_timer = self.after(400, self.refresh_table)

    def clear_search(self):
        self.search_entry.delete(0, tk.END)
        self.refresh_table()

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
        self.detail_text.configure(state="disabled")

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

        dialog = AddRuleDialog(self)
        self.wait_window(dialog)

        if dialog.result:
            filename = f"custom_rule_{dialog.result['rule_id']}.xml"
            filepath = os.path.join(self.current_folder, filename)

            if os.path.exists(filepath):
                if not messagebox.askyesno("Confirm Overwrite", f"File {filename} already exists. Overwrite?"):
                    return

            try:
                from .parser import create_rule_xml
                create_rule_xml(dialog.result, filepath)
                messagebox.showinfo("Success", f"Rule saved to {filename}")
                self.scan_rules() # Refresh list
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save rule: {e}")

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
        for i, (full_path, rel_path, f_hash) in enumerate(files_to_scan):
            self.files_label.configure(text=f"Scanning: {i+1}/{total_files}")
            self.update_idletasks()

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

class AddRuleDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Add New Rule")
        self.geometry("500x600")
        self.result = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.frame = ctk.CTkFrame(self)
        self.frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.frame.grid_columnconfigure(1, weight=1)

        fields = ["Rule ID", "Level", "Description", "Match", "Group"]
        self.entries = {}

        for i, field in enumerate(fields):
            label = ctk.CTkLabel(self.frame, text=field)
            label.grid(row=i, column=0, padx=10, pady=10, sticky="w")
            entry = ctk.CTkEntry(self.frame)
            entry.grid(row=i, column=1, padx=10, pady=10, sticky="ew")
            self.entries[field] = entry

        self.save_btn = ctk.CTkButton(self.frame, text="Save", command=self.save)
        self.save_btn.grid(row=len(fields), column=0, columnspan=2, pady=20)

    def save(self):
        self.result = {k.lower().replace(" ", "_"): v.get() for k, v in self.entries.items()}
        if not self.result["rule_id"]:
            messagebox.showwarning("Warning", "Rule ID is required.")
            return
        self.destroy()
