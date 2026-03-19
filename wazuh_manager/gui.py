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
        self.create_sidebar_button("📁 Select Folder", self.select_folder)
        self.create_sidebar_button("🔍 Scan Rules", self.scan_rules)

        ctk.CTkLabel(self.sidebar, text="Rule Operations", font=ctk.CTkFont(size=12, weight="bold"), text_color="#888888").pack(pady=(15, 5))
        self.ops_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.ops_frame.pack(fill="x", padx=10)
        self.create_grid_button(self.ops_frame, "➕ Add", self.add_rule, 0, 0)
        self.create_grid_button(self.ops_frame, "📝 Edit", self.edit_rule, 0, 1)
        self.create_grid_button(self.ops_frame, "👯 Clone", self.clone_rule, 1, 0)
        self.create_grid_button(self.ops_frame, "🗑️ Delete", self.delete_rule, 1, 1, color="#d9534f")

        ctk.CTkLabel(self.sidebar, text="Data Tools", font=ctk.CTkFont(size=12, weight="bold"), text_color="#888888").pack(pady=(15, 5))
        self.create_sidebar_button("📥 Import Rules", self.import_rules)
        self.create_sidebar_button("🚀 Advanced Import", self.advanced_import_flow)
        self.create_sidebar_button("📤 Export CSV", self.export_to_csv)
        self.create_sidebar_button("📦 Full Backup", self.full_backup)

        # Stats at the bottom
        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stats_frame.pack(pady=10, padx=20, side="bottom", fill="x")
        self.progress_bar = ctk.CTkProgressBar(self.stats_frame)
        self.progress_bar.pack(pady=5, fill="x")
        self.progress_bar.set(0)
        self.stats_label = ctk.CTkLabel(self.stats_frame, text="Rules: 0", font=ctk.CTkFont(size=13))
        self.stats_label.pack()

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
        self.refresh_table()

    def create_sidebar_button(self, text, command):
        btn = ctk.CTkButton(self.sidebar, text=text, command=command, height=35, anchor="w")
        btn.pack(pady=4, padx=15, fill="x")

    def create_grid_button(self, parent, text, command, r, c, color=None):
        btn = ctk.CTkButton(parent, text=text, command=command, width=120, height=32, fg_color=color)
        btn.grid(row=r, column=c, padx=5, pady=4)

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

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.current_folder = folder
            self.scan_rules()

    def scan_rules(self):
        if not self.current_folder: return
        self.progress_bar.set(0)
        files = []
        for root, _, fnames in os.walk(self.current_folder):
            for f in fnames:
                if f.endswith(".xml"):
                    files.append(os.path.join(root, f))

        if not files: return
        for i, full_path in enumerate(files):
            rel_path = os.path.relpath(full_path, self.current_folder)
            f_hash = get_file_hash(full_path)
            if f_hash != self.db.get_file_hash(rel_path):
                rules = parse_wazuh_xml(full_path, self.current_folder)
                self.db.save_rules(rules)
                self.db.update_file_state(rel_path, f_hash)
            self.progress_bar.set((i+1)/len(files))
            self.update_idletasks()

        self.refresh_table()
        self.update_analytics()

    def refresh_table(self):
        search_term = self.search_entry.get()
        data, columns = self.db.search_rules(search_term)
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = columns
        for col in columns:
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=120)
        for row in data: self.tree.insert("", "end", values=row)
        self.stats_label.configure(text=f"Rules: {len(data)}")

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

    def import_rules(self):
        if not self.current_folder: return
        filepath = filedialog.askopenfilename(filetypes=[("CSV/XML", "*.csv *.xml")])
        if not filepath: return
        try:
            if filepath.endswith(".csv"):
                from wazuh_manager.parser import parse_rules_from_csv
                rules = parse_rules_from_csv(filepath)
            else:
                rules = parse_wazuh_xml(filepath, os.path.dirname(filepath))
            if rules:
                save_rules_to_xml(rules, os.path.join(self.current_folder, "imported_rules.xml"))
                self.scan_rules()
        except Exception as e: messagebox.showerror("Error", str(e))

    def advanced_import_flow(self):
        if not self.current_folder: return
        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not filepath: return
        try:
            rules = csv_to_json_rules(filepath, self.db.get_columns())
            dialog = AdvancedImportDialog(self, rules)
            self.wait_window(dialog)
            if dialog.approved:
                for rule in rules:
                    fname = rule.get("filename") or f"adv_imp_{rule['rule_id']}.xml"
                    save_rules_to_xml([rule], os.path.join(self.current_folder, fname))
                self.scan_rules()
        except Exception as e: messagebox.showerror("Error", str(e))

    def export_to_csv(self):
        data, cols = self.db.search_rules(self.search_entry.get())
        f = filedialog.asksaveasfilename(defaultextension=".csv")
        if f:
            with open(f, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(cols)
                writer.writerows(data)

    def full_backup(self):
        data, cols = self.db.search_rules("")
        f = filedialog.asksaveasfilename(defaultextension=".csv")
        if f:
            with open(f, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(cols)
                writer.writerows(data)

    def add_rule(self):
        if not self.current_folder: return
        cols = self.db.get_columns()
        dialog = RuleDialog(self, title="Add New Rule", columns=cols)
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
        dialog = RuleDialog(self, title="Edit Rule", initial_data=rule, columns=self.db.get_columns())
        self.wait_window(dialog)
        if dialog.result:
            update_rule_xml(rule["rule_id"], dialog.result, os.path.join(self.current_folder, rule["relative_path"]))
            self.scan_rules()

    def clone_rule(self):
        sel = self.tree.selection()
        if not sel: return
        values = self.tree.item(sel[0])["values"]
        cols = self.tree["columns"]
        rule = dict(zip(cols, values))
        clone = rule.copy()
        clone["rule_id"] = f"{rule['rule_id']}_clone"
        dialog = RuleDialog(self, title="Clone Rule", initial_data=clone, columns=self.db.get_columns())
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
            if delete_rule_from_xml(rule["rule_id"], os.path.join(self.current_folder, rule["relative_path"])):
                self.db.delete_rule(rule["rule_id"], rule["relative_path"])
                self.scan_rules()

class RuleDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Rule Dialog", initial_data=None, columns=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x800")
        self.result = None
        self.initial_data = initial_data or {}
        self.scroll = ctk.CTkScrollableFrame(self)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=20)
        self.entries = {}
        excluded = ["id", "is_rule", "filename", "relative_path"]
        fields = ["rule_id", "level", "description", "group"]
        if columns:
            for c in columns:
                if c not in excluded and c not in fields: fields.append(c)
        for i, f in enumerate(fields):
            ctk.CTkLabel(self.scroll, text=f.replace("_"," ").title()).grid(row=i, column=0, padx=10, pady=5, sticky="w")
            e = ctk.CTkEntry(self.scroll, width=300)
            e.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
            if f in self.initial_data: e.insert(0, str(self.initial_data[f]))
            self.entries[f] = e
        ctk.CTkButton(self, text="Save", command=self.save).pack(pady=20)

    def save(self):
        self.result = {k: v.get() for k, v in self.entries.items() if v.get()}
        self.destroy()

class AdvancedImportDialog(ctk.CTkToplevel):
    def __init__(self, parent, rules):
        super().__init__(parent)
        self.title("Approve Import")
        self.geometry("800x600")
        self.rules = rules
        self.approved = False
        ctk.CTkLabel(self, text=f"Review {len(rules)} rules for import", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        self.tree = ttk.Treeview(self, columns=["ID", "Level", "Description"], show="headings")
        for c in ["ID", "Level", "Description"]: self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True, padx=20)
        for r in rules: self.tree.insert("", "end", values=[r.get("rule_id"), r.get("level"), r.get("description")])
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=20)
        ctk.CTkButton(self.btn_frame, text="Approve", command=self.approve, fg_color="#5cb85c").pack(side="left", padx=10)
        ctk.CTkButton(self.btn_frame, text="Cancel", command=self.destroy, fg_color="#d9534f").pack(side="left", padx=10)
    def approve(self):
        self.approved = True
        self.destroy()
