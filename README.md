# Wazuh Rule Manager

A modern, dynamic GUI tool for indexing, searching, and managing Wazuh XML rules.

![Wazuh Rule Manager](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Build](https://img.shields.io/badge/UI-CustomTkinter-orange.svg)
![DB](https://img.shields.io/badge/Database-SQLite-lightgrey.svg)

## 🚀 Features

- **✔ Modern GUI**: Sleek dark-mode interface built with `customtkinter`.
- **✔ Dynamic Schema**: Automatically creates database columns for any new XML tags found in your rules.
- **✔ Recursive Scanning**: Deep-scans folders for all `.xml` rule files.
- **✔ Intelligent Tracking**: SHA256 hash-based file state tracking—only re-scans files that have changed.
- **✔ Group Propagation**: Automatically handles `<group>` tag propagation to individual rules.
- **✔ Global Search**: Search across all columns (standard and custom tags) instantly.
- **✔ Relative Paths**: Stores only relative paths for better portability across systems.
- **✔ Idempotent**: Safe to re-run scans; it handles updates and duplicates gracefully.

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/aman-amino/Wazuh-rule-manager.git
   cd Wazuh-rule-manager
   ```

2. **Install dependencies**:
   ```bash
   pip install customtkinter darkdetect
   ```

## 📖 Usage

1. **Run the application**:
   ```bash
   python main.py
   ```

2. **Select Folder**: Click the "Select Folder" button and choose your Wazuh rules directory (e.g., `/var/ossec/ruleset/rules`).
3. **Scan**: Click "Scan Rules". The tool will process all XML files and index them into the local SQLite database.
4. **Search**: Use the top search bar to find rules by ID, description, match string, or any other XML tag.

## 🗄️ Database Structure

The tool creates two local database files:
- `wazuh_rules_v2.db`: Stores the rules and dynamically generated columns based on XML tags.
- `file_states`: (Internal) Tracks file hashes and scan timestamps to optimize performance.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.
