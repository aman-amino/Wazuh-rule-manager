# Project Roadmap: Wazuh Rule Manager Enhancements

## Step 1: Align Advanced Import & Data Mapping
- Recheck CSV to JSON to XML mapping logic in `advanced_importer.py`.
- Update `advanced_importer.py` to dynamically use column names from the database schema.
- Ensure compliance and details fields are correctly serialized during the conversion process.

## Step 2: Advanced Search & Database Statistics
- Modify `database.py` search logic:
    - Detect column types (Numeric vs. Text).
    - Perform exact match for numbers and pattern match (LIKE) for text.
- Add methods to calculate rule statistics:
    - Rule counts by Level.
    - Rule counts by ID ranges (e.g., 0-10000, 10001-20000, etc.).

## Step 3: UI Redesign & Stitch Integration
- Create a new Stitch project for the "Wazuh Rule Manager Dashboard".
- Generate UI screens focusing on:
    - A polished, clear data table.
    - A new "Status Panel" on the right (replacing the Rule Attributes panel).
    - Improved Sidebar and Search controls.

## Step 4: Implement Status Panel & UI Polish
- Replace the "Rule Attributes" quick editor with the "Status Panel" in `gui.py`.
- Implement the ID range and Level count visualizations.
- Update the table and overall styling based on the Stitch designs.

## Step 5: Verification & Testing
- Run all unit tests.
- Verify the full import/export flow with the new data mapping.
- Final UI check and cleanup of redundant code.
