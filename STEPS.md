# Wazuh Rule Manager - Fixes and Enhancements

## 1. Fixed XML Reconstruction Error
The previous version flattened Wazuh rules into a simple key-value structure in the database, which caused multi-value tags (like multiple `<field>` tags) and attributes to be lost or corrupted when saving back to XML.

**Fix:**
- Implemented **Raw XML Storage**: Every rule now has its original XML fragment stored in a `raw_xml` column.
- Implemented **Indexed Field Naming**: Tags that appear multiple times are now indexed (e.g., `field1`, `field2`) in the database.
- Implemented **Dotted Attribute Naming**: Attributes are now stored using a dot separator (e.g., `field1.name`, `rule.level`).

## 2. Advanced Rule Editor
- Added a **Raw XML Editor** to the Rule Dialog.
- Users can now edit the full XML structure of a rule directly.
- The editor includes validation to ensure only valid XML is saved.

## 3. Rule History and Restore
- Created a `rule_history` table to track every change made to a rule.
- Added a **View History** button to the editor.
- Users can compare current rules with previous versions and **Restore** any past version with a single click.

## 4. Database Migration
- Updated `DatabaseManager` to automatically handle the new `raw_xml` column and the history table.
- Added support for fetching and recording rule history.

## 5. Improved Importer
- The Advanced Importer now correctly handles complex nested JSON in CSV files (like Tetragon rules).
- It automatically generates a `raw_xml` fragment during import to ensure consistency with the new architecture.

## 6. Syntax and Stability
- Fixed a major `SyntaxError` in `gui.py` that prevented the application from starting.
- Standardized error handling across all file operations.
