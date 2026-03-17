with open('wazuh_manager/gui.py', 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'fields = all_display_cols' in line:
        # Re-include internal columns that were excluded from summary but might be useful in editor
        # Actually, let's keep it consistent.
        pass
    new_lines.append(line)

# Wait, I noticed I might have missed the horizontal scrollbar grid index if I added a row
# I already updated it to row 3.

with open('wazuh_manager/gui.py', 'w') as f:
    f.writelines(new_lines)
