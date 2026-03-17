import sys
import argparse
from wazuh_manager.gui import App
from wazuh_manager.cli import run_cli

def main():
    if len(sys.argv) > 1:
        # If there are arguments, use CLI mode
        run_cli()
    else:
        # Otherwise, default to GUI
        try:
            app = App()
            app.mainloop()
        except Exception as e:
            print(f"Error starting GUI: {e}")
            print("Try using CLI mode by providing arguments.")

if __name__ == "__main__":
    main()
