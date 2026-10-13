"""
Pytest configuration for PhishGuard.
Adds project root directory to sys.path so modules like app, config, and src can be imported directly.
"""
import sys
from pathlib import Path

# Insert project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
