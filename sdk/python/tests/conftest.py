"""Shared test fixtures for vellaveto SDK tests."""

import sys
from pathlib import Path

import pytest

# Ensure the vellaveto package is importable from the sdk/python directory
sdk_path = Path(__file__).parent.parent
if str(sdk_path) not in sys.path:
    sys.path.insert(0, str(sdk_path))
