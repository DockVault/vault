"""Filesystem anchors for the application tree.

The server modules live under app/, but the runtime asset directories
(static/, brand/) sit at the APPLICATION ROOT (/app in the container image,
the repository root in a checkout). Anchor them here instead of deriving
them from each module's __file__ so moving a module can never silently
repoint them.
"""
from pathlib import Path

# app/core/paths.py -> app/core -> app -> <application root>
PROJECT_ROOT = Path(__file__).resolve().parents[2]
