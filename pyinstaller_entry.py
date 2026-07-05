"""PyInstaller entry point for the standalone Cascavel binary.

The package uses relative imports, so it cannot be handed to PyInstaller
directly; this thin launcher gives the frozen build a valid top-level script.
"""

from cascavel.__main__ import main

if __name__ == "__main__":
    main()
