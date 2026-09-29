# ABOUTME: Allows running kubeid as `python -m kubeid`.
# ABOUTME: Delegates to the CLI entry point.
from kubeid.cli import main

raise SystemExit(main())
