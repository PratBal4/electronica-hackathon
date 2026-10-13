#!/usr/bin/env python3
"""Build and installation entrypoint alias.

Runs install.py for automated environment configuration, dependency installation,
and verification.
"""

import sys
from install import main

if __name__ == "__main__":
    sys.exit(main())
