"""Legacy entrypoint shim forwarding to the legacy vectorscan module."""

import sys

from legacy.vectorscan_legacy import main


if __name__ == "__main__":
    sys.exit(main())
