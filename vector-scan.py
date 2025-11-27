#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VectorScan fake launcher (demo-mode only)

This script implements a deterministic, video-optimized demo output when
invoked with `--demo` or when `DEMO_MODE=1` is set. It does NOT modify any
production rules, scanners, or ledger generation. The demo branch is
entirely self-contained and prints a short, symmetric, deterministic
animation suitable for marketing videos.

Usage: python3 vector-scan.py --demo
       DEMO_MODE=1 python3 vector-scan.py
"""
from __future__ import annotations

import os
import sys
import time

# ANSI colors (subtle; no bold/underline)
YELLOW = "\033[33m"
RED = "\033[31m"
GREEN = "\033[32m"
CYAN = "\033[36m"
RESET = "\033[0m"


def safe_print(s: str = "") -> None:
    """Print without extra spaces and flush immediately (deterministic)."""
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


def blink_cursor(prompt: str, blink_secs: float = 0.2) -> None:
    """Simulate a single blink: print a cursor char then remove it.

    Uses a single blink of exactly blink_secs (0.2s required by spec).
    """
    sys.stdout.write(prompt + " ")
    sys.stdout.flush()
    # print cursor
    sys.stdout.write("_")
    sys.stdout.flush()
    time.sleep(blink_secs)
    # erase cursor (backspace, space, backspace)
    sys.stdout.write("\b \b")
    sys.stdout.flush()
    # finalize line
    sys.stdout.write("\n")
    sys.stdout.flush()


def small_pause(total: float, step: float = 0.2) -> None:
    """Pause for total seconds by repeating sleeps <= 0.2s to remain deterministic."""
    if total <= 0:
        return
    steps = int(round(total / step))
    # adjust step to be exact
    if steps <= 0:
        time.sleep(total)
        return
    per = total / steps
    for _ in range(steps):
        time.sleep(per)


def run_demo_output() -> None:
    # Deterministic demo output for recording.
    # Do not modify without updating the video assets.

    # Color palette for demo only
    RESET = "\033[0m"
    BRIGHT_WHITE = "\033[97m"
    DIM_GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BOLD_WHITE = "\033[1;97m"
    BRIGHT_CYAN = "\033[96m"

    def run_demo() -> None:
        # prompt / command
        print(f"{BRIGHT_WHITE}$ vectorscan plan.json{RESET}")
        sys.stdout.flush()
        # blank line to match requested layout
        print()

        time.sleep(2.0)
        print(f"{DIM_GRAY}Parsing plan...{RESET}")
        sys.stdout.flush()

        time.sleep(1.0)
        print(f"{DIM_GRAY}Analyzing resources...{RESET}")
        sys.stdout.flush()

        time.sleep(1.0)
        print(f"{DIM_GRAY}Checking security posture...{RESET}")
        sys.stdout.flush()
        # blank line before findings
        print()

        time.sleep(1.5)
        # findings — bright red, each on its own line
        print(f"{BRIGHT_RED}● Public endpoint: 0.0.0.0/0{RESET}")
        print(f"{BRIGHT_RED}● Storage encryption disabled{RESET}")
        print(f"{BRIGHT_RED}● IAM wildcard permissions{RESET}")
        sys.stdout.flush()

        # blank line between findings and summary
        print()
        time.sleep(1.0)
        print(f"{BOLD_WHITE}Scan complete: 3 issues found{RESET}")
        sys.stdout.flush()

        time.sleep(1.5)
        print()  # blank line
        print(f"{BRIGHT_CYAN}→ Fixable in VectorGuard{RESET}")
        sys.stdout.flush()

    run_demo()


def demo_mode() -> int:
    # Adapter that runs the isolated demo output and returns success.
    run_demo_output()
    return 0


def main(argv: list[str]) -> int:
    demo_flag = False
    if os.getenv("DEMO_MODE") == "1":
        demo_flag = True
    if "--demo" in argv or "-d" in argv:
        demo_flag = True

    if demo_flag:
        return demo_mode()

    # Non-demo: print a short message and exit (do not run production scanners)
    safe_print("This is a demo-only launcher. Run with --demo or DEMO_MODE=1")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
