"""Shared fixtures for the NET-03 test suite."""

import os
import sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PROJECT, "src")

if SRC not in sys.path:
    sys.path.insert(0, SRC)

FLAG = "GZCTF{NET03_TEST_FLAG}"
FLAG_A = "GZCTF{NET03_TEAM_A_TEST}"
FLAG_B = "GZCTF{NET03_TEAM_B_TEST}"

IMAGE = os.environ.get("NET03_IMAGE", "net-03-the-last-transmission:test")
