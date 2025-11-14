"""Compatibility shim exposing `tools.vectorscan.lead_api` at the repository root.
"""
from importlib import import_module
import sys

_lead_api_module = import_module("tools.vectorscan.lead_api")
sys.modules[__name__] = _lead_api_module
