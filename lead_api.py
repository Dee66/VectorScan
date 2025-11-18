"""Compatibility shim exposing `tools.vectorscan.lead_api` at the repository root."""

import sys
from importlib import import_module

_lead_api_module = import_module("tools.vectorscan.lead_api")
sys.modules[__name__] = _lead_api_module
