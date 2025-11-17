"""Streaming Terraform plan parser for VectorScan."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


class PlanStreamError(RuntimeError):
    """Raised when the streaming parser encounters invalid JSON."""


class PlanSchemaError(ValueError):
    """Raised when required tfplan schema elements are missing."""


FAST_PATH_RESOURCES = int(os.getenv("VSCAN_PLAN_FAST_PATH_RESOURCES", "1000"))
FAST_PATH_MAX_MS = int(os.getenv("VSCAN_PLAN_FAST_PATH_MS", "200"))
LARGE_PLAN_RESOURCES = int(os.getenv("VSCAN_PLAN_LARGE_RESOURCES", "10000"))
LARGE_PLAN_MAX_MS = int(os.getenv("VSCAN_PLAN_LARGE_MS", "2000"))
MAX_FILE_SIZE_BYTES = int(os.getenv("VSCAN_PLAN_FILE_LIMIT_BYTES", str(1_500_000_000)))


@dataclass(slots=True)
class ModuleStats:
    module_count: int = 0
    modules_with_resources: int = 0
    child_module_count: int = 0
    root_address: str = "root"


@dataclass(slots=True)
class PlanStreamResult:
    top_level: Dict[str, Any]
    resources: List[Dict[str, Any]]
    resource_changes: List[Dict[str, Any]]
    module_stats: ModuleStats
    file_size_bytes: int
    parse_duration_ms: int


class _CharStream:
    __slots__ = ("_fh", "_buffer", "_pos", "source")

    def __init__(self, fh, source: str):
        self._fh = fh
        self._buffer = ""
        self._pos = 0
        self.source = source

    def _ensure(self, size: int = 1) -> bool:
        while len(self._buffer) - self._pos < size:
            chunk = self._fh.read(65536)
            if not chunk:
                return False
            if self._pos == 0:
                self._buffer += chunk
            else:
                self._buffer = self._buffer[self._pos :] + chunk
                self._pos = 0
        return True

    def peek(self) -> str:
        if not self._ensure(1):
            return ""
        return self._buffer[self._pos]

    def read(self) -> str:
        ch = self.peek()
        if not ch:
            raise PlanStreamError("Unexpected end of JSON input")
        self._pos += 1
        return ch

    def expect(self, char: str) -> None:
        actual = self.read()
        if actual != char:
            raise PlanStreamError(f"Expected '{char}' but found '{actual}'")


class _JSONStream:
    __slots__ = ("chars",)

    def __init__(self, chars: _CharStream):
        self.chars = chars

    def _skip_ws(self) -> None:
        while True:
            ch = self.chars.peek()
            if ch and ch in " \t\r\n":
                self.chars.read()
                continue
            break

    def _scan_string(self) -> str:
        self.chars.expect('"')
        buf: List[str] = []
        while True:
            ch = self.chars.read()
            if ch == '"':
                break
            if ch == "\\":
                esc = self.chars.read()
                if esc in ('"', "\\", "/"):
                    buf.append(esc)
                elif esc == "b":
                    buf.append("\b")
                elif esc == "f":
                    buf.append("\f")
                elif esc == "n":
                    buf.append("\n")
                elif esc == "r":
                    buf.append("\r")
                elif esc == "t":
                    buf.append("\t")
                elif esc == "u":
                    hex_digits = ""
                    for _ in range(4):
                        hex_digits += self.chars.read()
                    buf.append(chr(int(hex_digits, 16)))
                else:
                    raise PlanStreamError(f"Invalid escape sequence \\{esc}")
            else:
                buf.append(ch)
        return "".join(buf)

    def _scan_number(self) -> Any:
        buf: List[str] = []
        ch = self.chars.peek()
        if ch == "-":
            buf.append(self.chars.read())
            ch = self.chars.peek()
        if not ch or not ch.isdigit():
            raise PlanStreamError("Invalid number literal")
        if ch == "0":
            buf.append(self.chars.read())
        else:
            while True:
                ch = self.chars.peek()
                if not ch or not ch.isdigit():
                    break
                buf.append(self.chars.read())
        ch = self.chars.peek()
        if ch == ".":
            buf.append(self.chars.read())
            ch = self.chars.peek()
            if not ch or not ch.isdigit():
                raise PlanStreamError("Invalid fractional number")
            while True:
                ch = self.chars.peek()
                if not ch or not ch.isdigit():
                    break
                buf.append(self.chars.read())
        ch = self.chars.peek()
        if ch in ("e", "E"):
            buf.append(self.chars.read())
            ch = self.chars.peek()
            if ch in ("+", "-"):
                buf.append(self.chars.read())
            ch = self.chars.peek()
            if not ch or not ch.isdigit():
                raise PlanStreamError("Invalid exponent in number")
            while True:
                ch = self.chars.peek()
                if not ch or not ch.isdigit():
                    break
                buf.append(self.chars.read())
        literal = "".join(buf)
        return float(literal) if ("." in literal or "e" in literal or "E" in literal) else int(literal)

    def _expect_literal(self, literal: str, value: Any) -> Any:
        for ch in literal:
            self.chars.expect(ch)
        return value

    def parse_value(self) -> Any:
        self._skip_ws()
        ch = self.chars.peek()
        if ch == "":
            raise PlanStreamError("Unexpected end of JSON data")
        if ch == '{':
            return self.parse_object()
        if ch == '[':
            return self.parse_array()
        if ch == '"':
            return self._scan_string()
        if ch in "-0123456789":
            return self._scan_number()
        if ch == "t":
            return self._expect_literal("true", True)
        if ch == "f":
            return self._expect_literal("false", False)
        if ch == "n":
            return self._expect_literal("null", None)
        raise PlanStreamError(f"Unexpected character {ch!r}")

    def discard_value(self) -> None:
        self._skip_ws()
        ch = self.chars.peek()
        if ch == '"':
            self._scan_string()
            return
        if ch in "-0123456789":
            self._scan_number()
            return
        if ch in "tfn":
            self.parse_value()
            return
        if ch == '[':
            self.chars.expect('[')
            first = True
            while True:
                self._skip_ws()
                nxt = self.chars.peek()
                if nxt == ']':
                    self.chars.read()
                    break
                if not first:
                    self.chars.expect(',')
                    self._skip_ws()
                self.discard_value()
                first = False
            return
        if ch == '{':
            self.chars.expect('{')
            first = True
            while True:
                self._skip_ws()
                nxt = self.chars.peek()
                if nxt == '}':
                    self.chars.read()
                    break
                if not first:
                    self.chars.expect(',')
                    self._skip_ws()
                key = self._scan_string()
                self._skip_ws()
                self.chars.expect(':')
                self.discard_value()
                first = False
            return
        raise PlanStreamError(f"Cannot discard value starting with {ch!r}")

    def parse_array(self, item_handler: Optional[Callable[[int, "_JSONStream"], bool]] = None) -> List[Any]:
        items: List[Any] = []
        self._skip_ws()
        self.chars.expect('[')
        index = 0
        first = True
        while True:
            self._skip_ws()
            ch = self.chars.peek()
            if ch == ']':
                self.chars.read()
                break
            if not first:
                self.chars.expect(',')
                self._skip_ws()
            if item_handler and item_handler(index, self):
                pass
            else:
                items.append(self.parse_value())
            index += 1
            first = False
        return items

    def parse_object(
        self,
        key_handler: Optional[Callable[[str, Dict[str, Any], "_JSONStream"], bool]] = None,
    ) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        self._skip_ws()
        self.chars.expect('{')
        first = True
        while True:
            self._skip_ws()
            ch = self.chars.peek()
            if ch == '}':
                self.chars.read()
                break
            if not first:
                self.chars.expect(',')
                self._skip_ws()
            key = self._scan_string()
            self._skip_ws()
            self.chars.expect(':')
            if key_handler and key_handler(key, obj, self):
                first = False
                continue
            obj[key] = self.parse_value()
            first = False
        return obj


class PlanStreamParser:
    """Streaming parser that extracts resources without loading full plans."""

    def __init__(self, path: Path):
        self.path = path
        self.resources: List[Dict[str, Any]] = []
        self.resource_changes: List[Dict[str, Any]] = []
        self.module_stats = ModuleStats()

    def parse(self) -> PlanStreamResult:
        start = time.perf_counter()
        file_size = self.path.stat().st_size
        with self.path.open("r", encoding="utf-8") as fh:
            stream = _JSONStream(_CharStream(fh, str(self.path)))
            top_level = stream.parse_object(self._handle_top_level)
        duration_ms = int(round((time.perf_counter() - start) * 1000))
        plan_stub = {
            "format_version": top_level.get("format_version"),
            "terraform_version": top_level.get("terraform_version"),
            "planned_values": top_level.get("planned_values", {"root_module": {"resources": []}}),
            "resource_changes": top_level.get("resource_changes", []),
        }
        return PlanStreamResult(
            top_level=plan_stub,
            resources=self.resources,
            resource_changes=plan_stub["resource_changes"],
            module_stats=self.module_stats,
            file_size_bytes=file_size,
            parse_duration_ms=duration_ms,
        )

    # Key handlers -----------------------------------------------------
    def _handle_top_level(self, key: str, obj: Dict[str, Any], parser: _JSONStream) -> bool:
        if key == "planned_values":
            obj[key] = self._parse_planned_values(parser)
            return True
        if key == "resource_changes":
            value = parser.parse_value()
            obj[key] = value if isinstance(value, list) else []
            self.resource_changes = obj[key]
            return True
        return False

    def _parse_planned_values(self, parser: _JSONStream) -> Dict[str, Any]:
        container: Dict[str, Any] = {"root_module": {"resources": [], "child_modules": []}}

        def handler(key: str, obj: Dict[str, Any], stream: _JSONStream) -> bool:
            if key == "root_module":
                obj[key] = self._parse_module(stream, "root")
                self.module_stats.root_address = obj[key].get("address", "root")
                obj[key]["resources"] = []
                obj[key].setdefault("child_modules", [])
                return True
            stream.discard_value()
            return True

        result = parser.parse_object(handler)
        if "root_module" not in result:
            raise PlanSchemaError("planned_values.root_module must be present")
        return container | result

    def _parse_module(self, parser: _JSONStream, fallback_address: str) -> Dict[str, Any]:
        self.module_stats.module_count += 1
        module_address = fallback_address
        module_has_resources = False
        module_repr: Dict[str, Any] = {"resources": [], "child_modules": []}

        def handler(key: str, obj: Dict[str, Any], stream: _JSONStream) -> bool:
            nonlocal module_address, module_has_resources
            if key == "address":
                value = stream.parse_value()
                if isinstance(value, str) and value.strip():
                    module_address = value
                    obj["address"] = value
                else:
                    obj["address"] = fallback_address
                return True
            if key == "resources":
                had_resources = self._parse_resource_array(stream, module_address)
                module_has_resources = module_has_resources or had_resources
                obj["resources"] = []
                return True
            if key == "child_modules":
                self._parse_child_modules(stream, module_address)
                obj["child_modules"] = []
                return True
            stream.discard_value()
            return True

        parser.parse_object(handler)
        if module_has_resources:
            self.module_stats.modules_with_resources += 1
        module_repr["address"] = module_address
        module_repr["resources"] = []
        module_repr["child_modules"] = []
        return module_repr

    def _parse_resource_array(self, parser: _JSONStream, module_address: str) -> bool:
        consumed_any = False

        def resource_handler(_: int, stream: _JSONStream) -> bool:
            nonlocal consumed_any
            resource = stream.parse_value()
            if isinstance(resource, dict):
                consumed_any = True
                if "module_address" not in resource:
                    resource["module_address"] = module_address
                resource.setdefault("address", self._build_address(module_address, resource))
                self.resources.append(resource)
            return True

        parser._skip_ws()
        next_char = parser.chars.peek()
        if next_char == 'n':
            parser.parse_value()
            return False
        if next_char != '[':
            raise PlanSchemaError("resources must be a list under planned_values.root_module")
        parser.parse_array(resource_handler)
        return consumed_any

    def _parse_child_modules(self, parser: _JSONStream, parent_address: str) -> None:
        parser._skip_ws()
        next_char = parser.chars.peek()
        if next_char == 'n':
            parser.parse_value()
            return
        if next_char != '[':
            raise PlanSchemaError("child_modules must be a list when present")

        def child_handler(index: int, stream: _JSONStream) -> bool:
            self.module_stats.child_module_count += 1
            fallback = f"{parent_address}.child[{index}]" if parent_address else f"child[{index}]"
            self._parse_module(stream, fallback)
            return True

        parser.parse_array(child_handler)

    @staticmethod
    def _build_address(module_address: str, resource: Dict[str, Any]) -> str:
        r_type = resource.get("type") or "resource"
        r_name = resource.get("name") or "unnamed"
        address = f"{r_type}.{r_name}"
        if module_address and module_address != "root":
            return f"{module_address}.{address}"
        return address


def stream_plan(path: Path) -> PlanStreamResult:
    parser = PlanStreamParser(path)
    return parser.parse()


def build_slo_metadata(resource_count: int, parse_duration_ms: int, file_size_bytes: int) -> Tuple[bool, Dict[str, Any]]:
    """Compute SLO/threshold metadata for plan parsing."""

    breach_reason: Optional[str] = None
    target_ms = FAST_PATH_MAX_MS
    slo_label = "fast_path"

    if resource_count <= FAST_PATH_RESOURCES:
        target_ms = FAST_PATH_MAX_MS
        slo_label = "fast_path"
    elif resource_count <= LARGE_PLAN_RESOURCES:
        target_ms = LARGE_PLAN_MAX_MS
        slo_label = "large_plan"
    else:
        target_ms = LARGE_PLAN_MAX_MS
        slo_label = "oversized"
        breach_reason = "resource_count"

    exceeds = False
    if not breach_reason and parse_duration_ms > target_ms:
        exceeds = True
        breach_reason = "parse_duration"
    if not breach_reason and file_size_bytes > MAX_FILE_SIZE_BYTES:
        exceeds = True
        breach_reason = "file_size"
    if breach_reason == "resource_count":
        exceeds = True

    slo_block = {
        "observed": {
            "resource_count": resource_count,
            "parse_duration_ms": parse_duration_ms,
            "file_size_bytes": file_size_bytes,
        },
        "thresholds": {
            "fast_path": {
                "max_resources": FAST_PATH_RESOURCES,
                "max_parse_ms": FAST_PATH_MAX_MS,
            },
            "large_plan": {
                "max_resources": LARGE_PLAN_RESOURCES,
                "max_parse_ms": LARGE_PLAN_MAX_MS,
            },
            "file_size_limit_bytes": MAX_FILE_SIZE_BYTES,
        },
        "active_window": slo_label,
        "breach_reason": breach_reason,
    }
    return exceeds, slo_block