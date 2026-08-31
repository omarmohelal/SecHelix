"""Small JSON Schema 2020-12 validator for SecHelix's checked-in contracts.

The project deliberately has no runtime package dependency.  This module implements
the schema keywords used by ``schemas/*.schema.json`` and rejects unsupported remote
references.  It is not intended to replace a general-purpose JSON Schema library.
"""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Iterable


def _json_equal(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _is_type(value: Any, expected: str) -> bool:
    return {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
        "null": lambda: value is None,
    }.get(expected, lambda: False)()


def _path(parent: str, child: str | int) -> str:
    return f"{parent}[{child}]" if isinstance(child, int) else f"{parent}.{child}"


class SchemaValidator:
    """Validate instances against a local schema and its sibling schema files."""

    def __init__(self, schema: dict[str, Any], schema_path: Path):
        self.schema = schema
        self.schema_path = schema_path.resolve()
        self._cache: dict[Path, dict[str, Any]] = {self.schema_path: schema}

    @classmethod
    def from_path(cls, path: str | Path) -> "SchemaValidator":
        schema_path = Path(path)
        with schema_path.open(encoding="utf-8") as handle:
            return cls(json.load(handle), schema_path)

    def validate(self, instance: Any) -> list[str]:
        errors: list[str] = []
        self._validate(instance, self.schema, "$", self.schema, self.schema_path, errors)
        return errors

    def _resolve_ref(
        self,
        ref: str,
        root: dict[str, Any],
        schema_path: Path,
    ) -> tuple[dict[str, Any], dict[str, Any], Path]:
        document, _, fragment = ref.partition("#")
        if document:
            if "://" in document:
                raise ValueError(f"remote schema reference is not allowed: {ref}")
            target_path = (schema_path.parent / document).resolve()
            if target_path not in self._cache:
                with target_path.open(encoding="utf-8") as handle:
                    self._cache[target_path] = json.load(handle)
            root = self._cache[target_path]
            schema_path = target_path
        target: Any = root
        if fragment:
            if not fragment.startswith("/"):
                raise ValueError(f"unsupported schema fragment: {ref}")
            for token in fragment[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                target = target[token]
        return target, root, schema_path

    def _validate(
        self,
        value: Any,
        schema: Any,
        instance_path: str,
        root: dict[str, Any],
        schema_path: Path,
        errors: list[str],
    ) -> None:
        if schema is True:
            return
        if schema is False:
            errors.append(f"{instance_path}: value is forbidden by schema")
            return
        if "$ref" in schema:
            try:
                target, target_root, target_path = self._resolve_ref(schema["$ref"], root, schema_path)
                self._validate(value, target, instance_path, target_root, target_path, errors)
            except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{instance_path}: invalid schema reference {schema['$ref']!r}: {exc}")
            return

        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword not in schema:
                continue
            results: list[list[str]] = []
            for option in schema[keyword]:
                option_errors: list[str] = []
                self._validate(value, option, instance_path, root, schema_path, option_errors)
                results.append(option_errors)
            matches = sum(not result for result in results)
            if keyword == "allOf":
                for result in results:
                    errors.extend(result)
            elif keyword == "anyOf" and matches == 0:
                errors.append(f"{instance_path}: value does not match any allowed schema")
            elif keyword == "oneOf" and matches != 1:
                errors.append(f"{instance_path}: value must match exactly one allowed schema")

        if "const" in schema and not _json_equal(value, schema["const"]):
            errors.append(f"{instance_path}: expected constant {schema['const']!r}")
        if "enum" in schema and not any(_json_equal(value, item) for item in schema["enum"]):
            errors.append(f"{instance_path}: {value!r} is not one of {schema['enum']!r}")

        expected = schema.get("type")
        if expected:
            expected_types = [expected] if isinstance(expected, str) else expected
            if not any(_is_type(value, item) for item in expected_types):
                errors.append(f"{instance_path}: expected type {expected!r}, got {type(value).__name__}")
                return

        if isinstance(value, dict):
            properties = schema.get("properties", {})
            patterns = [(re.compile(pattern), subschema) for pattern, subschema in schema.get("patternProperties", {}).items()]
            for required in schema.get("required", []):
                if required not in value:
                    errors.append(f"{instance_path}: missing required property {required!r}")
            for key, item in value.items():
                matched = False
                if key in properties:
                    matched = True
                    self._validate(item, properties[key], _path(instance_path, key), root, schema_path, errors)
                for pattern, subschema in patterns:
                    if pattern.search(key):
                        matched = True
                        self._validate(item, subschema, _path(instance_path, key), root, schema_path, errors)
                if not matched:
                    additional = schema.get("additionalProperties", True)
                    if additional is False:
                        errors.append(f"{instance_path}: additional property {key!r} is not allowed")
                    elif isinstance(additional, dict):
                        self._validate(item, additional, _path(instance_path, key), root, schema_path, errors)
            if len(value) < schema.get("minProperties", 0):
                errors.append(f"{instance_path}: object has too few properties")

        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                errors.append(f"{instance_path}: expected at least {schema['minItems']} items")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                errors.append(f"{instance_path}: expected at most {schema['maxItems']} items")
            if schema.get("uniqueItems"):
                seen: set[str] = set()
                for index, item in enumerate(value):
                    marker = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    if marker in seen:
                        errors.append(f"{_path(instance_path, index)}: duplicate array item")
                    seen.add(marker)
            if isinstance(schema.get("items"), dict):
                for index, item in enumerate(value):
                    self._validate(item, schema["items"], _path(instance_path, index), root, schema_path, errors)

        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0):
                errors.append(f"{instance_path}: string is shorter than {schema['minLength']}")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errors.append(f"{instance_path}: string is longer than {schema['maxLength']}")
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                errors.append(f"{instance_path}: string does not match {schema['pattern']!r}")
            if schema.get("format") == "date-time":
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("timezone is required")
                except ValueError:
                    errors.append(f"{instance_path}: expected an RFC 3339 date-time with timezone")

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(f"{instance_path}: value is below minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(f"{instance_path}: value is above maximum {schema['maximum']}")


def validate_schema(instance: Any, schema_path: str | Path) -> list[str]:
    """Return stable, human-readable validation errors (empty means valid)."""

    return SchemaValidator.from_path(schema_path).validate(instance)
