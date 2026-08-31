"""OWASP ZAP JSON report normalization.

This module parses reports only. Command construction is guarded by safety.py.
"""

from __future__ import annotations

from typing import Any

from .base import candidate, location, read_json, require_list, require_mapping, text, tool_signal


def parse(payload: Any) -> list[dict[str, Any]]:
    document, digest = read_json(payload)
    root = require_mapping(document, "ZAP input")
    output: list[dict[str, Any]] = []
    for raw_site in require_list(root.get("site"), "ZAP sites"):
        site = require_mapping(raw_site, "ZAP site")
        for raw_alert in require_list(site.get("alerts"), "ZAP alerts"):
            alert = require_mapping(raw_alert, "ZAP alert")
            instances = require_list(alert.get("instances"), "ZAP instances") or [{}]
            for raw_instance in instances:
                instance = require_mapping(raw_instance, "ZAP instance")
                rule_id = alert.get("pluginid") or alert.get("alertRef") or alert.get("alert")
                claim = text(alert.get("alert"), text(rule_id, "ZAP alert"))
                output.append(
                    candidate(
                        source="zap",
                        source_type="passive-web-observation",
                        source_version=root.get("@version"),
                        rule_id=rule_id,
                        claim=claim,
                        digest=digest,
                        finding_location=location(uri=instance.get("uri") or site.get("@name")),
                        observations=[alert.get("desc"), instance.get("evidence"), alert.get("otherinfo")],
                        signal=tool_signal(
                            risk_code=alert.get("riskcode"),
                            risk_description=alert.get("riskdesc"),
                            confidence=alert.get("confidence"),
                        ),
                        properties={
                            "method": instance.get("method"),
                            "parameter": instance.get("param"),
                            "solution": alert.get("solution"),
                            "reference": alert.get("reference"),
                        },
                    )
                )
    return output
