"""
Data models of the VMRay module.

Field names on VMRay-sourced models follow the VMRay Platform REST API
(OpenAPI spec, v2026.2.1) verbatim. They are NOT renamed to Sekoia conventions,
so a field here can always be traced straight back to the API.

Types are intentionally loose (plain `str` rather than a `Literal`/enum) on
any VMRay-controlled value whose full set of possibilities was not directly
confirmed against real response bodies (verdict, severity, classification
strings). A strict Literal would raise on an unseen-but-valid value VMRay adds
later; a plain str degrades gracefully instead.
"""

from typing import Any

from pydantic import BaseModel, Field
from sekoia_automation.module import Module


def hide_empty_defaults(schema: dict[str, Any]) -> None:
    """Sekoia's playbook editor shows an input only when it has a plain `type`: optional inputs are typed
    `X | SkipJsonSchema[None]` so the schema carries no `null` branch, and their `"default": null` is dropped
    here — empty still means "not set" in the code."""
    for prop in schema.get("properties", {}).values():
        if "default" in prop and prop["default"] is None:
            del prop["default"]


# --------------------------------------------------------------------------
# Module configuration
# --------------------------------------------------------------------------


class VMRayConfiguration(BaseModel):
    base_url: str = Field(
        ...,
        title="Base URL",
        description="VMRay Platform URL, e.g. https://eu.cloud.vmray.com or an on-prem appliance URL",
        json_schema_extra={"format": "uri"},
    )
    api_key: str = Field(..., title="API Key", description="VMRay API key", json_schema_extra={"secret": True})
    verify_ssl: bool = Field(
        default=True,
        title="Verify SSL",
        description="Verify the TLS certificate of the VMRay Platform. "
        "Disable only for an on-prem appliance with a self-signed certificate.",
    )


class VMRayModule(Module):
    configuration: VMRayConfiguration
