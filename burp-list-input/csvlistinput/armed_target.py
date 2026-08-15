# -*- coding: utf-8 -*-
"""Holds the single "armed" target request: its connection signature, the
template insertion-point list (detected once at arm time), the user's
path -> CSV-column mapping, and per-path escape overrides.

v1 supports exactly one armed target at a time, matching the requirement's
framing of a single specified test-target packet.
"""

from csvlistinput.constants import DEFAULT_ENABLED_TOOL_FLAGS, EscapeMode


class ArmedTarget(object):
    def __init__(self):
        self.connection_signature = None
        self.template_points = []
        self.template_points_by_path = {}
        self.mapping = {}             # path -> column_name
        self.escape_overrides = {}    # path -> EscapeMode (absent == Auto)
        self.enabled_tool_flags = set(DEFAULT_ENABLED_TOOL_FLAGS)
        self.allow_crlf_in_headers = False
        self.payload_text_encoding = 'utf-8'  # how CSV payload text is encoded into the request buffer
        # When a request from a NON-enabled tool hits the same host/path as
        # the armed target, log a DIAGNOSTIC entry so the user can discover
        # which tool flag to enable (useful when hunting for a macro's
        # actual toolFlag). Off by default -- once the right flag is known,
        # this just adds noise from ordinary browsing/Proxy traffic to the
        # same endpoint.
        self.log_diagnostics_for_other_tools = False
        # Best-effort recovery for malformed nested JSON (a stray character,
        # a missing comma) -- see detection_engine's module docstring. Off
        # by default: recovered results can land at the wrong nesting level
        # for deeply-corrupted input, which is a real risk for a tool whose
        # whole point is precise byte-offset substitution.
        self.allow_lenient_json = False
        self.active = False
        self.original_request_bytes = None
        self.http_service = None
        self.label = None  # short display string, e.g. "POST /api/register"

    def arm(self, connection_signature, template_points, http_service, request_bytes, label=None):
        self.connection_signature = connection_signature
        self.template_points = template_points
        self.template_points_by_path = dict((p.path, p) for p in template_points)
        self.http_service = http_service
        self.original_request_bytes = request_bytes
        # Arming/re-detecting only captures the template. Activation is an
        # explicit user choice; never turn it on as a side effect.
        self.label = label
        # Drop stale mapping/override entries for paths that no longer exist
        # (e.g. re-arming against a differently-shaped request).
        self.mapping = dict((k, v) for k, v in self.mapping.items() if k in self.template_points_by_path)
        self.escape_overrides = dict((k, v) for k, v in self.escape_overrides.items()
                                      if k in self.template_points_by_path)

    def disarm(self):
        self.active = False

    def is_armed(self):
        return self.connection_signature is not None

    def set_mapping(self, path, column_name):
        if not column_name:
            self.mapping.pop(path, None)
        else:
            self.mapping[path] = column_name

    def get_mapping(self, path):
        return self.mapping.get(path)

    def set_escape_override(self, path, mode):
        if not mode or mode == EscapeMode.AUTO:
            self.escape_overrides.pop(path, None)
        else:
            self.escape_overrides[path] = mode

    def get_escape_override(self, path):
        return self.escape_overrides.get(path, EscapeMode.AUTO)

    def mapped_count(self):
        return len([1 for v in self.mapping.values() if v])
