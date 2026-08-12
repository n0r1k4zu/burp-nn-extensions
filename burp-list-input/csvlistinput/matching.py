# -*- coding: utf-8 -*-
"""Joins an ArmedTarget's saved path -> column mapping against a freshly
re-detected live insertion-point list (never against stale offsets), and
resolves connection signatures. This is the core of the "never trust
persisted offsets across sends" design -- see detection_engine.detect,
which both arm-time and live-time callers run identically.
"""

from csvlistinput.constants import PointStatus
from csvlistinput.models import ConnectionSignature, Edit, PointResult
from csvlistinput.substitution_engine import is_ancestor_path
from csvlistinput.utils import escape_for_context


def signature_from_message(helpers, http_service, request_bytes):
    request_info = helpers.analyzeRequest(http_service, request_bytes)
    url = request_info.getUrl()
    return ConnectionSignature(
        protocol=http_service.getProtocol(),
        host=http_service.getHost(),
        port=http_service.getPort(),
        method=request_info.getMethod(),
        url_path=url.getPath())


def find_conflicting_mapped_paths(mapped_paths):
    """Return the set of paths that should be dropped because a mapped
    ancestor also covers them (byte-range overlap once a live buffer
    exists). The UI is expected to prevent this configuration in the
    first place; this is a runtime safety net."""
    conflicts = set()
    for a in mapped_paths:
        for b in mapped_paths:
            if a != b and is_ancestor_path(a, b):
                conflicts.add(b)
    return conflicts


def build_edits(armed_target, live_points, row_values, helpers):
    """Returns (edits: list[Edit], point_results: list[PointResult])."""
    live_by_path = dict((p.path, p) for p in live_points)
    mapping_items = [(path, column) for path, column in armed_target.mapping.items() if column]
    conflict_paths = find_conflicting_mapped_paths([path for path, _ in mapping_items])

    edits = []
    results = []
    for path, column in mapping_items:
        if path in conflict_paths:
            results.append(PointResult(path, column, PointStatus.SKIPPED_OVERLAP_CONFLICT))
            continue

        live_ip = live_by_path.get(path)
        if live_ip is None:
            results.append(PointResult(path, column, PointStatus.SKIPPED_PATH_MISSING))
            continue

        template_ip = armed_target.template_points_by_path.get(path)
        if template_ip is not None and template_ip.type != live_ip.type:
            results.append(PointResult(path, column, PointStatus.SKIPPED_TYPE_MISMATCH))
            continue

        raw_value = row_values.get(column)
        if raw_value is None:
            results.append(PointResult(path, column, PointStatus.SKIPPED_PATH_MISSING))
            continue

        escape_mode = armed_target.get_escape_override(path)
        replacement = escape_for_context(
            raw_value, live_ip, escape_mode, helpers=helpers,
            allow_crlf_in_headers=armed_target.allow_crlf_in_headers,
            payload_encoding=armed_target.payload_text_encoding)
        edits.append(Edit(live_ip.start, live_ip.end, replacement, path=path))
        results.append(PointResult(path, column, PointStatus.OK, preview_value=raw_value))

    return edits, results
