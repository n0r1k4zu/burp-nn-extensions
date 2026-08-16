# -*- coding: utf-8 -*-
"""Applies a ReplaceRuleStore's enabled rules to whichever packet regions
are in scope (see replace_settings.py / packet_regions.py), then hands the
resulting per-region edits to substitution_engine.substitute() for the
same descending-offset splice + Content-Length patch used by CSV
Insertion Point substitution -- this module only decides *what* to
replace, not how to safely splice bytes.
"""

import re

from csvlistinput import packet_regions, substitution_engine
from csvlistinput.models import Edit
from csvlistinput.utils import bytes_to_bytestring, bytestring_to_bytes, to_bytestring_space, coerce_boolean


def _region_spans_for_scope(regions, settings):
    spans = []
    if settings.scope_method and regions['method']:
        spans.append(regions['method'])
    if settings.scope_path and regions['path']:
        spans.append(regions['path'])
    if settings.scope_headers:
        spans.append(regions['headers'])
    if settings.scope_body:
        spans.append(regions['body'])
    return spans


def _apply_rules_to_text(text, rules):
    """Applies `rules` top-to-bottom, each seeing the previous rule's
    output (cumulative, matching Burp's own Match and Replace semantics).
    Returns (new_text, applied_count)."""
    applied = 0
    for rule in rules:
        before = to_bytestring_space(rule.before)
        after = to_bytestring_space(rule.after)
        if not before:
            continue
        if coerce_boolean(rule.is_regex):
            try:
                pattern = re.compile(before)
            except re.error:
                continue  # malformed regex -- skip this rule rather than crash the listener
            try:
                new_text, n = pattern.subn(after, text)
            except re.error:
                continue  # e.g. bad backreference in `after`
        else:
            n = text.count(before)
            new_text = text.replace(before, after)
        if n:
            applied += n
            text = new_text
    return text, applied


def _apply(helpers, buf, regions, rule_store, settings):
    rules = rule_store.enabled_rules()
    edits = []
    total_applied = 0
    for span in _region_spans_for_scope(regions, settings):
        start, end = span
        new_text, applied = _apply_rules_to_text(buf[start:end], rules)
        if applied:
            edits.append(Edit(start, end, new_text))
            total_applied += applied
    if not edits:
        return None, 0
    new_buf, _accepted, _skipped = substitution_engine.substitute(buf, edits, body_offset=regions['body_offset'])
    return new_buf, total_applied


def apply_to_request(helpers, http_service, request_bytes, rule_store, settings):
    """Returns (new_request_bytes, applied_count). Caller is responsible
    for checking settings.enabled / toolFlag before calling this."""
    buf = bytes_to_bytestring(helpers, request_bytes)
    regions = packet_regions.request_regions(helpers, http_service, request_bytes, buf)
    new_buf, applied = _apply(helpers, buf, regions, rule_store, settings)
    if new_buf is None:
        return request_bytes, 0
    return bytestring_to_bytes(helpers, new_buf), applied


def apply_to_response(helpers, response_bytes, rule_store, settings):
    """Returns (new_response_bytes, applied_count)."""
    buf = bytes_to_bytestring(helpers, response_bytes)
    regions = packet_regions.response_regions(helpers, response_bytes, buf)
    new_buf, applied = _apply(helpers, buf, regions, rule_store, settings)
    if new_buf is None:
        return response_bytes, 0
    return bytestring_to_bytes(helpers, new_buf), applied
