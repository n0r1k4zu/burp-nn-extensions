# -*- coding: utf-8 -*-
"""Splits a request/response buffer (byte-string space -- see utils.py)
into the Method/Path/Headers/Body byte spans Match & Replace's scope
checkboxes refer to. Deliberately flat/regex-based rather than reusing
detection_engine's JSON/XML-aware machinery -- Match & Replace operates on
raw text within a region, not on structurally-detected leaf values.
"""

import re

_REQUEST_LINE_RE = re.compile(r'^(\S+)([ \t]+)(\S+)(?:[ \t]+\S+)?\r?\n')


def request_regions(helpers, http_service, request_bytes, buf):
    """Returns {'method': (s,e) or None, 'path': (s,e) or None,
    'headers': (s,e), 'body': (s,e), 'body_offset': int}."""
    info = helpers.analyzeRequest(http_service, request_bytes)
    body_offset = info.getBodyOffset()

    m = _REQUEST_LINE_RE.match(buf)
    method_span = (m.start(1), m.end(1)) if m else None
    path_span = (m.start(3), m.end(3)) if m else None
    line_end = m.end() if m else 0

    return {
        'method': method_span,
        'path': path_span,
        'headers': (line_end, body_offset),
        'body': (body_offset, len(buf)),
        'body_offset': body_offset,
    }


def response_regions(helpers, response_bytes, buf):
    """No Method/Path concept for a response -- always None."""
    info = helpers.analyzeResponse(response_bytes)
    body_offset = info.getBodyOffset()

    head = buf[:body_offset]
    if '\r\n' in head:
        line_end = head.find('\r\n') + 2
    elif '\n' in head:
        line_end = head.find('\n') + 1
    else:
        line_end = 0

    return {
        'method': None,
        'path': None,
        'headers': (line_end, body_offset),
        'body': (body_offset, len(buf)),
        'body_offset': body_offset,
    }
