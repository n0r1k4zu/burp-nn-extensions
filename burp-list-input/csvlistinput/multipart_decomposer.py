# -*- coding: utf-8 -*-
"""Boundary-aware multipart/form-data splitter. Yields each part's own
headers plus absolute (start, end) byte offsets of its body, so the
JSON/XML decomposers can be applied inside file-upload parts whose
payload happens to be structured data (e.g. a JSON blob uploaded as a
form field). Simple text fields are already covered by
IExtensionHelpers.analyzeRequest's PARAM_MULTIPART_ATTR and are not
duplicated here.
"""

import re

_BOUNDARY_RE = re.compile(r'(?i)boundary\s*=\s*("([^"]*)"|[^;]+)')


def parse_boundary(content_type_header_value):
    if not content_type_header_value:
        return None
    m = _BOUNDARY_RE.search(content_type_header_value)
    if not m:
        return None
    value = m.group(2) if m.group(2) is not None else m.group(1)
    return value.strip()


def _parse_part_headers(header_block):
    headers = {}
    for line in header_block.split('\r\n'):
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return headers


_DISPOSITION_FIELD_RE_CACHE = {}


def _extract_disposition_field(disposition_value, field_name):
    rx = _DISPOSITION_FIELD_RE_CACHE.get(field_name)
    if rx is None:
        rx = re.compile(field_name + r'="([^"]*)"')
        _DISPOSITION_FIELD_RE_CACHE[field_name] = rx
    m = rx.search(disposition_value or '')
    return m.group(1) if m else None


def decompose(buf, body_start, body_end, boundary):
    """Split buf[body_start:body_end] (a multipart/form-data body) into
    parts. Returns a list of dicts:
      {part_index, name, filename, content_type, headers,
       body_start, body_end}
    where body_start/body_end are absolute offsets into `buf`.
    Tolerant of malformed input: returns whatever parts were
    successfully parsed before giving up.
    """
    if not boundary:
        return []
    delim = '--' + boundary
    parts = []
    pos = body_start
    part_index = 0
    try:
        while True:
            delim_pos = buf.find(delim, pos, body_end)
            if delim_pos == -1:
                break
            after_delim = delim_pos + len(delim)
            if buf[after_delim:after_delim + 2] == '--':
                break  # closing boundary
            line_end = buf.find('\r\n', after_delim, body_end)
            if line_end == -1:
                break
            part_headers_start = line_end + 2
            headers_end = buf.find('\r\n\r\n', part_headers_start, body_end)
            if headers_end == -1:
                break
            part_body_start = headers_end + 4
            next_delim_pos = buf.find('\r\n--' + boundary, part_body_start, body_end)
            part_body_end = next_delim_pos if next_delim_pos != -1 else body_end

            header_block = buf[part_headers_start:headers_end]
            headers = _parse_part_headers(header_block)
            content_type = headers.get('content-type', '')
            disposition = headers.get('content-disposition', '')
            name = _extract_disposition_field(disposition, 'name')
            filename = _extract_disposition_field(disposition, 'filename')

            parts.append({
                'part_index': part_index,
                'name': name,
                'filename': filename,
                'content_type': content_type,
                'headers': headers,
                'body_start': part_body_start,
                'body_end': part_body_end,
            })
            part_index += 1
            pos = part_body_end
    except Exception:
        pass
    return parts
