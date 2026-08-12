# -*- coding: utf-8 -*-
"""Orchestrates all decomposers (Burp's own analyzeRequest for URL/cookie/
header params, plus our JSON/XML/multipart recursive decomposers for the
body) into one flat list[InsertionPoint]. This is the single code path
used both when a request is "armed" (building the template) and on every
live outgoing request (matching.py joins the two lists by `path`), which
is what makes the path-based re-matching design sound -- both sides are
always produced by the exact same logic.

Every leaf value this module extracts -- whether it's a whole JSON/XML
body, a single URL query parameter, a cookie, a header, an
x-www-form-urlencoded body field, or a simple multipart field -- is
checked for nested JSON/XML and recursively unravelled if found. A
parameter whose *value* happens to be a JSON blob is just as valid a
target as a JSON request body; the detection granularity must not depend
on which container the value happened to arrive in.

`on_error(msg)`, threaded through every entry point below, is purely
diagnostic: it's called whenever a leaf's value LOOKED like JSON/XML but
couldn't actually be parsed/expanded, so the reason is visible (Log tab)
instead of silently falling back to flat detection.

`lenient`, also threaded throughout, opts into json_offset_parser's
resync-based recovery as a second attempt when strict parsing fails --
this can rescue mildly-corrupted JSON (a stray character, a missing
comma) but is fundamentally a best-effort heuristic for genuinely
malformed input; points found this way come back with `.recovered = True`
so the UI can flag them rather than presenting them at full confidence.
Off by default: recovered results can land at the wrong nesting level if
the corruption goes deep enough, which is a real risk for a tool whose
whole point is precise byte-offset substitution.
"""

import traceback

from csvlistinput import json_offset_parser, multipart_decomposer, xml_offset_scanner
from csvlistinput.constants import BurpParamType, EscapeMode, InsertionPointType, NESTED_JSON_MARKER, NESTED_XML_MARKER
from csvlistinput.models import InsertionPoint
from csvlistinput.utils import bytes_to_bytestring, looks_like_json, looks_like_xml, url_decode_with_map


def _identity_decode(buf, start, end):
    """"Decode" function for values that are NOT transport-encoded in the
    raw buffer (headers, multipart simple fields) -- the raw slice already
    equals the effective value, so offsets need no translation."""
    return buf[start:end], list(range(start, end + 1))


def _report(on_error, msg):
    if on_error:
        try:
            on_error(msg)
        except Exception:
            pass


def _report_exc(on_error, prefix):
    """Like _report, but appends a full traceback -- for genuinely
    unexpected exceptions (not the routine JsonParseError/XML-parse-failure
    cases, which already have clear, targeted messages) where knowing the
    exact source line is what's actually needed to fix the bug. Collapsed
    to one line (" | "-joined) since the Log tab's Note column is a JTable
    cell -- easier to read and copy-paste there than embedded newlines."""
    if on_error:
        try:
            tb_lines = [ln for ln in traceback.format_exc().splitlines() if ln.strip()]
            on_error("%s %s" % (prefix, " | ".join(tb_lines)))
        except Exception:
            pass


def _make_recovered_reporter(on_error, label):
    def on_recovered(spans):
        if not spans:
            return
        preview = ", ".join("%d-%d" % (s, e) for s, e in spans[:5])
        if len(spans) > 5:
            preview += ", ..."
        _report(on_error, "%s: expanded via lenient recovery (malformed JSON) -- "
                           "treat these insertion points as approximate; skipped byte ranges: %s"
                           % (label, preview))
    return on_recovered


def _recurse_into_leaf_value(buf, ip, decode_fn, out_points, on_error=None, lenient=False):
    """Given a flat InsertionPoint `ip` (already appended to out_points),
    check whether its value is itself a serialized JSON or XML document
    and, if so, append deeper InsertionPoints for what's inside it --
    generalizes the nested-string sniff that json_offset_parser/
    xml_offset_scanner already do internally for JSON string leaves and
    XML text/attr nodes, to every OTHER kind of leaf this module produces
    (URL params, cookies, headers, form body fields, multipart fields).
    `decode_fn(buf, start, end) -> (decoded, decoded_to_raw)` accounts for
    whatever transport encoding (URL percent-encoding, or none) applies
    to that leaf's raw bytes.
    """
    try:
        decoded, decoded_to_raw = decode_fn(buf, ip.start, ip.end)
    except Exception:
        _report_exc(on_error, "%s: failed to decode value for nested JSON/XML check:" % ip.path)
        return
    stripped = decoded.strip()
    if not stripped:
        return

    def translator(local_pos):
        return decoded_to_raw[local_pos]

    if looks_like_json(stripped):
        inner = None
        try:
            inner = json_offset_parser.detect_in_text(
                decoded, translator, base_path=ip.path + NESTED_JSON_MARKER,
                start_depth=1, chain=[{'kind': 'json', 'container_path': ip.path}],
                allow_lenient=lenient, on_recovered=_make_recovered_reporter(on_error, ip.path),
                on_error=on_error)
        except Exception:
            _report_exc(on_error, "%s: looked like JSON but detection raised unexpectedly:" % ip.path)
        if inner:
            out_points.extend(inner)
        elif on_error:
            # detect_in_text() returns None only when it genuinely didn't
            # parse as JSON (even leniently) -- re-parse strictly just to
            # recover *why*, for diagnostics.
            try:
                json_offset_parser.parse(decoded)
            except json_offset_parser.JsonParseError as e:
                _report(on_error, "%s: looked like JSON but failed to parse (kept as a flat, "
                                   "unexpanded value): %s" % (ip.path, e))
    elif looks_like_xml(stripped):
        inner = None
        try:
            inner = xml_offset_scanner.detect_in_text(
                decoded, translator, base_path=ip.path + NESTED_XML_MARKER,
                start_depth=1, chain=[{'kind': 'xml', 'container_path': ip.path}])
        except Exception:
            _report_exc(on_error, "%s: looked like XML but detection raised unexpectedly:" % ip.path)
        if inner:
            out_points.extend(inner)


def _get_header_value(headers_list, name):
    name_lc = name.lower()
    for line in headers_list[1:]:
        colon = line.find(':')
        if colon == -1:
            continue
        if line[:colon].strip().lower() == name_lc:
            return line[colon + 1:].strip()
    return None


def _extract_header_points(buf, headers_list, body_offset, on_error=None, lenient=False):
    points = []
    first_line_end = buf.find('\r\n', 0)
    if first_line_end == -1:
        return points
    cursor = first_line_end + 2
    for line in headers_list[1:]:
        colon = line.find(':')
        if colon == -1:
            continue
        header_name = line[:colon].strip()
        header_lc = header_name.lower()
        search_target = header_name + ':'
        name_pos = buf.find(search_target, cursor, body_offset)
        if name_pos == -1:
            continue
        value_region_start = name_pos + len(search_target)
        line_end = buf.find('\r\n', value_region_start, body_offset)
        if line_end == -1:
            line_end = body_offset
        v_start = value_region_start
        while v_start < line_end and buf[v_start] in ' \t':
            v_start += 1
        v_end = line_end
        while v_end > v_start and buf[v_end - 1] in ' \t':
            v_end -= 1
        cursor = line_end + 2

        if header_lc in ('cookie', 'content-length'):
            # Cookie: individual pairs already come from analyzeRequest's
            # PARAM_COOKIE entries at finer granularity. Content-Length is
            # a derived value, never a meaningful independent point.
            continue

        path = 'header[' + header_name + ']'
        ip = InsertionPoint(
            path=path, type_=InsertionPointType.HEADER, start=v_start, end=v_end,
            original_value=buf[v_start:v_end], context=EscapeMode.RAW, nesting_depth=0)
        points.append(ip)
        _recurse_into_leaf_value(buf, ip, _identity_decode, points, on_error=on_error, lenient=lenient)
    return points


def _decompose_multipart_part(buf, part, out_points, on_error=None, lenient=False):
    body_start = part['body_start']
    body_end = part['body_end']
    if body_start >= body_end:
        return
    text = buf[body_start:body_end]
    ct = (part['content_type'] or '').lower()
    part_label = part['name'] if part['name'] else ('idx' + str(part['part_index']))
    prefix = 'multipart[' + part_label + ']'

    sub_points = None
    if 'json' in ct or (not ct and looks_like_json(text)):
        try:
            sub_points = json_offset_parser.detect(buf, body_start, body_end, allow_lenient=lenient,
                                                     on_recovered=_make_recovered_reporter(on_error, prefix),
                                                     on_error=on_error)
        except Exception:
            _report_exc(on_error, "%s: JSON detection raised unexpectedly:" % prefix)
        if sub_points is None and on_error:
            try:
                json_offset_parser.parse(text)
            except json_offset_parser.JsonParseError as e:
                _report(on_error, "%s: looked like JSON but failed to parse: %s" % (prefix, e))
    elif 'xml' in ct or (not ct and looks_like_xml(text)):
        try:
            sub_points = xml_offset_scanner.detect(buf, body_start, body_end)
        except Exception:
            _report_exc(on_error, "%s: XML detection raised unexpectedly:" % prefix)

    if not sub_points:
        return
    for p in sub_points:
        p.path = prefix + p.path
        p.multipart_part_index = part['part_index']
        if p.type in (InsertionPointType.JSON_LEAF, InsertionPointType.XML_TEXT, InsertionPointType.XML_ATTR):
            p.type = InsertionPointType.MULTIPART_BODY_LEAF
        out_points.append(p)


def _add_multipart_attr_params(request_info, buf, out_points, on_error=None, lenient=False):
    for param in request_info.getParameters():
        if param.getType() != BurpParamType.MULTIPART_ATTR:
            continue
        start = param.getValueStart()
        end = param.getValueEnd()
        name = param.getName()
        ip = InsertionPoint(
            path='multipart[' + name + ']', type_=InsertionPointType.MULTIPART_ATTR,
            start=start, end=end, original_value=buf[start:end], context=EscapeMode.RAW)
        out_points.append(ip)
        _recurse_into_leaf_value(buf, ip, _identity_decode, out_points, on_error=on_error, lenient=lenient)


def _add_body_fallback_params(request_info, buf, out_points, on_error=None, lenient=False):
    for param in request_info.getParameters():
        if param.getType() != BurpParamType.BODY:
            continue
        start = param.getValueStart()
        end = param.getValueEnd()
        name = param.getName()
        ip = InsertionPoint(
            path='body[' + name + ']', type_=InsertionPointType.BODY_PARAM,
            start=start, end=end, original_value=buf[start:end], context=EscapeMode.URL_COMPONENT)
        out_points.append(ip)
        # x-www-form-urlencoded values are percent-encoded in the raw buffer.
        _recurse_into_leaf_value(buf, ip, lambda b, s, e: url_decode_with_map(b, s, e, True),
                                  out_points, on_error=on_error, lenient=lenient)


def _process_body(request_info, buf, out_points, on_error=None, lenient=False):
    body_offset = request_info.getBodyOffset()
    body_end = len(buf)
    if body_offset >= body_end:
        return
    headers_list = list(request_info.getHeaders())
    content_type = _get_header_value(headers_list, 'content-type') or ''
    ct_lower = content_type.lower()
    body_text = buf[body_offset:body_end]

    if 'multipart/form-data' in ct_lower:
        try:
            boundary = multipart_decomposer.parse_boundary(content_type)
            parts = multipart_decomposer.decompose(buf, body_offset, body_end, boundary) if boundary else []
            for part in parts:
                _decompose_multipart_part(buf, part, out_points, on_error=on_error, lenient=lenient)
            _add_multipart_attr_params(request_info, buf, out_points, on_error=on_error, lenient=lenient)
        except Exception:
            _report_exc(on_error, "multipart body detection raised:")
        return

    if 'json' in ct_lower or looks_like_json(body_text):
        json_points = None
        try:
            json_points = json_offset_parser.detect(buf, body_offset, body_end, allow_lenient=lenient,
                                                      on_recovered=_make_recovered_reporter(on_error, "body"),
                                                      on_error=on_error)
        except Exception:
            _report_exc(on_error, "JSON body detection raised unexpectedly:")
        if json_points is not None:
            out_points.extend(json_points)
            return
        # detect() returns None only when the body genuinely didn't parse as
        # JSON (even leniently) -- re-parse strictly just to recover *why*.
        try:
            json_offset_parser.parse(body_text)
        except json_offset_parser.JsonParseError as e:
            _report(on_error, "Body looked like JSON but failed to parse (falling back to flat "
                              "body-parameter detection): %s" % e)
        # Content-Type claimed JSON but it didn't actually parse -- fall
        # through to XML/flat-parameter detection below.

    if 'xml' in ct_lower or looks_like_xml(body_text):
        try:
            xml_points = xml_offset_scanner.detect(buf, body_offset, body_end)
        except Exception as e:
            xml_points = []
            _report(on_error, "XML body detection raised: %s" % e)
        out_points.extend(xml_points)
        return

    _add_body_fallback_params(request_info, buf, out_points, on_error=on_error, lenient=lenient)


def detect(helpers, request_bytes, http_service=None, on_error=None, lenient=False):
    """Detect all insertion points in `request_bytes` (a Java byte[] as
    returned by IHttpRequestResponse.getRequest()/messageInfo.getRequest()).
    Returns list[InsertionPoint] with offsets absolute against the
    byte-string form of request_bytes (see utils.bytes_to_bytestring --
    callers must use that same conversion when splicing). `on_error(msg)`,
    if given, is called with a human-readable string for any body-parsing
    problem encountered along the way -- detection still proceeds and
    returns whatever it could find (URL/cookie/header points are collected
    independently of body parsing), this is purely diagnostic. `lenient`
    opts into best-effort recovery for malformed JSON (see module
    docstring) -- resulting points are marked `.recovered = True`.
    """
    buf = bytes_to_bytestring(helpers, request_bytes)
    if http_service is not None:
        request_info = helpers.analyzeRequest(http_service, request_bytes)
    else:
        request_info = helpers.analyzeRequest(request_bytes)

    points = []
    for param in request_info.getParameters():
        ptype = param.getType()
        if ptype == BurpParamType.URL:
            start, end = param.getValueStart(), param.getValueEnd()
            ip = InsertionPoint(
                path='url[' + param.getName() + ']', type_=InsertionPointType.URL_PARAM,
                start=start, end=end, original_value=buf[start:end], context=EscapeMode.URL_COMPONENT)
            points.append(ip)
            # Query string values are percent-encoded in the raw buffer.
            _recurse_into_leaf_value(buf, ip, lambda b, s, e: url_decode_with_map(b, s, e, True),
                                      points, on_error=on_error, lenient=lenient)
        elif ptype == BurpParamType.COOKIE:
            start, end = param.getValueStart(), param.getValueEnd()
            ip = InsertionPoint(
                path='cookie[' + param.getName() + ']', type_=InsertionPointType.COOKIE,
                start=start, end=end, original_value=buf[start:end], context=EscapeMode.URL_COMPONENT)
            points.append(ip)
            # Cookies aren't form-urlencoded by spec, but %XX escaping of
            # special characters is common; '+' is left literal (not
            # decoded to space) since cookies don't share that convention.
            _recurse_into_leaf_value(buf, ip, lambda b, s, e: url_decode_with_map(b, s, e, False),
                                      points, on_error=on_error, lenient=lenient)
        # PARAM_BODY/PARAM_XML/PARAM_XML_ATTR/PARAM_MULTIPART_ATTR/PARAM_JSON are
        # deliberately NOT taken from analyzeRequest here -- the body is handled
        # by our own recursive decomposers below for Burp-Scanner-equivalent (or
        # deeper) granularity. PARAM_BODY is used only as a fallback when the
        # body isn't JSON/XML/multipart. PARAM_MULTIPART_ATTR is added within
        # the multipart branch.

    points.extend(_extract_header_points(buf, list(request_info.getHeaders()), request_info.getBodyOffset(),
                                          on_error=on_error, lenient=lenient))

    try:
        _process_body(request_info, buf, points, on_error=on_error, lenient=lenient)
    except Exception:
        # Never let a body-parsing edge case take down the whole detection
        # pass -- URL/header/cookie points already collected are still useful.
        _report_exc(on_error, "body detection raised unexpectedly:")

    return points
