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

``detect()`` is intentionally a compatibility facade.  Its implementation is
split into DetectionContext (one Burp analysis), DetectionPipeline (ordered
transport/header/body stages), and DetectionEngine (bounded caching/resource
policy).  Every feature should call this facade or an explicitly configured
DetectionEngine rather than invoking an individual decomposer directly.
"""

import hashlib
import threading
import traceback
from collections import OrderedDict

from csvlistinput import json_offset_parser, multipart_decomposer, xml_offset_scanner
from csvlistinput.constants import BurpParamType, EscapeMode, InsertionPointType, NESTED_JSON_MARKER, NESTED_XML_MARKER
from csvlistinput.models import InsertionPoint
from csvlistinput.utils import bytes_to_bytestring, looks_like_json, looks_like_xml, url_decode_with_map


# These defaults are deliberately conservative enough not to affect normal
# application traffic, while giving every consumer of this module the same
# protection against pathological history entries.  Callers that need legacy
# unlimited-body behaviour can construct DetectionEngine(max_body_bytes=None).
DEFAULT_CACHE_SIZE = 64
DEFAULT_MAX_CACHEABLE_BYTES = 1024 * 1024
DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_JSON_STRUCTURE_DEPTH = 256
DEFAULT_MAX_PERCENT_DECODE_LAYERS = 3


def _clone_point(point):
    """Return an independent copy suitable for crossing a cache boundary.

    UI code is allowed to retain and annotate the returned points.  Returning
    the cache's own instances would therefore make one tab capable of changing
    the result later observed by another tab.
    """
    clone = InsertionPoint(
        path=point.path, type_=point.type, start=point.start, end=point.end,
        original_value=point.original_value, context=point.context,
        nesting_depth=point.nesting_depth,
        container_chain=[dict(item) for item in point.container_chain],
        quote_char=point.quote_char,
        multipart_part_index=point.multipart_part_index)
    clone.recovered = bool(getattr(point, 'recovered', False))
    return clone


def _clone_points(points):
    return [_clone_point(point) for point in points]


def _service_cache_key(http_service):
    if http_service is None:
        return None
    try:
        return (http_service.getProtocol(), http_service.getHost(), http_service.getPort())
    except Exception:
        # An unusual/custom IHttpService implementation should not prevent
        # detection.  Disabling cache reuse for it is safer than guessing.
        return ('uncacheable-service', id(http_service))


def _json_structure_depth_exceeds(text, maximum):
    """Cheap, string-aware guard for structurally pathological JSON.

    This is not a parser and does not decide validity.  It only counts object
    and array delimiters outside quoted strings before the recursive parser is
    entered.  Exact parsing and byte offsets remain the parser's responsibility.
    """
    if maximum is None:
        return False
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == '{' or ch == '[':
            depth += 1
            if depth > maximum:
                return True
        elif ch == '}' or ch == ']':
            if depth:
                depth -= 1
    return False


def _deduplicate_points(points):
    """Suppress only byte-identical discoveries, preserving first-seen order.

    Repeated parameter names at different offsets remain distinct.  This only
    removes the same structural point emitted twice by overlapping analyzers.
    """
    seen = set()
    unique = []
    for point in points:
        key = (point.path, point.type, point.start, point.end)
        if key in seen:
            continue
        seen.add(key)
        unique.append(point)
    return unique


class DetectionContext(object):
    """Immutable request-analysis inputs shared by all detection stages."""

    def __init__(self, helpers, request_bytes, http_service, buf, request_info,
                 on_error=None, lenient=False, max_body_bytes=None,
                 max_json_structure_depth=None):
        self.helpers = helpers
        self.request_bytes = request_bytes
        self.http_service = http_service
        self.buf = buf
        self.request_info = request_info
        self.headers = list(request_info.getHeaders())
        self.body_offset = request_info.getBodyOffset()
        self.on_error = on_error
        self.lenient = lenient
        self.max_body_bytes = max_body_bytes
        self.max_json_structure_depth = max_json_structure_depth


class DetectionEngine(object):
    """Reusable, thread-safe request detector with a bounded result cache.

    The public module-level ``detect`` function delegates to one instance of
    this class, so Target Mapping, Decode/Replace, and Parameters all use the
    exact same pipeline.  A separate instance is useful in tests or
    when a caller needs different resource limits.
    """

    def __init__(self, cache_size=DEFAULT_CACHE_SIZE,
                 max_cacheable_bytes=DEFAULT_MAX_CACHEABLE_BYTES,
                 max_body_bytes=DEFAULT_MAX_BODY_BYTES,
                 max_json_structure_depth=DEFAULT_MAX_JSON_STRUCTURE_DEPTH):
        self.cache_size = max(0, int(cache_size or 0))
        self.max_cacheable_bytes = max_cacheable_bytes
        self.max_body_bytes = max_body_bytes
        self.max_json_structure_depth = max_json_structure_depth
        self._cache = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def clear_cache(self):
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def cache_stats(self):
        with self._lock:
            return {'hits': self._hits, 'misses': self._misses,
                    'entries': len(self._cache)}

    def _cache_key(self, buf, http_service, lenient):
        try:
            # Jython 2 byte-string: passing it directly avoids an implicit
            # ASCII decode of bytes >= 0x80.
            digest = hashlib.sha256(buf).digest()
        except TypeError:
            # Python 3 regression runner, where hashlib requires bytes.
            digest = hashlib.sha256(buf.encode('latin-1')).digest()
        return (digest, len(buf), _service_cache_key(http_service), bool(lenient),
                self.max_body_bytes, self.max_json_structure_depth)

    def _can_cache(self, buf):
        return (self.cache_size > 0 and
                (self.max_cacheable_bytes is None or len(buf) <= self.max_cacheable_bytes))

    def _touch_cache_key(self, key):
        # OrderedDict.move_to_end is not available on every Jython 2.7
        # distribution supported by Burp.
        value = self._cache.pop(key)
        self._cache[key] = value

    def detect(self, helpers, request_bytes, http_service=None, on_error=None, lenient=False):
        buf = bytes_to_bytestring(helpers, request_bytes)
        cacheable = self._can_cache(buf)
        key = self._cache_key(buf, http_service, lenient) if cacheable else None
        cached_result = None
        if cacheable:
            with self._lock:
                cached = self._cache.get(key)
                if cached is not None:
                    self._hits += 1
                    self._touch_cache_key(key)
                    cached_points, cached_errors = cached
                    cached_result = (_clone_points(cached_points), list(cached_errors))
                else:
                    self._misses += 1
        if cached_result is not None:
            cached_points, cached_errors = cached_result
            for message in cached_errors:
                _report(on_error, message)
            return cached_points

        errors = []

        def capture_error(message):
            errors.append(message)
            _report(on_error, message)

        request_info = _analyze_request(helpers, request_bytes, http_service)
        context = DetectionContext(
            helpers, request_bytes, http_service, buf, request_info,
            on_error=capture_error, lenient=lenient,
            max_body_bytes=self.max_body_bytes,
            max_json_structure_depth=self.max_json_structure_depth)
        points = DetectionPipeline(context).run()

        if cacheable:
            with self._lock:
                self._cache[key] = (_clone_points(points), list(errors))
                self._touch_cache_key(key)
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
        return points


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


def _recurse_into_leaf_value(buf, ip, decode_fn, out_points, on_error=None, lenient=False,
                             max_json_structure_depth=None):
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
        if _json_structure_depth_exceeds(stripped, max_json_structure_depth):
            _report(on_error, "%s: nested JSON expansion skipped because structural nesting "
                              "exceeds the configured depth limit of %d"
                              % (ip.path, max_json_structure_depth))
            return
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


def _extract_header_points(buf, headers_list, body_offset, on_error=None, lenient=False,
                           max_json_structure_depth=None):
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
        _recurse_into_leaf_value(
            buf, ip, _identity_decode, points, on_error=on_error, lenient=lenient,
            max_json_structure_depth=max_json_structure_depth)
    return points


def _decompose_multipart_part(buf, part, out_points, on_error=None, lenient=False,
                              max_json_structure_depth=None):
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
        if _json_structure_depth_exceeds(text, max_json_structure_depth):
            _report(on_error, "%s: JSON expansion skipped because structural nesting exceeds "
                              "the configured depth limit of %d"
                              % (prefix, max_json_structure_depth))
            return
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


def _add_multipart_attr_params(request_info, buf, out_points, on_error=None, lenient=False,
                               max_json_structure_depth=None):
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
        _recurse_into_leaf_value(
            buf, ip, _identity_decode, out_points, on_error=on_error, lenient=lenient,
            max_json_structure_depth=max_json_structure_depth)


def _add_body_fallback_params(request_info, buf, out_points, on_error=None, lenient=False,
                              max_json_structure_depth=None):
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
        _recurse_into_leaf_value(buf, ip, lambda b, s, e: _percent_decode_with_map(b, s, e, True),
                                  out_points, on_error=on_error, lenient=lenient,
                                  max_json_structure_depth=max_json_structure_depth)


def _detect_json_lines(buf, body_start, body_end, out_points, on_error=None, lenient=False,
                       max_json_structure_depth=None):
    """Detect one JSON document per non-empty NDJSON / JSON-sequence line.

    A complete NDJSON body is not itself valid JSON, so feeding it to the
    ordinary body parser loses every insertion point.  Parse individual lines
    with an absolute offset translator and make their identity unambiguous in
    the resulting path (``ndjson[3]$.account.id``).
    """
    line_no = 0
    cursor = body_start
    while cursor < body_end:
        line_end = buf.find('\n', cursor, body_end)
        if line_end == -1:
            line_end = body_end
        content_start = cursor
        content_end = line_end
        if content_end > content_start and buf[content_end - 1] == '\r':
            content_end -= 1
        # RFC 7464 JSON Text Sequences optionally prefix records with RS.
        if content_start < content_end and buf[content_start] == '\x1e':
            content_start += 1
        while content_start < content_end and buf[content_start] in ' \t':
            content_start += 1
        while content_end > content_start and buf[content_end - 1] in ' \t':
            content_end -= 1
        text = buf[content_start:content_end]
        if text:
            if _json_structure_depth_exceeds(text, max_json_structure_depth):
                _report(on_error, 'NDJSON line %d skipped: structural nesting exceeds depth limit of %d'
                        % (line_no + 1, max_json_structure_depth))
            else:
                try:
                    points = json_offset_parser.detect(
                        buf, content_start, content_end, allow_lenient=lenient,
                        on_recovered=_make_recovered_reporter(on_error, 'ndjson[%d]' % line_no),
                        on_error=on_error)
                    if points:
                        for point in points:
                            point.path = 'ndjson[%d]' % line_no + point.path
                        out_points.extend(points)
                except Exception:
                    _report_exc(on_error, 'NDJSON line %d detection raised unexpectedly:' % (line_no + 1))
            line_no += 1
        cursor = line_end + 1


def _process_body(request_info, buf, out_points, on_error=None, lenient=False,
                  max_body_bytes=None, max_json_structure_depth=None):
    body_offset = request_info.getBodyOffset()
    body_end = len(buf)
    if body_offset >= body_end:
        return
    body_size = body_end - body_offset
    if max_body_bytes is not None and body_size > max_body_bytes:
        _report(on_error, "Body detection skipped: %d bytes exceeds the configured %d-byte limit; "
                          "URL, cookie and header points were still collected."
                          % (body_size, max_body_bytes))
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
                _decompose_multipart_part(
                    buf, part, out_points, on_error=on_error, lenient=lenient,
                    max_json_structure_depth=max_json_structure_depth)
            _add_multipart_attr_params(
                request_info, buf, out_points, on_error=on_error, lenient=lenient,
                max_json_structure_depth=max_json_structure_depth)
        except Exception:
            _report_exc(on_error, "multipart body detection raised:")
        return

    if 'ndjson' in ct_lower or 'jsonl' in ct_lower or 'json-seq' in ct_lower:
        _detect_json_lines(buf, body_offset, body_end, out_points, on_error=on_error, lenient=lenient,
                           max_json_structure_depth=max_json_structure_depth)
        return

    if 'json' in ct_lower or looks_like_json(body_text):
        if _json_structure_depth_exceeds(body_text, max_json_structure_depth):
            _report(on_error, "JSON body detection skipped: structural nesting exceeds the "
                              "configured depth limit of %d; URL, cookie and header points "
                              "were still collected." % max_json_structure_depth)
            return
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

    _add_body_fallback_params(
        request_info, buf, out_points, on_error=on_error, lenient=lenient,
        max_json_structure_depth=max_json_structure_depth)


def _analyze_request(helpers, request_bytes, http_service):
    """Keep Burp's overloaded analyzeRequest selection in one place."""
    if http_service is not None:
        return helpers.analyzeRequest(http_service, request_bytes)
    return helpers.analyzeRequest(request_bytes)


def _url_form_decode(buf, start, end):
    return _percent_decode_with_map(buf, start, end, True)


def _cookie_decode(buf, start, end):
    return _percent_decode_with_map(buf, start, end, False)


def _has_percent_escape(text):
    """Whether another percent-decode pass could change ``text``."""
    for pos in range(0, max(0, len(text) - 2)):
        if text[pos] == '%' and text[pos + 1] in '0123456789abcdefABCDEF' and text[pos + 2] in '0123456789abcdefABCDEF':
            return True
    return False


def _percent_decode_with_map(buf, start, end, plus_as_space):
    """Decode up to three percent-encoding layers without losing offsets.

    ``url_decode_with_map`` maps decoded character boundaries back to the
    source request.  On later layers the returned map is composed with the
    previous one, so a nested JSON leaf can still be replaced at its exact
    original `%25...` byte range rather than merely displayed.
    """
    decoded, decoded_to_raw = url_decode_with_map(buf, start, end, plus_as_space)
    for _layer in range(1, DEFAULT_MAX_PERCENT_DECODE_LAYERS):
        if not _has_percent_escape(decoded):
            break
        next_decoded, next_to_previous = url_decode_with_map(decoded, 0, len(decoded), plus_as_space)
        if next_decoded == decoded:
            break
        decoded_to_raw = [decoded_to_raw[local_pos] for local_pos in next_to_previous]
        decoded = next_decoded
    return decoded, decoded_to_raw


def _collect_url_cookie_points(context, out_points):
    """Collect Burp-analyzed transport parameters and expand nested values."""
    for param in context.request_info.getParameters():
        ptype = param.getType()
        if ptype == BurpParamType.URL:
            start, end = param.getValueStart(), param.getValueEnd()
            ip = InsertionPoint(
                path='url[' + param.getName() + ']', type_=InsertionPointType.URL_PARAM,
                start=start, end=end, original_value=context.buf[start:end],
                context=EscapeMode.URL_COMPONENT)
            out_points.append(ip)
            _recurse_into_leaf_value(
                context.buf, ip, _url_form_decode, out_points,
                on_error=context.on_error, lenient=context.lenient,
                max_json_structure_depth=context.max_json_structure_depth)
        elif ptype == BurpParamType.COOKIE:
            start, end = param.getValueStart(), param.getValueEnd()
            ip = InsertionPoint(
                path='cookie[' + param.getName() + ']', type_=InsertionPointType.COOKIE,
                start=start, end=end, original_value=context.buf[start:end],
                context=EscapeMode.URL_COMPONENT)
            out_points.append(ip)
            _recurse_into_leaf_value(
                context.buf, ip, _cookie_decode, out_points,
                on_error=context.on_error, lenient=context.lenient,
                max_json_structure_depth=context.max_json_structure_depth)
        # BODY/XML/XML_ATTR/MULTIPART_ATTR/JSON are intentionally handled by
        # the shared body stage for deeper and deterministic granularity.


class DetectionPipeline(object):
    """Ordered request detection stages operating on one analyzed context."""

    def __init__(self, context):
        self.context = context

    def run(self):
        points = []
        _collect_url_cookie_points(self.context, points)
        points.extend(_extract_header_points(
            self.context.buf, self.context.headers, self.context.body_offset,
            on_error=self.context.on_error, lenient=self.context.lenient,
            max_json_structure_depth=self.context.max_json_structure_depth))
        try:
            _process_body(
                self.context.request_info, self.context.buf, points,
                on_error=self.context.on_error, lenient=self.context.lenient,
                max_body_bytes=self.context.max_body_bytes,
                max_json_structure_depth=self.context.max_json_structure_depth)
        except Exception:
            # Body failure must never discard independently collected URL,
            # cookie and header points.
            _report_exc(self.context.on_error, "body detection raised unexpectedly:")
        return _deduplicate_points(points)


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
    return _DEFAULT_ENGINE.detect(
        helpers, request_bytes, http_service=http_service,
        on_error=on_error, lenient=lenient)


_DEFAULT_ENGINE = DetectionEngine()


def clear_cache():
    """Clear the shared detector cache (primarily useful for diagnostics)."""
    _DEFAULT_ENGINE.clear_cache()


def cache_stats():
    """Return a snapshot of shared cache hit/miss counters."""
    return _DEFAULT_ENGINE.cache_stats()
