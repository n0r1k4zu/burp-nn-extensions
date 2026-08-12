# -*- coding: utf-8 -*-
"""Hand-rolled recursive-descent JSON parser that tracks absolute byte
offsets for every leaf value, including leaves whose string value is
itself a serialized JSON or XML document (recursed into, per the
"unravel nested structures" requirement).

Operates entirely in byte-string space (see utils.py) -- every offset
here is a plain character index that is also a raw HTTP byte offset once
translated back through the enclosing buffers via the `translator`
closures threaded through extract_leaves/sniff_and_recurse.
"""

import re
import traceback

from csvlistinput.constants import (EscapeMode, InsertionPointType, MAX_NEST_DEPTH,
                                     NESTED_JSON_MARKER, NESTED_XML_MARKER)
from csvlistinput.models import InsertionPoint
from csvlistinput.utils import (JSON_BACKSLASH_ESCAPES, looks_like_json, looks_like_xml)

IDENTIFIER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


class JsonParseError(Exception):
    pass


class JsonNode(object):
    OBJECT = 'OBJECT'
    ARRAY = 'ARRAY'
    STRING = 'STRING'
    NUMBER = 'NUMBER'
    TRUE = 'TRUE'
    FALSE = 'FALSE'
    NULL = 'NULL'

    def __init__(self, kind, start, end):
        self.kind = kind
        self.start = start
        self.end = end
        self.path = None
        self.members = None          # OBJECT: list[(key_node, value_node)]
        self.items = None            # ARRAY: list[value_node]
        self.content_start = None    # STRING: offset just past opening quote
        self.content_end = None      # STRING: offset of closing quote
        self.raw = None              # raw token text (escaped form for strings)
        self.decoded = None          # STRING: decoded value
        self.decoded_to_raw = None   # STRING: decoded_to_raw[i] = raw offset of decoded[i]'s source;
                                      #         decoded_to_raw[len(decoded)] = content_end (sentinel)

    def __repr__(self):
        return "JsonNode(%s, %s, %s)" % (self.kind, self.start, self.end)


def _skip_ws(buf, pos):
    n = len(buf)
    while pos < n and buf[pos] in ' \t\r\n':
        pos += 1
    return pos


def _parse_value(buf, pos, lenient=False, recovered=None):
    pos = _skip_ws(buf, pos)
    if pos >= len(buf):
        raise JsonParseError("Unexpected end of input at %d" % pos)
    c = buf[pos]
    if c == '{':
        return _parse_object(buf, pos, lenient=lenient, recovered=recovered)
    if c == '[':
        return _parse_array(buf, pos, lenient=lenient, recovered=recovered)
    if c == '"':
        return _parse_string(buf, pos)
    if c == '-' or c.isdigit():
        return _parse_number(buf, pos)
    if buf[pos:pos + 4] == 'true':
        node = JsonNode(JsonNode.TRUE, pos, pos + 4)
        node.raw = 'true'
        return node, pos + 4
    if buf[pos:pos + 5] == 'false':
        node = JsonNode(JsonNode.FALSE, pos, pos + 5)
        node.raw = 'false'
        return node, pos + 5
    if buf[pos:pos + 4] == 'null':
        node = JsonNode(JsonNode.NULL, pos, pos + 4)
        node.raw = 'null'
        return node, pos + 4
    raise JsonParseError("Unexpected character %r at %d" % (c, pos))


def _parse_number(buf, pos):
    start = pos
    n = len(buf)
    if pos < n and buf[pos] == '-':
        pos += 1
    while pos < n and buf[pos].isdigit():
        pos += 1
    if pos < n and buf[pos] == '.':
        pos += 1
        while pos < n and buf[pos].isdigit():
            pos += 1
    if pos < n and buf[pos] in 'eE':
        pos += 1
        if pos < n and buf[pos] in '+-':
            pos += 1
        while pos < n and buf[pos].isdigit():
            pos += 1
    if pos == start:
        raise JsonParseError("Invalid number at %d" % pos)
    node = JsonNode(JsonNode.NUMBER, start, pos)
    node.raw = buf[start:pos]
    return node, pos


def _parse_string(buf, pos):
    start = pos
    if buf[pos] != '"':
        raise JsonParseError("Expected '\"' at %d" % pos)
    pos += 1
    content_start = pos
    n = len(buf)
    decoded_chars = []
    decoded_to_raw = []
    content_end = None
    while True:
        if pos >= n:
            raise JsonParseError("Unterminated string starting at %d" % start)
        c = buf[pos]
        if c == '\\':
            if pos + 1 >= n:
                raise JsonParseError("Bad escape at %d" % pos)
            esc = buf[pos + 1]
            if esc == 'u':
                if pos + 6 > n:
                    raise JsonParseError("Bad unicode escape at %d" % pos)
                cp = int(buf[pos + 2:pos + 6], 16)
                esc_start = pos
                pos += 6
                # Combine a UTF-16 surrogate pair into one codepoint (e.g.
                # emoji) if the next escape completes one.
                if 0xD800 <= cp <= 0xDBFF and pos + 6 <= n and buf[pos:pos + 2] == '\\u':
                    low = int(buf[pos + 2:pos + 6], 16)
                    if 0xDC00 <= low <= 0xDFFF:
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                        pos += 6
                # Encode to UTF-8 bytes and append them individually as
                # plain str (byte-string-space) elements, matching every
                # other char in this list -- NEVER append a bare unicode
                # object here. Python 2/Jython 2 silently promotes
                # str+unicode joins through an implicit ASCII decode, which
                # raises UnicodeDecodeError the moment buf (a plain str)
                # contains any raw non-ASCII byte elsewhere in this same
                # string (e.g. literal, non-escaped Japanese text).
                try:
                    utf8_bytes = unichr(cp).encode('utf-8')
                except ValueError:
                    utf8_bytes = '?'  # codepoint unrepresentable on this build; tolerate rather than crash
                for b in utf8_bytes:
                    decoded_chars.append(b)
                    decoded_to_raw.append(esc_start)
            elif esc in JSON_BACKSLASH_ESCAPES:
                decoded_chars.append(JSON_BACKSLASH_ESCAPES[esc])
                decoded_to_raw.append(pos)
                pos += 2
            else:
                # Tolerant of unknown escapes: keep the char literally.
                decoded_chars.append(esc)
                decoded_to_raw.append(pos)
                pos += 2
        elif c == '"':
            content_end = pos
            pos += 1
            break
        else:
            decoded_chars.append(c)
            decoded_to_raw.append(pos)
            pos += 1
    decoded_to_raw.append(content_end)  # sentinel: end-of-string index
    node = JsonNode(JsonNode.STRING, start, pos)
    node.content_start = content_start
    node.content_end = content_end
    node.raw = buf[content_start:content_end]
    node.decoded = ''.join(decoded_chars)
    node.decoded_to_raw = decoded_to_raw
    return node, pos


def _resync(buf, pos, stop_chars, recovered):
    """Lenient-mode helper: scan forward from `pos` for the next character
    in `stop_chars` (a set of plausible resumption points), recording the
    skipped span into `recovered` (list of (start, end) tuples) if any
    characters were actually skipped. Returns the new position, which is
    len(buf) if none of stop_chars was found before the end."""
    start = pos
    n = len(buf)
    while pos < n and buf[pos] not in stop_chars:
        pos += 1
    if recovered is not None and pos > start:
        recovered.append((start, pos))
    return pos


def _parse_object(buf, pos, lenient=False, recovered=None):
    start = pos
    pos += 1
    members = []
    pos = _skip_ws(buf, pos)
    if pos < len(buf) and buf[pos] == '}':
        node = JsonNode(JsonNode.OBJECT, start, pos + 1)
        node.members = members
        return node, pos + 1
    while True:
        pos = _skip_ws(buf, pos)

        if pos >= len(buf) or buf[pos] != '"':
            if not lenient:
                raise JsonParseError("Expected '\"' at %d" % pos)
            # Malformed escaping upstream can leave stray characters where
            # a key's opening quote was expected -- skip forward to the
            # next quote (a plausible key start) or this object's close.
            pos = _resync(buf, pos, '"}', recovered)
            if pos >= len(buf):
                raise JsonParseError("Unterminated object at %d" % start)
            if buf[pos] == '}':
                pos += 1
                break

        key_node, pos = _parse_string(buf, pos)
        pos = _skip_ws(buf, pos)

        if pos >= len(buf) or buf[pos] != ':':
            if not lenient:
                raise JsonParseError("Expected ':' at %d" % pos)
            resync_start = pos
            pos = _resync(buf, pos, ':,}', recovered)
            if pos < len(buf) and buf[pos] == ':':
                pos += 1
            else:
                # No colon reached before the next structural character --
                # this key has no recoverable value; record it as null and
                # keep going rather than abandoning the whole object.
                if recovered is not None and pos == resync_start:
                    pass  # _resync already logged the span if non-empty
                val_node = JsonNode(JsonNode.NULL, pos, pos)
                val_node.raw = 'null'
                members.append((key_node, val_node))
                if pos < len(buf) and buf[pos] == ',':
                    pos += 1
                    continue
                if pos < len(buf) and buf[pos] == '}':
                    pos += 1
                    break
                raise JsonParseError("Unterminated object at %d" % start)
        else:
            pos += 1

        pos = _skip_ws(buf, pos)
        val_node, pos = _parse_value(buf, pos, lenient=lenient, recovered=recovered)
        members.append((key_node, val_node))
        pos = _skip_ws(buf, pos)
        if pos >= len(buf):
            raise JsonParseError("Unterminated object at %d" % start)
        if buf[pos] == ',':
            pos += 1
            continue
        if buf[pos] == '}':
            pos += 1
            break
        if lenient:
            # A value ended somewhere unexpected (typically mismatched
            # escaping upstream of this parser, e.g. an inconsistently
            # escaped quote closing a string early). Rather than abandon
            # the whole object, scan forward for the next plausible
            # resumption point -- a new key's opening quote, a comma, or
            # this object's closing brace -- and keep going.
            pos = _resync(buf, pos, ',}"', recovered)
            if pos < len(buf):
                if buf[pos] == ',':
                    pos += 1
                    continue
                if buf[pos] == '}':
                    pos += 1
                    break
                continue  # buf[pos] == '"': treat as an implicit comma before a new key
        raise JsonParseError("Expected ',' or '}' at %d" % pos)
    node = JsonNode(JsonNode.OBJECT, start, pos)
    node.members = members
    return node, pos


def _parse_array(buf, pos, lenient=False, recovered=None):
    start = pos
    pos += 1
    items = []
    pos = _skip_ws(buf, pos)
    if pos < len(buf) and buf[pos] == ']':
        node = JsonNode(JsonNode.ARRAY, start, pos + 1)
        node.items = items
        return node, pos + 1
    while True:
        pos = _skip_ws(buf, pos)
        val_node, pos = _parse_value(buf, pos, lenient=lenient, recovered=recovered)
        items.append(val_node)
        pos = _skip_ws(buf, pos)
        if pos >= len(buf):
            raise JsonParseError("Unterminated array at %d" % start)
        if buf[pos] == ',':
            pos += 1
            continue
        if buf[pos] == ']':
            pos += 1
            break
        if lenient:
            resync_start = pos
            n = len(buf)
            while pos < n and buf[pos] not in ',]':
                pos += 1
            if pos < n:
                if recovered is not None and pos > resync_start:
                    recovered.append((resync_start, pos))
                if buf[pos] == ',':
                    pos += 1
                    continue
                if buf[pos] == ']':
                    pos += 1
                    break
        raise JsonParseError("Expected ',' or ']' at %d" % pos)
    node = JsonNode(JsonNode.ARRAY, start, pos)
    node.items = items
    return node, pos


def parse(buf, lenient=False, recovered=None):
    """Parse the full `buf` as a single JSON value; raises JsonParseError
    on any trailing garbage or malformed input (unless `lenient`, in which
    case unexpected characters between object/array elements are skipped
    over -- see _parse_object/_parse_array -- and any skipped spans are
    appended to `recovered` as (start, end) tuples for the caller to flag
    as best-effort/approximate)."""
    pos = _skip_ws(buf, 0)
    node, pos = _parse_value(buf, pos, lenient=lenient, recovered=recovered)
    pos = _skip_ws(buf, pos)
    if pos != len(buf):
        if lenient:
            if recovered is not None:
                recovered.append((pos, len(buf)))
        else:
            raise JsonParseError("Trailing data at %d" % pos)
    return node


def _json_key_repr(key):
    return '"' + key.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _ensure_bytestring(s):
    """Defensive second layer, independent of utils.bytes_to_bytestring:
    force `s` into byte-string space (str, one char == one byte)
    regardless of what type it actually arrives as. Path strings get
    built via plain `str + str` concatenation throughout this module,
    which raises UnicodeDecodeError in Python 2/Jython 2 the instant one
    side is unicode/Java-String-proxy-flavored and the other contains a
    non-ASCII byte -- this makes that impossible regardless of root cause."""
    if isinstance(s, str):
        return s
    try:
        return unicode(s).encode('latin-1')
    except UnicodeEncodeError:
        # Contains a real codepoint > 255 (genuine Unicode text, not a
        # byte-value-as-codepoint) -- re-encode as UTF-8 instead so it
        # still round-trips into a definite `str`.
        return unicode(s).encode('utf-8')


def assign_paths(node, base_path):
    node.path = base_path
    if node.kind == JsonNode.OBJECT:
        for key_node, val_node in node.members:
            key = _ensure_bytestring(key_node.decoded)
            if IDENTIFIER_RE.match(key):
                child_path = base_path + '.' + key
            else:
                child_path = base_path + '[' + _json_key_repr(key) + ']'
            assign_paths(val_node, child_path)
    elif node.kind == JsonNode.ARRAY:
        for idx, item in enumerate(node.items):
            assign_paths(item, base_path + '[' + str(idx) + ']')


def _identity_translator(local_pos):
    return local_pos


def extract_leaves(node, depth, chain, out_list, translator, allow_lenient=False, on_recovered=None,
                    on_error=None):
    """Walk `node`, appending InsertionPoint objects for every leaf
    (string/number/true/false/null) to out_list. `translator` maps a
    local offset (an index into the buffer this node tree was parsed
    from) to an absolute byte offset in the original HTTP request."""
    if node.kind in (JsonNode.STRING, JsonNode.NUMBER, JsonNode.TRUE, JsonNode.FALSE, JsonNode.NULL):
        if node.kind == JsonNode.STRING:
            abs_start = translator(node.content_start)
            abs_end = translator(node.content_end)
            value = node.decoded
            context = EscapeMode.JSON_STRING
        else:
            abs_start = translator(node.start)
            abs_end = translator(node.end)
            value = node.raw
            context = EscapeMode.RAW
        ip_type = InsertionPointType.JSON_LEAF if depth == 0 else InsertionPointType.JSON_LEAF_NESTED
        ip = InsertionPoint(path=node.path, type_=ip_type, start=abs_start, end=abs_end,
                             original_value=value, context=context, nesting_depth=depth,
                             container_chain=list(chain))
        out_list.append(ip)
        if node.kind == JsonNode.STRING and depth < MAX_NEST_DEPTH:
            _sniff_and_recurse(node, depth, chain, out_list, translator,
                                allow_lenient=allow_lenient, on_recovered=on_recovered, on_error=on_error)
    elif node.kind == JsonNode.OBJECT:
        for _key_node, val_node in node.members:
            extract_leaves(val_node, depth, chain, out_list, translator,
                            allow_lenient=allow_lenient, on_recovered=on_recovered, on_error=on_error)
    elif node.kind == JsonNode.ARRAY:
        for item in node.items:
            extract_leaves(item, depth, chain, out_list, translator,
                            allow_lenient=allow_lenient, on_recovered=on_recovered, on_error=on_error)


def _sniff_and_recurse(string_node, depth, chain, out_list, parent_translator,
                        allow_lenient=False, on_recovered=None, on_error=None):
    text = string_node.decoded
    stripped = text.strip()
    if not stripped:
        return

    def local_translator(local_pos):
        raw_pos = string_node.decoded_to_raw[local_pos]
        return parent_translator(raw_pos)

    if looks_like_json(stripped):
        new_chain = chain + [{'kind': 'json', 'container_path': string_node.path}]
        inner_points = None
        try:
            inner_points = detect_in_text(
                text, local_translator, base_path=string_node.path + NESTED_JSON_MARKER,
                start_depth=depth + 1, chain=new_chain,
                allow_lenient=allow_lenient, on_recovered=on_recovered, on_error=on_error)
        except Exception:
            if on_error:
                try:
                    on_error("%s: looked like nested JSON but detection raised unexpectedly: %s"
                             % (string_node.path, traceback.format_exc().splitlines()[-1]))
                except Exception:
                    pass
        if inner_points:
            out_list.extend(inner_points)
        elif on_error:
            try:
                parse(text)
            except JsonParseError as e:
                on_error("%s: looked like nested JSON but failed to parse even under the current "
                         "recovery settings (kept as a flat, unexpanded value): %s" % (string_node.path, e))
    elif looks_like_xml(stripped):
        # Lazy import: xml_offset_scanner symmetrically imports this module
        # for its own nested-JSON detection, so import at call time to
        # avoid a circular import at module load.
        from csvlistinput import xml_offset_scanner
        inner_points = xml_offset_scanner.detect_in_text(
            text, local_translator, base_path=string_node.path + NESTED_XML_MARKER,
            start_depth=depth + 1, chain=chain + [{'kind': 'xml', 'container_path': string_node.path}])
        if inner_points:
            out_list.extend(inner_points)


# ---- Tier 3: flat heuristic scan (last resort for input too corrupted for
# even resync-based recovery to reconstruct a correct nested tree) ----
#
# A quote "token" is treated as EITHER a bare `"` or an escaped `\"` --
# interchangeably. This directly targets the failure mode seen in practice:
# content that's *supposed* to be JSON-string-escaped (because it lives one
# level deep inside another JSON string) where some quotes were escaped and
# others weren't, so a strict "quotes always come in one specific form"
# scanner loses its place. Object/array nesting is not tracked at all here
# -- only individual "key": value leaf pairs are found, wherever they are.
_HEURISTIC_QUOTE = r'\\?"'
_HEURISTIC_CONTENT = r'(?:\\(?!")|[^"\\])*?'
_HEURISTIC_KV_RE = re.compile(
    _HEURISTIC_QUOTE + r'(' + _HEURISTIC_CONTENT + r')' + _HEURISTIC_QUOTE +
    r'\s*:\s*'
    r'(?:'
    + _HEURISTIC_QUOTE + r'(' + _HEURISTIC_CONTENT + r')' + _HEURISTIC_QUOTE +
    r'|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    r'|(true|false|null)'
    r')'
)


def _heuristic_unescape(raw):
    """Best-effort unescape for display purposes (original_value) only --
    tolerant of the same escapes _parse_string handles, but never raises;
    anything it doesn't recognize is passed through literally rather than
    aborting (this is already the last-resort tier)."""
    out = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == '\\' and i + 1 < n:
            esc = raw[i + 1]
            if esc == 'u' and i + 6 <= n:
                try:
                    cp = int(raw[i + 2:i + 6], 16)
                except ValueError:
                    cp = None
                if cp is not None:
                    try:
                        out.append(unichr(cp).encode('utf-8'))
                    except ValueError:
                        out.append('?')
                    i += 6
                    continue
            if esc in JSON_BACKSLASH_ESCAPES:
                out.append(JSON_BACKSLASH_ESCAPES[esc])
                i += 2
                continue
            out.append(esc)
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def heuristic_scan(text, translator, base_path, depth, chain):
    """Scan `text` for "key": value patterns via _HEURISTIC_KV_RE,
    completely ignoring object/array nesting validity. Returns
    list[InsertionPoint] (possibly empty -- never None, never raises).
    Paths are `{base_path}{heuristic}[N].key` (N = match index): true
    nesting can't be trusted from corrupted input, so uniqueness comes
    from position in the scan rather than structure. Every point is
    marked `.recovered = True`.
    """
    out = []
    for i, m in enumerate(_HEURISTIC_KV_RE.finditer(text)):
        key = _ensure_bytestring(_heuristic_unescape(m.group(1)))
        if m.group(2) is not None:
            start, end = m.start(2), m.end(2)
            value = _heuristic_unescape(m.group(2))
            context = EscapeMode.JSON_STRING
        elif m.group(3) is not None:
            start, end = m.start(3), m.end(3)
            value = m.group(3)
            context = EscapeMode.RAW
        else:
            start, end = m.start(4), m.end(4)
            value = m.group(4)
            context = EscapeMode.RAW
        safe_key = key if IDENTIFIER_RE.match(key) else _json_key_repr(key)
        path = "%s{heuristic}[%d].%s" % (base_path, i, safe_key)
        ip = InsertionPoint(path=path, type_=InsertionPointType.JSON_LEAF_NESTED,
                             start=translator(start), end=translator(end),
                             original_value=value, context=context, nesting_depth=depth,
                             container_chain=list(chain))
        ip.recovered = True
        out.append(ip)
    return out


_SUSPICIOUS_KEY_CHARS = set('"{}[]:\\')
_MAX_REASONABLE_KEY_LEN = 120


def _looks_like_garbled_recovery(ip):
    """Sanity check applied to tier-2 (resync) output only: a legitimate
    JSON object key is a short identifier or simple string. If a path's
    last segment is implausibly long or contains JSON-structural
    characters, the resync's "find the next key" step almost certainly
    mis-parsed a large stretch of escaped content as one giant "key" --
    see the caller for how that happens. Not a proof, just a cheap,
    effective filter for a very recognizable failure shape."""
    tail = ip.path.rsplit('.', 1)[-1].rsplit('[', 1)[-1].rstrip(']')
    if len(tail) > _MAX_REASONABLE_KEY_LEN:
        return True
    return any(c in _SUSPICIOUS_KEY_CHARS for c in tail)


def detect_in_text(text, translator, base_path='$', start_depth=0, chain=None,
                    allow_lenient=False, on_recovered=None, on_error=None):
    """Parse `text` as a JSON document. Returns list[InsertionPoint] with
    offsets translated to absolute via `translator`, or None if nothing
    could be extracted at all (even leniently, when allow_lenient is set).

    1. Strict recursive-descent parse (parse()) -- exact, trusted fully.
    2. If `allow_lenient`: resync-based recovery (parse(lenient=True)) --
       can rescue mildly-corrupted JSON (a stray character, a missing
       comma) while still building a real, correctly-nested tree.
    3. If `allow_lenient`, a SUPPLEMENTARY full-text heuristic_scan() pass
       always runs afterward (whether tier 1/2 succeeded or not) and any
       points it finds that don't byte-overlap something already found
       are merged in. This matters because a broken string boundary
       elsewhere in `text` can make the tree parser (tiers 1/2) truncate
       a nested value early and silently drop everything "inside" it --
       tier 2 succeeding for the document as a whole does not mean every
       individual value inside it was recovered correctly. The
       heuristic's flat "key": value pattern match does not depend on
       string-boundary correctness at all, so it independently catches
       content the tree-based tiers lost.

    Every point found via tier 2 or the heuristic pass is marked
    `.recovered = True` (and `on_recovered(spans)` is called with (start,
    end) ranges to flag as approximate) so callers can present it with
    less confidence than clean (tier 1) detection.
    """
    text = _ensure_bytestring(text)
    base_path = _ensure_bytestring(base_path)
    chain = chain or []
    used_lenient = False
    out = None
    try:
        root = parse(text)
    except JsonParseError:
        if not allow_lenient:
            return None
        recovered_spans = []
        try:
            root = parse(text, lenient=True, recovered=recovered_spans)
            used_lenient = True
        except JsonParseError:
            root = None  # tier 2 failed outright; fall through to the heuristic-only pass below

    if root is not None:
        assign_paths(root, base_path)
        out = []
        extract_leaves(root, start_depth, chain, out, translator,
                        allow_lenient=allow_lenient, on_recovered=on_recovered, on_error=on_error)
        if used_lenient:
            # The resync recovery's "find the next key" step can itself
            # mis-fire on content that's supposed to be one level of
            # string-escaping deep: it resyncs to the next BARE `"`, but
            # then parses the "key" with ordinary _parse_string, which
            # treats every subsequent `\"` as escaped content rather than
            # a terminator -- on content where a bare quote (the actual
            # corruption) is followed by many more `\"`-escaped quotes,
            # this can swallow a huge stretch of text into one nonsensical
            # "key" with a null value. Drop anything that looks like that
            # rather than show it as noise; the supplementary heuristic
            # pass below finds the real values independently, and
            # filtering BEFORE that pass also stops this garbage entry's
            # huge byte range from blocking the overlap check that decides
            # what the heuristic pass is still allowed to add.
            out = [ip for ip in out if not _looks_like_garbled_recovery(ip)]
            for ip in out:
                ip.recovered = True
            if on_recovered:
                try:
                    on_recovered([(translator(s), translator(e)) for s, e in recovered_spans])
                except Exception:
                    pass
    else:
        out = []

    if allow_lenient:
        existing_ranges = [(ip.start, ip.end) for ip in out]
        supplementary = heuristic_scan(text, translator, base_path, start_depth, chain)
        added = []
        for ip in supplementary:
            if not any(ip.start < e and s < ip.end for s, e in existing_ranges):
                added.append(ip)
                existing_ranges.append((ip.start, ip.end))
        if added:
            out.extend(added)
            if on_recovered:
                try:
                    on_recovered([(ip.start, ip.end) for ip in added])
                except Exception:
                    pass

    return out if out else None


def detect(full_buf, region_start, region_end, allow_lenient=False, on_recovered=None, on_error=None):
    """Parse full_buf[region_start:region_end] as JSON. Returns
    list[InsertionPoint] with offsets absolute against full_buf, or None
    if that region is not valid JSON (see detect_in_text for `allow_lenient`)."""
    text = full_buf[region_start:region_end]
    return detect_in_text(text, lambda local_pos: region_start + local_pos,
                           allow_lenient=allow_lenient, on_recovered=on_recovered, on_error=on_error)
