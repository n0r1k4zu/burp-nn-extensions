# -*- coding: utf-8 -*-
"""Cursor-based, tolerant single-pass XML scanner that tracks absolute
byte offsets for text nodes and attribute values, symmetric to
json_offset_parser.py. There is no offset-capable XML parser in the
Jython 2.7 standard library (minidom/ElementTree give no byte
positions), so this hand-rolled scanner fills that gap.

Malformed XML never raises out of this module: on any unexpected
condition the scan simply stops and returns whatever insertion points
were found so far (possibly none), per the "don't crash the extension
on bad input" requirement.
"""

from csvlistinput.constants import (EscapeMode, InsertionPointType, MAX_NEST_DEPTH,
                                     NESTED_JSON_MARKER, NESTED_XML_MARKER)
from csvlistinput.models import InsertionPoint
from csvlistinput.utils import NAMED_XML_ENTITIES, looks_like_json, looks_like_xml

_NAME_STOP_CHARS = ' \t\r\n/>='
_WS_CHARS = ' \t\r\n'


def _skip_ws(buf, pos):
    n = len(buf)
    while pos < n and buf[pos] in _WS_CHARS:
        pos += 1
    return pos


def _read_name(buf, pos):
    start = pos
    n = len(buf)
    while pos < n and buf[pos] not in _NAME_STOP_CHARS:
        pos += 1
    return buf[start:pos], pos


def decode_entities_range(buf, start, end):
    """Decode XML entities in buf[start:end]. Returns (decoded, decoded_to_raw)
    where decoded_to_raw[i] is the offset *within buf* (same address space
    as start/end) that decoded character i originated from, and
    decoded_to_raw[len(decoded)] == end (sentinel, for end-of-range lookups)."""
    decoded_chars = []
    decoded_to_raw = []
    pos = start
    while pos < end:
        c = buf[pos]
        if c == '&':
            semi = buf.find(';', pos, end)
            decoded_bytes = None  # plain str (UTF-8 bytes), never a bare unicode object -- see below
            if semi != -1:
                ent = buf[pos + 1:semi]
                cp = None
                if ent[:2] in ('#x', '#X'):
                    try:
                        cp = int(ent[2:], 16)
                    except ValueError:
                        cp = None
                elif ent[:1] == '#':
                    try:
                        cp = int(ent[1:])
                    except ValueError:
                        cp = None
                if cp is not None:
                    # Encode to UTF-8 bytes rather than appending a bare
                    # unichr() unicode object: Python 2/Jython 2 silently
                    # promotes str+unicode joins through an implicit ASCII
                    # decode, which raises UnicodeDecodeError the moment buf
                    # (a plain str) contains any raw non-ASCII byte
                    # elsewhere in this same text (e.g. literal Japanese).
                    try:
                        decoded_bytes = unichr(cp).encode('utf-8')
                    except (ValueError, OverflowError):
                        decoded_bytes = None
                elif ent in NAMED_XML_ENTITIES:
                    decoded_bytes = NAMED_XML_ENTITIES[ent]
            if decoded_bytes is not None:
                for b in decoded_bytes:
                    decoded_chars.append(b)
                    decoded_to_raw.append(pos)
                pos = semi + 1
                continue
            decoded_chars.append(c)
            decoded_to_raw.append(pos)
            pos += 1
        else:
            decoded_chars.append(c)
            decoded_to_raw.append(pos)
            pos += 1
    decoded_to_raw.append(end)
    return ''.join(decoded_chars), decoded_to_raw


class _Frame(object):
    def __init__(self, path):
        self.path = path
        self.child_counts = {}
        self.text_run_count = 0


def _sniff_and_recurse(decoded, decoded_to_raw, path, depth, chain, out):
    stripped = decoded.strip()
    if not stripped:
        return

    def translator(local_pos):
        return decoded_to_raw[local_pos]

    if looks_like_json(stripped):
        from csvlistinput import json_offset_parser
        inner = json_offset_parser.detect_in_text(
            decoded, translator, base_path=path + NESTED_JSON_MARKER,
            start_depth=depth + 1, chain=chain + [{'kind': 'json', 'container_path': path}])
        if inner:
            out.extend(inner)
    elif looks_like_xml(stripped):
        inner = detect_in_text(
            decoded, translator, base_path=path + NESTED_XML_MARKER,
            start_depth=depth + 1, chain=chain + [{'kind': 'xml', 'container_path': path}])
        if inner:
            out.extend(inner)


def _scan_local(buf, start_depth, chain, base_path):
    n = len(buf)
    pos = 0
    stack = []
    out = []

    def emit_text_run(text_start, text_end):
        if not stack or text_end <= text_start:
            return
        if buf[text_start:text_end].strip() == '':
            return
        frame = stack[-1]
        frame.text_run_count += 1
        decoded, decoded_to_raw = decode_entities_range(buf, text_start, text_end)
        path = frame.path + '/text()[' + str(frame.text_run_count) + ']'
        ip_type = InsertionPointType.XML_TEXT if start_depth == 0 else InsertionPointType.XML_TEXT_NESTED
        ip = InsertionPoint(path=path, type_=ip_type, start=text_start, end=text_end,
                             original_value=decoded, context=EscapeMode.XML_TEXT,
                             nesting_depth=start_depth, container_chain=list(chain))
        out.append(ip)
        if start_depth < MAX_NEST_DEPTH:
            _sniff_and_recurse(decoded, decoded_to_raw, path, start_depth, chain, out)

    while True:
        lt = buf.find('<', pos)
        if lt == -1:
            emit_text_run(pos, n)
            break
        if lt > pos:
            emit_text_run(pos, lt)
        pos = lt

        if buf[pos:pos + 4] == '<!--':
            end = buf.find('-->', pos)
            pos = (end + 3) if end != -1 else n
            continue
        if buf[pos:pos + 9] == '<![CDATA[':
            end = buf.find(']]>', pos)
            cdata_start = pos + 9
            cdata_end = end if end != -1 else n
            if stack and cdata_end > cdata_start:
                frame = stack[-1]
                frame.text_run_count += 1
                path = frame.path + '/text()[' + str(frame.text_run_count) + ']'
                value = buf[cdata_start:cdata_end]
                ip_type = InsertionPointType.XML_TEXT if start_depth == 0 else InsertionPointType.XML_TEXT_NESTED
                ip = InsertionPoint(path=path, type_=ip_type, start=cdata_start, end=cdata_end,
                                     original_value=value, context=EscapeMode.RAW,
                                     nesting_depth=start_depth, container_chain=list(chain))
                out.append(ip)
                if start_depth < MAX_NEST_DEPTH:
                    identity_map = list(range(cdata_start, cdata_end + 1))
                    _sniff_and_recurse(value, identity_map, path, start_depth, chain, out)
            pos = (end + 3) if end != -1 else n
            continue
        if buf[pos:pos + 2] == '<?':
            end = buf.find('?>', pos)
            pos = (end + 2) if end != -1 else n
            continue
        if buf[pos:pos + 2] == '<!':
            end = buf.find('>', pos)
            pos = (end + 1) if end != -1 else n
            continue
        if buf[pos:pos + 2] == '</':
            end = buf.find('>', pos)
            if stack:
                stack.pop()
            pos = (end + 1) if end != -1 else n
            continue

        # Opening tag.
        pos += 1
        name, pos = _read_name(buf, pos)
        if not name:
            # Malformed ('<' followed immediately by a stop char) -- skip
            # one char to guarantee forward progress and keep scanning.
            pos += 1
            continue
        parent = stack[-1] if stack else None
        parent_path = parent.path if parent else base_path
        idx = 1
        if parent is not None:
            idx = parent.child_counts.get(name, 0) + 1
            parent.child_counts[name] = idx
        elem_path = parent_path + '/' + name + '[' + str(idx) + ']'

        while True:
            pos = _skip_ws(buf, pos)
            if pos >= n or buf[pos] in '/>':
                break
            attr_name, pos = _read_name(buf, pos)
            if not attr_name:
                pos += 1
                continue
            pos = _skip_ws(buf, pos)
            if pos < n and buf[pos] == '=':
                pos += 1
                pos = _skip_ws(buf, pos)
                if pos < n and buf[pos] in '"\'':
                    quote = buf[pos]
                    pos += 1
                    val_start = pos
                    val_end = buf.find(quote, pos)
                    if val_end == -1:
                        val_end = n
                    decoded, decoded_to_raw = decode_entities_range(buf, val_start, val_end)
                    attr_path = elem_path + '/@' + attr_name
                    ip_type = InsertionPointType.XML_ATTR if start_depth == 0 else InsertionPointType.XML_ATTR_NESTED
                    ip = InsertionPoint(path=attr_path, type_=ip_type, start=val_start, end=val_end,
                                         original_value=decoded, context=EscapeMode.XML_ATTR,
                                         nesting_depth=start_depth, container_chain=list(chain),
                                         quote_char=quote)
                    out.append(ip)
                    if start_depth < MAX_NEST_DEPTH:
                        _sniff_and_recurse(decoded, decoded_to_raw, attr_path, start_depth, chain, out)
                    pos = val_end + 1
                # else: malformed attribute (no quoted value) -- drop it, loop continues.
            # else: boolean-style attribute with no '=' -- ignored.

        pos = _skip_ws(buf, pos)
        if pos + 1 < n and buf[pos] == '/' and buf[pos + 1] == '>':
            pos += 2
            continue  # self-closing: no frame pushed, no children/text possible
        if pos < n and buf[pos] == '>':
            pos += 1
            stack.append(_Frame(elem_path))
            continue
        # Malformed tag (unterminated '<name ...' with no '>' found) -- bail.
        break

    return out


def detect_in_text(text, translator, base_path='', start_depth=0, chain=None):
    """Scan `text` for XML text/attribute insertion points. Always
    returns a list (possibly empty) -- never raises. Offsets are
    translated to absolute via `translator`."""
    try:
        points = _scan_local(text, start_depth, chain or [], base_path)
    except Exception:
        return []
    for ip in points:
        ip.start = translator(ip.start)
        ip.end = translator(ip.end)
    return points


def detect(full_buf, region_start, region_end):
    """Scan full_buf[region_start:region_end] as XML. Returns
    list[InsertionPoint] with offsets absolute against full_buf."""
    text = full_buf[region_start:region_end]
    return detect_in_text(text, lambda local_pos: region_start + local_pos)
