# -*- coding: utf-8 -*-
"""Byte/string boundary helpers and context-aware escaping.

Everything downstream of `bytes_to_bytestring` operates in a "byte-string"
space where one Jython string character == one raw HTTP byte (Latin-1 /
ISO-8859-1 identity mapping, which is exactly what Burp's
IExtensionHelpers.bytesToString/stringToBytes round-trip use internally).
Never call .decode('utf-8') anywhere on these strings -- that would break
every byte offset computed by the JSON/XML parsers.
"""

import codecs
import re

from csvlistinput.constants import EscapeMode, InsertionPointType

CONTENT_LENGTH_RE = re.compile(r'(?im)^Content-Length:[ \t]*(\d+)[ \t]*\r?$')

NAMED_XML_ENTITIES = {
    'amp': '&',
    'lt': '<',
    'gt': '>',
    'apos': "'",
    'quot': '"',
}

JSON_BACKSLASH_ESCAPES = {
    '"': '"',
    '\\': '\\',
    '/': '/',
    'b': '\b',
    'f': '\f',
    'n': '\n',
    'r': '\r',
    't': '\t',
}

JSON_ESCAPE_OUT = {
    '"': '\\"',
    '\\': '\\\\',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
}


def bytes_to_bytestring(helpers, java_bytes):
    """Java byte[] -> Jython byte-preserving string (1 char == 1 byte).

    Jython's coercion of the underlying java.lang.String is not
    necessarily a clean Python `str` or `unicode` -- it can come back as
    a Java-String-backed proxy object that behaves string-like (supports
    indexing, slicing, +) without satisfying `isinstance(s, unicode)`,
    which made an earlier version of this normalization silently miss it.
    Route through `unicode(s)` unconditionally instead of branching on a
    type check: Jython's coercion machinery handles all three possible
    input shapes (str, unicode, java.lang.String proxy) uniformly there,
    producing a real Python `unicode` every time. Then flatten that to a
    definite `str` via the same lossless Latin-1 round trip bytesToString
    itself relies on (every character's codepoint is guaranteed 0-255).
    This is what the rest of this codebase -- written entirely with plain
    `str` literals -- assumes throughout: Python 2/Jython 2 silently
    promotes str+unicode concatenation/joining through an implicit ASCII
    decode, which raises UnicodeDecodeError the moment any non-ASCII byte
    (e.g. UTF-8-encoded Japanese text) is involved on either side.
    """
    s = helpers.bytesToString(java_bytes)
    return unicode(s).encode('latin-1')


def bytestring_to_bytes(helpers, s):
    """Jython byte-preserving string -> Java byte[]."""
    return helpers.stringToBytes(s)


def find_content_length_span(buf, header_region_end):
    """Return (digits_start, digits_end) of the Content-Length header's
    numeric value within buf[:header_region_end], or (None, None)."""
    header_block = buf[:header_region_end]
    m = CONTENT_LENGTH_RE.search(header_block)
    if not m:
        return None, None
    return m.start(1), m.end(1)


def looks_like_json(s):
    stripped = s.strip()
    if len(stripped) < 2:
        return False
    return ((stripped[0] == '{' and stripped[-1] == '}') or
            (stripped[0] == '[' and stripped[-1] == ']'))


def looks_like_xml(s):
    stripped = s.strip()
    if len(stripped) < 3:
        return False
    return stripped[0] == '<' and stripped[-1] == '>'


def looks_numeric(s):
    if s is None:
        return False
    s = s.strip()
    if not s:
        return False
    try:
        float(s)
        return True
    except ValueError:
        return False


def json_string_escape(s):
    out = []
    for ch in s:
        if ch in JSON_ESCAPE_OUT:
            out.append(JSON_ESCAPE_OUT[ch])
        elif ord(ch) < 0x20:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    return ''.join(out)


def xml_text_escape(s):
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    s = s.replace('>', '&gt;')
    return s


def xml_attr_escape(s, quote_char):
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    if quote_char == "'":
        s = s.replace("'", '&apos;')
    else:
        s = s.replace('"', '&quot;')
    return s


def strip_crlf(s):
    return s.replace('\r', '').replace('\n', '')


_HEX_DIGITS = '0123456789abcdefABCDEF'


def url_decode_with_map(buf, start, end, plus_as_space=True):
    """Percent-decode buf[start:end] (query-string / x-www-form-urlencoded
    style: '%XX' -> byte, optionally '+' -> space). Returns (decoded,
    decoded_to_raw), symmetric to xml_offset_scanner.decode_entities_range:
    decoded_to_raw[i] is the raw offset (within buf) that decoded
    character i originated from, with decoded_to_raw[len(decoded)] == end
    as a sentinel for end-of-range lookups. This is what lets nested
    JSON/XML found inside a URL-encoded parameter value (query param,
    cookie, x-www-form-urlencoded body field) get byte-accurate offsets
    back into the original buffer, the same way JSON string escapes and
    XML entities do.
    """
    decoded_chars = []
    decoded_to_raw = []
    pos = start
    while pos < end:
        c = buf[pos]
        if c == '%' and pos + 3 <= end and buf[pos + 1] in _HEX_DIGITS and buf[pos + 2] in _HEX_DIGITS:
            decoded_chars.append(chr(int(buf[pos + 1:pos + 3], 16)))
            decoded_to_raw.append(pos)
            pos += 3
            continue
        if plus_as_space and c == '+':
            decoded_chars.append(' ')
            decoded_to_raw.append(pos)
            pos += 1
            continue
        decoded_chars.append(c)
        decoded_to_raw.append(pos)
        pos += 1
    decoded_to_raw.append(end)
    return ''.join(decoded_chars), decoded_to_raw


def to_bytestring_space(text, encoding='utf-8'):
    """Convert real Unicode text (e.g. a CSV cell decoded from Shift_JIS
    or UTF-8) into the same "byte-string" space as the request buffer
    (one char == one raw byte, see the module docstring): encode as
    `encoding`, then reinterpret each resulting byte as one Latin-1
    character. This must run before any text is spliced into `buf` --
    otherwise non-ASCII payload values (Japanese names, etc.) would be
    concatenated against a buffer that represents raw bytes 1:1, silently
    corrupting anything downstream of the insertion point.
    Already-byte-string-space input (plain ASCII, or text that has
    already been through this conversion) passes through unchanged.
    """
    if text is None:
        return text
    return text.encode(encoding).decode('latin-1')


def from_bytestring_space(bytestring_text, encoding='utf-8'):
    """Inverse of to_bytestring_space(): given byte-string-space text (a
    plain `str` where each character IS one raw byte, see the module
    docstring), decode it as `encoding` to recover real Unicode text --
    e.g. for populating a Match & Replace rule's Before field from a
    right-clicked text selection in a message editor. Falls back to a
    Latin-1 decode (which never raises, since every byte 0-255 has a
    Latin-1 codepoint) if `encoding` doesn't apply cleanly, so callers
    always get *something* usable rather than an exception -- worst case
    is mojibake the user can retype, not a crash.
    """
    if bytestring_text is None:
        return bytestring_text
    try:
        return bytestring_text.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        return bytestring_text.decode('latin-1')


class Utf8CsvRecoder(object):
    """Python 2's csv module cannot read arbitrary encodings/Unicode
    directly (it operates on 8-bit byte strings). Standard workaround
    (per the csv module's own documentation): decode with the requested
    encoding, then feed csv.reader UTF-8-encoded bytes -- comma/quote/
    newline delimiters stay single-byte-safe in UTF-8, and decoded field
    text is recovered afterwards with `csv_cell_to_unicode`. Shared by
    csv_payload_store.py and replace_rule_store.py."""

    def __init__(self, f, encoding):
        self.reader = codecs.getreader(encoding)(f)

    def __iter__(self):
        return self

    def next(self):
        return next(self.reader).encode('utf-8')

    __next__ = next


def csv_cell_to_unicode(s):
    return s.decode('utf-8')


def escape_bytestring_for_context(raw_value, insertion_point, escape_mode, helpers=None,
                                   allow_crlf_in_headers=False):
    """Same job as escape_for_context, but `raw_value` is ALREADY in
    byte-string space (not real Unicode) -- for features that derive
    their replacement value from the request's own bytes (e.g. Target &
    Replace with Decode's decode -> find/replace -> re-encode pipeline)
    rather than from user-typed/CSV-sourced real-Unicode text. Passing
    such a value through escape_for_context's to_bytestring_space() step
    would re-encode already-byte-safe content and risk the classic
    str/unicode promotion crash on non-ASCII bytes -- this entry point
    skips that step entirely.
    """
    mode = escape_mode
    if mode == EscapeMode.AUTO or mode is None:
        mode = insertion_point.context or EscapeMode.RAW

    if mode == EscapeMode.RAW:
        value = raw_value
    elif mode == EscapeMode.JSON_STRING:
        value = json_string_escape(raw_value)
    elif mode == EscapeMode.XML_TEXT:
        value = xml_text_escape(raw_value)
    elif mode == EscapeMode.XML_ATTR:
        value = xml_attr_escape(raw_value, insertion_point.quote_char or '"')
    elif mode == EscapeMode.URL_COMPONENT:
        value = helpers.urlEncode(raw_value) if helpers is not None else raw_value
    else:
        value = raw_value

    if insertion_point.type == InsertionPointType.HEADER and not allow_crlf_in_headers:
        value = strip_crlf(value)

    return value


def escape_for_context(raw_value, insertion_point, escape_mode, helpers=None,
                        allow_crlf_in_headers=False, payload_encoding='utf-8'):
    """Turn a raw CSV cell value into the bytes to splice in, given the
    insertion point's context. `escape_mode` may be EscapeMode.AUTO, in
    which case insertion_point.context (a concrete mode assigned at
    detection time) is used. `raw_value` is expected to be real Unicode
    text (as produced by csv_payload_store); it is converted to
    byte-string space via `payload_encoding` before any splicing-context
    escaping is applied.
    """
    raw_value = to_bytestring_space(raw_value, payload_encoding)
    return escape_bytestring_for_context(raw_value, insertion_point, escape_mode, helpers=helpers,
                                          allow_crlf_in_headers=allow_crlf_in_headers)
