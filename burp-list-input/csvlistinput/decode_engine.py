# -*- coding: utf-8 -*-
"""Best-effort multi-format decode/encode preview for the Decode tab.
Pure-Python (no Burp helpers needed) so it stays independently testable
and works with no armed target / no HttpService in play. Each transform
is tried independently and reports its own success or failure -- one bad
transform (e.g. text that isn't valid Base64) never prevents the others
from showing.

Byte-level work uses `bytearray` throughout rather than raw str/bytes
slicing -- bytearray iterates as ints uniformly, which sidesteps the
str/unicode implicit-ASCII-promotion crash this project hit repeatedly
elsewhere (see utils.py's module docstring).
"""

import base64
import re

from csvlistinput.utils import to_display_text

try:
    import htmlentitydefs  # Jython 2 / CPython 2
except ImportError:
    import html.entities as htmlentitydefs  # CPython 3, for the test harness only

try:
    _unichr = unichr
except NameError:
    _unichr = chr

_HEX_DIGITS = '0123456789abcdefABCDEF'


class DecodeResult(object):
    def __init__(self, label, text=None, error=None):
        self.label = label
        self.text = text
        self.error = error

    def ok(self):
        return self.error is None


def _bytes_to_text(raw_bytes):
    try:
        return raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return raw_bytes.decode('latin-1')


def _url_decode(text):
    raw = bytearray()
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '%' and i + 2 < n and text[i + 1] in _HEX_DIGITS and text[i + 2] in _HEX_DIGITS:
            raw.append(int(text[i + 1:i + 3], 16))
            i += 3
        elif c == '+':
            raw.append(0x20)
            i += 1
        else:
            raw.extend(bytearray(c.encode('utf-8')))
            i += 1
    return _bytes_to_text(bytes(raw))


def _url_encode(text):
    out = []
    for b in bytearray(text.encode('utf-8')):
        ch = chr(b)
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or ch in '-_.~':
            out.append(ch)
        else:
            out.append('%%%02X' % b)
    return ''.join(out)


def _base64_decode(text):
    normalized = text.strip().replace('-', '+').replace('_', '/')
    normalized = re.sub(r'\s+', '', normalized)
    if not normalized:
        raise ValueError("empty input")
    normalized += '=' * ((-len(normalized)) % 4)
    raw = base64.b64decode(normalized.encode('ascii'))
    return _bytes_to_text(raw)


def _base64_encode(text):
    raw = bytes(bytearray(text.encode('utf-8')))
    return base64.b64encode(raw).decode('ascii')


def _hex_decode(text):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', text)
    if not cleaned:
        raise ValueError("empty input")
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    raw = bytearray()
    for i in range(0, len(cleaned), 2):
        raw.append(int(cleaned[i:i + 2], 16))
    return _bytes_to_text(bytes(raw))


def _hex_encode(text):
    return ''.join('%02x' % b for b in bytearray(text.encode('utf-8')))


_HTML_ENTITY_RE = re.compile(r'&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);')


def _html_decode(text):
    def repl(m):
        ent = m.group(1)
        try:
            if ent[0:2] in ('#x', '#X'):
                return _unichr(int(ent[2:], 16))
            if ent[0:1] == '#':
                return _unichr(int(ent[1:]))
            codepoint = htmlentitydefs.name2codepoint.get(ent)
            if codepoint is not None:
                return _unichr(codepoint)
        except (ValueError, OverflowError):
            pass
        return m.group(0)
    return _HTML_ENTITY_RE.sub(repl, text)


def _html_encode(text):
    out = []
    for ch in text:
        if ch == '&':
            out.append('&amp;')
        elif ch == '<':
            out.append('&lt;')
        elif ch == '>':
            out.append('&gt;')
        elif ch == '"':
            out.append('&quot;')
        elif ch == "'":
            out.append('&#39;')
        else:
            out.append(ch)
    return ''.join(out)


_UNICODE_ESCAPE_RE = re.compile(r'\\u([0-9a-fA-F]{4})')


def _unicode_escape_decode(text):
    if not _UNICODE_ESCAPE_RE.search(text):
        raise ValueError("no \\uXXXX escapes found")
    return _UNICODE_ESCAPE_RE.sub(lambda m: _unichr(int(m.group(1), 16)), text)


def _rot13(text):
    out = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr((code - 65 + 13) % 26 + 65))
        elif 97 <= code <= 122:
            out.append(chr((code - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)


def _jwt_decode(text):
    parts = text.strip().split('.')
    if len(parts) < 2:
        raise ValueError("not a JWT (expected header.payload[.signature])")

    def decode_segment(seg):
        seg = seg.replace('-', '+').replace('_', '/')
        seg += '=' * ((-len(seg)) % 4)
        raw = base64.b64decode(seg.encode('ascii'))
        return _bytes_to_text(raw)

    header = decode_segment(parts[0])
    payload = decode_segment(parts[1])
    return "header:\n%s\n\npayload:\n%s" % (header, payload)


_TRANSFORMS = [
    ("URL Decode", _url_decode),
    ("URL Encode", _url_encode),
    ("Base64 Decode", _base64_decode),
    ("Base64 Encode", _base64_encode),
    ("Hex Decode", _hex_decode),
    ("Hex Encode", _hex_encode),
    ("HTML Entity Decode", _html_decode),
    ("HTML Entity Encode", _html_encode),
    ("Unicode \\uXXXX Decode", _unicode_escape_decode),
    ("ROT13", _rot13),
    ("JWT Decode (header/payload, unverified)", _jwt_decode),
]

# Exposed so the UI can build one checkbox per transform (manual on/off
# switching) without duplicating this list.
TRANSFORM_LABELS = [label for label, _fn in _TRANSFORMS]


def run_all(text, enabled_labels=None):
    """Runs every transform in TRANSFORM_LABELS whose label is in
    `enabled_labels`, or all of them if `enabled_labels` is None (the
    "auto" default -- try everything, let each transform report its own
    applicability)."""
    if text is None:
        text = u""
    results = []
    for label, fn in _TRANSFORMS:
        if enabled_labels is not None and label not in enabled_labels:
            continue
        try:
            out = fn(text)
            results.append(DecodeResult(label, text=out))
        except Exception as e:
            results.append(DecodeResult(label, error=to_display_text(e)))
    return results
