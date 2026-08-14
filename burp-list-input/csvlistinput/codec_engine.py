# -*- coding: utf-8 -*-
"""Byte-string-space (see utils.py) encode/decode codec pairs used by the
Target & Replace with Decode & Encode feature: decode an Insertion Point's raw
value, run a find/replace on the decoded text, then re-encode with the
SAME codec before splicing the result back into the request.

Deliberately separate from decode_engine.py (the read-only Decode tab's
display-oriented transforms, which work with real Unicode via UTF-8
round trips). Everything here consumes and returns plain `str` where one
character IS one raw byte -- calling a real text codec's .encode() on a
byte-string-space `str` would trigger the classic Python 2/Jython
str+unicode implicit-ASCII-promotion crash this project hit repeatedly
elsewhere (see utils.py's module docstring), so every decode step that
can produce a codepoint above ASCII explicitly folds it to UTF-8 bytes
(one byte -> one byte-string-space character) instead of leaving a bare
non-Latin-1 unicode character in the result.
"""

import base64
import re

try:
    import htmlentitydefs  # Jython 2 / CPython 2
except ImportError:
    import html.entities as htmlentitydefs  # CPython 3, for the test harness only

try:
    _unichr = unichr
except NameError:
    _unichr = chr

_HEX_DIGITS = '0123456789abcdefABCDEF'


def _as_binary(s):
    """Adapt byte-string-space values for CPython test execution.

    Jython's ``str`` already is the byte type used throughout this module.
    CPython 3 distinguishes ``str`` and ``bytes``, so use Latin-1 as the
    identity mapping only at the base64 library boundary.
    """
    if isinstance(s, bytes):
        return s
    return s.encode('latin-1')


def _from_binary(raw):
    if isinstance(raw, bytes):
        return raw.decode('latin-1')
    return raw


def _codepoint_to_bytestring(codepoint):
    """ASCII passes through as a single byte; anything above gets folded
    to its UTF-8 byte sequence (each resulting byte becomes one
    byte-string-space character) -- matches this codebase's UTF-8-first
    convention (payload_text_encoding defaults to utf-8 everywhere else)."""
    if codepoint <= 0x7F:
        return chr(codepoint)
    return _unichr(codepoint).encode('utf-8')


def identity(s):
    return s


def url_decode(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '%' and i + 2 < n and s[i + 1] in _HEX_DIGITS and s[i + 2] in _HEX_DIGITS:
            out.append(chr(int(s[i + 1:i + 3], 16)))
            i += 3
        elif c == '+':
            out.append(' ')
            i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def url_encode(s):
    out = []
    for ch in s:
        b = ord(ch)
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or ch in '-_.~':
            out.append(ch)
        else:
            out.append('%%%02X' % b)
    return ''.join(out)


_BASE64_CHARS_RE = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
# A Base64 value is often embedded in a JSON/string wrapper (for example
# ``prefix:SGVsbG8=;suffix``).  Keep this deliberately conservative: only
# token-shaped runs are considered and the decoded bytes must look like text.
_BASE64_TOKEN_RE = re.compile(r'(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{4,}={0,2})(?![A-Za-z0-9+/_-])')
_HEX_TOKEN_RE = re.compile(r'(?<![0-9A-Fa-f])([0-9A-Fa-f]{4,})(?![0-9A-Fa-f])')


def base64_decode(s):
    normalized = re.sub(r'\s+', '', s.strip()).replace('-', '+').replace('_', '/')
    if not normalized:
        raise ValueError("empty input")
    normalized += '=' * ((-len(normalized)) % 4)
    # base64.b64decode() in Python 2 (Jython 2.7's stdlib) has no
    # validate= kwarg -- it silently drops unrecognized characters
    # instead of raising, which would let obviously-invalid input
    # through as garbage. Check the alphabet ourselves first so a
    # misconfigured "Base64" codec choice reports a clear
    # SKIPPED_DECODE_ERROR instead of splicing nonsense into the request.
    if not _BASE64_CHARS_RE.match(normalized):
        raise ValueError("not valid Base64 (contains non-Base64 characters)")
    return _from_binary(base64.b64decode(_as_binary(normalized)))


def base64_encode(s):
    return _from_binary(base64.b64encode(_as_binary(s)))


def _looks_like_text(value):
    """Return whether decoded bytes are safe to expose as replacement text."""
    try:
        if isinstance(value, bytes):
            decoded = value.decode('utf-8')
        else:
            # Jython byte-string-space ``str`` exposes decode(); CPython's
            # test representation is a Latin-1 ``str`` and needs the
            # equivalent bytes round-trip first.
            decoded = value.decode('utf-8')
    except AttributeError:
        try:
            decoded = value.encode('latin-1').decode('utf-8')
        except (UnicodeDecodeError, UnicodeEncodeError):
            return False
    except UnicodeDecodeError:
        # Treat opaque binary blobs as non-candidates.  This also prevents
        # ordinary wrapper words such as ``prefix`` from being mistaken for
        # Base64 merely because their decoded bytes are printable by chance.
        return False
    for ch in decoded:
        code = ord(ch)
        if code < 0x20 and ch not in ('\t', '\r', '\n'):
            return False
    return True


def base64_embedded_parts(value):
    """Return ``(start, end, decoded)`` for text-like embedded Base64 runs.

    This is a tolerant companion to :func:`base64_decode`; the latter remains
    strict for standalone values.  Invalid/opaque candidates are ignored so
    wrappers and ordinary text are never replaced accidentally.
    """
    parts = []
    for match in _BASE64_TOKEN_RE.finditer(value):
        token = match.group(1)
        try:
            decoded = base64_decode(token)
        except (ValueError, TypeError, IndexError):
            continue
        if _looks_like_text(decoded):
            parts.append((match.start(1), match.end(1), decoded))
    return parts


def base64_decode_embedded(value):
    """Decode text-like Base64 runs while preserving surrounding text."""
    parts = base64_embedded_parts(value)
    if not parts:
        raise ValueError("no embedded Base64 value found")
    out = []
    cursor = 0
    for start, end, decoded in parts:
        out.append(value[cursor:start])
        out.append(decoded)
        cursor = end
    out.append(value[cursor:])
    return ''.join(out)


def hex_embedded_parts(value):
    """Return text-like embedded hexadecimal runs for nested-codec preview."""
    parts = []
    for match in _HEX_TOKEN_RE.finditer(value):
        token = match.group(1)
        if len(token) % 2:
            continue
        try:
            decoded = hex_decode(token)
        except (ValueError, TypeError):
            continue
        if _looks_like_text(decoded):
            parts.append((match.start(1), match.end(1), decoded))
    return parts


def hex_decode_embedded(value):
    parts = hex_embedded_parts(value)
    if not parts:
        raise ValueError("no embedded hexadecimal value found")
    out = []
    cursor = 0
    for start, end, decoded in parts:
        out.append(value[cursor:start])
        out.append(decoded)
        cursor = end
    out.append(value[cursor:])
    return ''.join(out)


def hex_decode(s):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', s)
    if not cleaned:
        raise ValueError("empty input")
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    out = []
    for i in range(0, len(cleaned), 2):
        out.append(chr(int(cleaned[i:i + 2], 16)))
    return ''.join(out)


def hex_encode(s):
    return ''.join('%02x' % ord(ch) for ch in s)


_HTML_ENTITY_RE = re.compile(r'&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);')


def html_decode(s):
    def repl(m):
        ent = m.group(1)
        try:
            if ent[0:2] in ('#x', '#X'):
                codepoint = int(ent[2:], 16)
            elif ent[0:1] == '#':
                codepoint = int(ent[1:])
            else:
                codepoint = htmlentitydefs.name2codepoint.get(ent)
                if codepoint is None:
                    return m.group(0)
            return _codepoint_to_bytestring(codepoint)
        except (ValueError, OverflowError):
            return m.group(0)
    return _HTML_ENTITY_RE.sub(repl, s)


def html_encode(s):
    # Deliberately only re-escapes the 5 XML-reserved characters (not a
    # full inverse of every entity html_decode() might understand) --
    # matches decode_engine.py's own Decode-tab scope for the same reason:
    # a byte-level round trip of every possible named/numeric entity has
    # no single unambiguous answer.
    out = []
    for ch in s:
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


def unicode_escape_decode(s):
    return _UNICODE_ESCAPE_RE.sub(lambda m: _codepoint_to_bytestring(int(m.group(1), 16)), s)


def unicode_escape_encode(s):
    try:
        text = s.decode('utf-8')
    except UnicodeDecodeError:
        text = s.decode('latin-1')
    out = []
    for ch in text:
        code = ord(ch)
        if code > 0x7e or code < 0x20:
            out.append('\\u%04x' % code)
        else:
            out.append(chr(code))
    return ''.join(out)


def rot13(s):
    out = []
    for ch in s:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr((code - 65 + 13) % 26 + 65))
        elif 97 <= code <= 122:
            out.append(chr((code - 97 + 13) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)


CODEC_PAIRS = {
    "None": (identity, identity),
    "URL": (url_decode, url_encode),
    "Base64": (base64_decode, base64_encode),
    "Hex": (hex_decode, hex_encode),
    "HTML Entity": (html_decode, html_encode),
    "Unicode \\uXXXX": (unicode_escape_decode, unicode_escape_encode),
    "ROT13": (rot13, rot13),
}

# A chain is written "outer -> inner": decoding runs from left to right,
# while encoding runs in reverse.  Thus "URL -> Base64" handles a value that
# was Base64-encoded first and URL-encoded afterwards.  The combo box offers
# common one/two-layer chains; it is editable, so operators can enter three
# or more layers such as "URL -> Base64 -> URL" when needed.
_SINGLE_CODEC_NAMES = ["None", "URL", "Base64", "Hex", "HTML Entity", "Unicode \\uXXXX", "ROT13"]
_NESTABLE_CODEC_NAMES = [name for name in _SINGLE_CODEC_NAMES if name != "None"]
_NESTED_SEPARATOR = " -> "
_LEGACY_NESTED_SEPARATOR = u" → "

# Exposed so the UI can build the Codec combo box without duplicating this
# list. Include common ordered two-layer combinations, including repeated
# encodings such as URL → URL. Longer chains are parsed from editable input
# rather than generating hundreds of hard-to-navigate menu entries.
CODEC_NAMES = list(_SINGLE_CODEC_NAMES)
CODEC_NAMES.extend([outer + _NESTED_SEPARATOR + inner
                    for outer in _NESTABLE_CODEC_NAMES for inner in _NESTABLE_CODEC_NAMES])


def codec_steps(codec_name):
    """Return the decode steps for a configured Codec display name.

    A KeyError deliberately signals a stale/invalid saved rule to the caller
    as a decode failure rather than silently applying a different transform.
    """
    if codec_name in CODEC_PAIRS:
        return [codec_name]
    # Accept the former Unicode-arrow form in saved rules, while only showing
    # ASCII separators in the UI to avoid font/encoding mojibake on Burp's
    # Java runtime.
    codec_name = codec_name.replace(_LEGACY_NESTED_SEPARATOR, _NESTED_SEPARATOR)
    parts = [part.strip() for part in codec_name.split(_NESTED_SEPARATOR)]
    if len(parts) < 2 or any(part not in _NESTABLE_CODEC_NAMES for part in parts):
        raise KeyError(codec_name)
    return parts


def decode_value(codec_name, value):
    """Decode one or more layers, from the outermost layer inward."""
    for step in codec_steps(codec_name):
        # ``hex_decode`` historically accepts separators; when the value has
        # non-hex wrapper text, select the embedded-token path explicitly so
        # the wrapper is not discarded by that permissive legacy decoder.
        if step == "Hex" and re.search(r'[^0-9A-Fa-f\s]', value):
            value = hex_decode_embedded(value)
            continue
        try:
            value = CODEC_PAIRS[step][0](value)
        except ValueError:
            # URL-decoded JSON/form values can contain a Base64 token next to
            # ordinary text.  Decode those tokens in place instead of making
            # the preview (and the rule) fail because the whole field is not
            # itself Base64.
            if step not in ("Base64", "Hex"):
                raise
            value = (base64_decode_embedded(value) if step == "Base64"
                     else hex_decode_embedded(value))
    return value


def encode_value(codec_name, value):
    """Re-encode one or more layers, from the innermost layer outward."""
    for step in reversed(codec_steps(codec_name)):
        value = CODEC_PAIRS[step][1](value)
    return value
