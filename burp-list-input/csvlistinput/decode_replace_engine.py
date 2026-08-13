# -*- coding: utf-8 -*-
"""Decode -> find/replace -> re-encode pipeline for a single Insertion
Point, driving the Target & Replace with Decode & Encode feature: an Insertion
Point's raw value is decoded with the rule's chosen codec (codec_engine),
a plain-substring or regex find/replace runs on that decoded text, then
the SAME codec re-wraps the result before it's spliced back into the
request. Everything here stays in byte-string space (see utils.py)
throughout.
"""

import re

from csvlistinput import codec_engine
from csvlistinput.utils import to_bytestring_space

try:
    _UNICODE_TYPE = unicode
    _BYTES_TYPE = str
except NameError:  # CPython 3 test runtime
    _UNICODE_TYPE = str
    _BYTES_TYPE = bytes


def apply_rule(raw_value, rule):
    """raw_value: byte-string-space str (the Insertion Point's current
    value, possibly None). rule: DecodeReplaceRule.

    Returns (new_raw_value, hit_count). hit_count is 0 (with
    new_raw_value == raw_value's re-encoded round trip) when Find didn't
    match anything -- the caller should treat that as "nothing to do",
    not an error. Raises on a genuine failure (bad codec input, invalid
    regex) for the caller to report as a skip.
    """
    if raw_value is None:
        raw_value = ''

    decoded = codec_engine.decode_value(rule.codec, raw_value)

    find = to_bytestring_space(rule.find)
    if not find:
        raise ValueError("Find is empty")
    replace_with = to_bytestring_space(rule.replace_with)
    # CPython's test runtime represents decoded codec output as text while
    # the Jython/Burp runtime uses a byte-string ``str`` for both values.
    # Normalize only that test-runtime boundary; production values are
    # already the same type and take this branch nowhere.
    if isinstance(decoded, _UNICODE_TYPE) and isinstance(find, _BYTES_TYPE):
        find = find.decode('latin-1')
        replace_with = replace_with.decode('latin-1')

    if rule.is_regex:
        pattern = re.compile(find)
        new_decoded, hit_count = pattern.subn(replace_with, decoded)
    else:
        hit_count = decoded.count(find)
        new_decoded = decoded.replace(find, replace_with)

    new_raw_value = codec_engine.encode_value(rule.codec, new_decoded)
    return new_raw_value, hit_count
