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

    decode_fn, encode_fn = codec_engine.CODEC_PAIRS[rule.codec]
    decoded = decode_fn(raw_value)

    find = to_bytestring_space(rule.find)
    if not find:
        raise ValueError("Find is empty")
    replace_with = to_bytestring_space(rule.replace_with)

    if rule.is_regex:
        pattern = re.compile(find)
        new_decoded, hit_count = pattern.subn(replace_with, decoded)
    else:
        hit_count = decoded.count(find)
        new_decoded = decoded.replace(find, replace_with)

    new_raw_value = encode_fn(new_decoded)
    return new_raw_value, hit_count
