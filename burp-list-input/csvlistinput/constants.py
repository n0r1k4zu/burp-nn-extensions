# -*- coding: utf-8 -*-
"""Shared enums and lookup tables for the CSV List Input extension."""


class InsertionPointType(object):
    URL_PARAM = "URL_PARAM"
    BODY_PARAM = "BODY_PARAM"
    COOKIE = "COOKIE"
    HEADER = "HEADER"
    JSON_LEAF = "JSON_LEAF"
    JSON_LEAF_NESTED = "JSON_LEAF_NESTED"
    XML_TEXT = "XML_TEXT"
    XML_TEXT_NESTED = "XML_TEXT_NESTED"
    XML_ATTR = "XML_ATTR"
    XML_ATTR_NESTED = "XML_ATTR_NESTED"
    MULTIPART_ATTR = "MULTIPART_ATTR"
    MULTIPART_BODY_LEAF = "MULTIPART_BODY_LEAF"

    NESTED_TYPES = (JSON_LEAF_NESTED, XML_TEXT_NESTED, XML_ATTR_NESTED, MULTIPART_BODY_LEAF)


class EscapeMode(object):
    AUTO = "Auto"
    RAW = "Raw"
    JSON_STRING = "JSON String"
    XML_TEXT = "XML Text"
    XML_ATTR = "XML Attr"
    URL_COMPONENT = "URL Component"

    ALL = (AUTO, RAW, JSON_STRING, XML_TEXT, XML_ATTR, URL_COMPONENT)


class PointStatus(object):
    OK = "OK"
    SKIPPED_PATH_MISSING = "SKIPPED_PATH_MISSING"
    SKIPPED_TYPE_MISMATCH = "SKIPPED_TYPE_MISMATCH"
    SKIPPED_OVERLAP_CONFLICT = "SKIPPED_OVERLAP_CONFLICT"
    # Target & Replace with Decode & Encode: the Find text/pattern didn't match
    # anything in the decoded value -- nothing to do, not an error.
    SKIPPED_NO_MATCH = "SKIPPED_NO_MATCH"
    # Target & Replace with Decode & Encode: decoding the raw value with the
    # configured codec failed (e.g. not valid Base64) -- preview_value
    # carries the error message.
    SKIPPED_DECODE_ERROR = "SKIPPED_DECODE_ERROR"


class SendStatus(object):
    APPLIED = "APPLIED"
    EXHAUSTED = "EXHAUSTED"
    DIAGNOSTIC = "DIAGNOSTIC"
    ERROR = "ERROR"
    REPLACED = "REPLACED"  # Match & Replace fired with no armed-target CSV substitution involved


# IBurpExtenderCallbacks.TOOL_* values, duplicated here so UI code and
# non-Burp-aware modules don't need a live `callbacks` reference just to
# build the checkbox list. Values match the Burp Extender API constants
# (TOOL_SPIDER sits between Proxy and Scanner -- easy to miss and every
# value after it shifts by one slot if it's omitted).
TOOL_FLAG_LABELS = [
    (0x00000001, "Suite"),
    (0x00000002, "Target"),
    (0x00000004, "Proxy"),
    (0x00000008, "Spider"),
    (0x00000010, "Scanner"),
    (0x00000020, "Intruder"),
    (0x00000040, "Repeater"),
    (0x00000080, "Sequencer"),
    (0x00000100, "Decoder"),
    (0x00000200, "Comparer"),
    (0x00000400, "Extender"),
]

DEFAULT_ENABLED_TOOL_FLAGS = set([0x00000040])  # Repeater only, by default

class BurpParamType(object):
    """Mirrors burp.IParameter's PARAM_* constants."""
    URL = 0
    BODY = 1
    COOKIE = 2
    XML = 3
    XML_ATTR = 4
    MULTIPART_ATTR = 5
    JSON = 6


MAX_NEST_DEPTH = 5

# JSON pointer-ish path used to tag the synthetic root of a sniffed-and-recursed
# nested document embedded inside a string leaf.
NESTED_JSON_MARKER = "{json}"
NESTED_XML_MARKER = "{xml}"
