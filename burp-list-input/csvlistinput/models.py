# -*- coding: utf-8 -*-
"""Plain data classes shared across the extension (Jython 2.7 has no dataclasses)."""

from csvlistinput.constants import EscapeMode


class InsertionPoint(object):
    """A single substitutable location, expressed in byte-string offsets
    (see utils.py for the byte-preserving string-space discipline) against
    whichever buffer it was most recently detected against.

    `path` is the stable structural identity used to re-join a template
    insertion point (detected once at "arm" time) with the corresponding
    point detected fresh on a live outgoing request -- offsets are NEVER
    persisted/reused across requests, only `path`.
    """

    def __init__(self, path, type_, start, end, original_value,
                 context=EscapeMode.AUTO, nesting_depth=0, container_chain=None,
                 quote_char=None, multipart_part_index=None):
        self.path = path
        self.type = type_
        self.start = start
        self.end = end
        self.original_value = original_value
        self.context = context
        self.nesting_depth = nesting_depth
        self.container_chain = container_chain if container_chain is not None else []
        self.quote_char = quote_char
        self.multipart_part_index = multipart_part_index
        # Set True when this point was only found via lenient/best-effort
        # recovery from malformed JSON (see json_offset_parser.detect_in_text)
        # -- its path/offsets are plausible but not guaranteed correct;
        # the UI should flag it rather than presenting it at full confidence.
        self.recovered = False

    def __repr__(self):
        return "InsertionPoint(path=%r, type=%s, start=%s, end=%s)" % (
            self.path, self.type, self.start, self.end)


class ConnectionSignature(object):
    def __init__(self, protocol, host, port, method, url_path):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.method = method
        # Trim exactly one trailing slash, per plan's documented v1 normalization.
        if url_path and url_path != "/" and url_path.endswith("/"):
            url_path = url_path[:-1]
        self.url_path = url_path

    def as_tuple(self):
        return (self.protocol, self.host, self.port, self.method, self.url_path)

    def matches_host_path(self, other):
        return (self.protocol == other.protocol and self.host == other.host
                and self.port == other.port and self.url_path == other.url_path)

    def __eq__(self, other):
        if not isinstance(other, ConnectionSignature):
            return False
        return self.as_tuple() == other.as_tuple()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.as_tuple())

    def __repr__(self):
        return "%s %s://%s:%s%s" % (self.method, self.protocol, self.host, self.port, self.url_path)


class Edit(object):
    """One splice operation: replace buf[start:end] with replacement."""

    def __init__(self, start, end, replacement, path=None):
        self.start = start
        self.end = end
        self.replacement = replacement
        self.path = path


class PointResult(object):
    def __init__(self, path, column, status, preview_value=None):
        self.path = path
        self.column = column
        self.status = status
        self.preview_value = preview_value


class LogEntry(object):
    def __init__(self):
        self.seq_id = None
        self.timestamp = None
        self.tool_flag = None
        self.tool_label = None
        self.send_status = None
        self.csv_row_index_used = None  # internal 0-based pointer position
        self.csv_row_no = None          # the value of the CSV's own "No" column for that row
        self.csv_row_values = None
        self.per_point_results = []  # list[PointResult]
        self.request_bytes_after = None
        self.connection_display = None
        self.http_service = None
        self.response_bytes = None  # populated later, when the response-phase IHttpListener callback fires
        self.response_status = None
        self.note = None
        # Match & Replace: count of rule-matches applied on the request/
        # response side of this transaction (0 if the feature didn't touch
        # it). Independent of per_point_results, which is CSV Insertion
        # Point-specific.
        self.request_replace_count = 0
        self.response_replace_count = 0
        # Match & Replace: the raw bytes as seen before replacement was
        # applied, so the Log tab can show a before/after comparison.
        # Stays None when Match & Replace didn't touch that side of the
        # transaction (nothing to compare against).
        self.request_bytes_before = None
        self.response_bytes_before = None
        # Lazily resolved, cached 1-based position of this transaction
        # within Burp's Proxy History (see log_panel.py's "Packet No"
        # column) -- None means "not looked up yet", -1 means "looked up,
        # not found there" (e.g. a Repeater-only send never went through
        # the Proxy listener).
        self.packet_no = None

    def status_summary(self):
        if not self.per_point_results:
            return self.send_status
        ok = sum(1 for r in self.per_point_results if r.status == "OK")
        total = len(self.per_point_results)
        return "%s (%d/%d applied)" % (self.send_status, ok, total)
