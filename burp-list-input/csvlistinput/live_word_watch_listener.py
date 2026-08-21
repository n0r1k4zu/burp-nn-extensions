# -*- coding: utf-8 -*-
"""IHttpListener implementation for Live Word Watch -- watches live
traffic through the enabled tools and appends a hit (with surrounding
context) to the store the moment the configured word is seen in a
request or response, instead of the on-demand full-history sweep the
History Search tab does.

Completely independent of http_listener.py's CSV Insertion Point /
Match & Replace / Target & Replace with Decode & Encode hot path --
this listener never mutates the request/response it's given and never
touches any of those stores, so it can't interfere with them (Burp
calls every registered IHttpListener for the same event).
"""

from burp import IHttpListener

from csvlistinput import word_search_engine
from csvlistinput.utils import to_display_text
from csvlistinput.constants import TOOL_FLAG_LABELS
from csvlistinput.live_word_watch_store import LiveWordHit

# A short/common search word against a large response (or just an
# ordinary page/script under Proxy) can match hundreds of thousands of
# times in a single message. Without a cap, one such message builds an
# enormous hit list and hammers the store/EDT synchronously on Burp's own
# network thread -- this is what actually froze the whole Burp UI (not
# just this tab) before this cap existed. 200 is already far more than
# anyone reads from one message; the rest of that message's occurrences
# are simply not reported.
_MAX_HITS_PER_MESSAGE = 200

# Every request/response through an enabled tool gets fully converted to
# a Jython string and lowercased before it's searched -- cheap for
# ordinary API traffic, but a real cost when a large video/image/JS
# bundle/download flows through (e.g. Proxy enabled while browsing
# normally). Bodies over this size are skipped entirely rather than
# scanned, so one big response can't add meaningful latency to Burp's
# own traffic-handling thread. 5 MB comfortably covers normal
# request/response bodies without touching genuinely large payloads.
_MAX_SCAN_BYTES = 5 * 1024 * 1024


def _tool_label(tool_flag):
    for flag, label in TOOL_FLAG_LABELS:
        if flag == tool_flag:
            return label
    return "0x%08x" % tool_flag


class LiveWordWatchListener(IHttpListener):
    def __init__(self, callbacks, helpers, settings, store, error_fn=None):
        self.callbacks = callbacks
        self.helpers = helpers
        self.settings = settings
        self.store = store
        self.error_fn = error_fn
        self._last_query_error = None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self.settings.enabled or not self.settings.word:
                return
            if toolFlag not in self.settings.enabled_tool_flags:
                return
            try:
                terms, operator = word_search_engine.parse_search_query(self.settings.word)
                terms = word_search_engine.terms_for_byte_text(terms)
                self._last_query_error = None
            except ValueError as e:
                # Do not flood the Errors tab once per message while the
                # user is still editing an invalid expression.
                message = to_display_text(e)
                if self.error_fn and message != self._last_query_error:
                    self.error_fn("Live Word Watch query", message)
                self._last_query_error = message
                return
            side = "Request" if messageIsRequest else "Response"
            raw_bytes = messageInfo.getRequest() if messageIsRequest else messageInfo.getResponse()
            # Cheapest checks first: a None/oversized body never needs a
            # scope lookup (which itself parses the request), and an
            # out-of-scope message never needs the actual body scan.
            if raw_bytes is None or len(raw_bytes) > _MAX_SCAN_BYTES:
                return
            if self.settings.scope_only and not self._in_scope(messageInfo):
                return
            if operator == '&':
                # Search the complete request/response pair so AND terms can
                # be split across both sides of the same Packet No.
                if not messageIsRequest:
                    self._scan_packet(toolFlag, messageInfo, terms, operator)
            else:
                self._scan(toolFlag, messageInfo, side, raw_bytes, terms, operator)
        except Exception as e:
            if self.error_fn:
                self.error_fn("LiveWordWatchListener.processHttpMessage (tool=%s)" % _tool_label(toolFlag),
                              to_display_text(e))

    def _in_scope(self, messageInfo):
        # Checked before any body conversion -- cuts out third-party/
        # tracker/CDN noise that Proxy otherwise captures during ordinary
        # browsing, which is usually most of the traffic volume by byte
        # count (ads, analytics, fonts, images) and the biggest
        # contributor to sustained CPU cost when scope isn't restricted.
        try:
            url = self.helpers.analyzeRequest(messageInfo).getUrl()
            return self.callbacks.isInScope(url)
        except Exception:
            return True  # fail open -- don't silently drop traffic over a parse error

    def _scan(self, toolFlag, messageInfo, side, raw_bytes, terms, operator):
        text = word_search_engine.message_text(self.helpers, raw_bytes)
        # The cap must be passed into the search itself.  Truncating a fully
        # built result list afterwards still lets a common one-character word
        # allocate millions of hit tuples on Burp's HTTP thread.
        hits = word_search_engine.hits_in_text_for_terms(
            text, terms, operator, self.settings.before_chars, self.settings.after_chars, _MAX_HITS_PER_MESSAGE)
        if not hits:
            return
        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse() if side == "Response" else None
        self._append_hits(toolFlag, side, hits, request_bytes, response_bytes, messageInfo.getHttpService())

    def _scan_packet(self, toolFlag, messageInfo, terms, operator):
        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse()
        if (request_bytes is None or response_bytes is None
                or len(request_bytes) > _MAX_SCAN_BYTES or len(response_bytes) > _MAX_SCAN_BYTES):
            return
        hits = word_search_engine.hits_in_packet_for_terms(
            word_search_engine.message_text(self.helpers, request_bytes),
            word_search_engine.message_text(self.helpers, response_bytes),
            terms, operator, self.settings.before_chars, self.settings.after_chars, _MAX_HITS_PER_MESSAGE)
        for side, before, match, after in hits:
            self._append_hits(toolFlag, side, [(before, match, after)], request_bytes,
                              response_bytes, messageInfo.getHttpService())

    def _append_hits(self, toolFlag, side, hits, request_bytes, response_bytes, http_service):
        tool_label = _tool_label(toolFlag)
        for before, match, after in hits:
            hit = LiveWordHit()
            hit.side = side
            hit.tool_label = tool_label
            # Results are byte-string slices while searching; convert at the
            # UI boundary so JTable/Decode never has to implicitly ASCII
            # decode a raw non-ASCII HTTP byte.
            hit.before = word_search_engine.display_text(before)
            hit.match = word_search_engine.display_text(match)
            hit.after = word_search_engine.display_text(after)
            hit.region = word_search_engine.region_for_hit(
                word_search_engine.message_text(self.helpers,
                    request_bytes if side == 'Request' else response_bytes),
                before, match, after)
            hit.request_bytes = request_bytes
            hit.response_bytes = response_bytes
            hit.http_service = http_service
            self.store.append(hit)
