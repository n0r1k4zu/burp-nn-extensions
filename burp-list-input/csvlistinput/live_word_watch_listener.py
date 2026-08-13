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


def _tool_label(tool_flag):
    for flag, label in TOOL_FLAG_LABELS:
        if flag == tool_flag:
            return label
    return "0x%08x" % tool_flag


class LiveWordWatchListener(IHttpListener):
    def __init__(self, helpers, settings, store, error_fn=None):
        self.helpers = helpers
        self.settings = settings
        self.store = store
        self.error_fn = error_fn

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self.settings.enabled or not self.settings.word:
                return
            if toolFlag not in self.settings.enabled_tool_flags:
                return
            side = "Request" if messageIsRequest else "Response"
            raw_bytes = messageInfo.getRequest() if messageIsRequest else messageInfo.getResponse()
            self._scan(toolFlag, messageInfo, side, raw_bytes)
        except Exception as e:
            if self.error_fn:
                self.error_fn("LiveWordWatchListener.processHttpMessage (tool=%s)" % _tool_label(toolFlag), str(e))

    def _scan(self, toolFlag, messageInfo, side, raw_bytes):
        if raw_bytes is None:
            return
        text = self.helpers.bytesToString(raw_bytes)
        hits = word_search_engine.hits_in_text(text, self.settings.word, self.settings.before_chars,
                                                 self.settings.after_chars)
        if not hits:
            return
        if len(hits) > _MAX_HITS_PER_MESSAGE:
            hits = hits[:_MAX_HITS_PER_MESSAGE]
        request_bytes = messageInfo.getRequest()
        response_bytes = messageInfo.getResponse() if side == "Response" else None
        http_service = messageInfo.getHttpService()
        tool_label = _tool_label(toolFlag)
        for before, match, after in hits:
            hit = LiveWordHit()
            hit.side = side
            hit.tool_label = tool_label
            hit.before = before
            hit.match = match
            hit.after = after
            hit.request_bytes = request_bytes
            hit.response_bytes = response_bytes
            hit.http_service = http_service
            self.store.append(hit)
