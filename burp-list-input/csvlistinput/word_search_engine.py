# -*- coding: utf-8 -*-
"""Searches the Proxy history's raw request/response bytes for a literal
word (case-insensitive, non-overlapping occurrences) and returns each hit
together with a caller-specified window of surrounding text. Kept
separate from the History Search tab's Swing code
(ui/word_search_panel.py) -- this module only decides what to search,
not how it's presented.
"""


def _find_all_spans(haystack_lower, needle_lower, max_spans=None):
    """Returns non-overlapping occurrence spans, optionally stopping after
    ``max_spans``.  Applying the limit while scanning is important for live
    traffic: building all spans for a one-character word in a multi-megabyte
    response can otherwise consume enough CPU and memory to block Burp's
    HTTP-processing thread."""
    spans = []
    if not needle_lower or (max_spans is not None and max_spans <= 0):
        return spans
    start = 0
    while True:
        idx = haystack_lower.find(needle_lower, start)
        if idx < 0:
            break
        end = idx + len(needle_lower)
        spans.append((idx, end))
        if max_spans is not None and len(spans) >= max_spans:
            break
        start = end
    return spans


def _hits_in_text(text, word_lower, before_chars, after_chars, max_hits=None):
    if not text:
        return []
    text_lower = text.lower()
    hits = []
    for start, end in _find_all_spans(text_lower, word_lower, max_hits):
        hits.append((text[max(0, start - before_chars):start], text[start:end], text[end:end + after_chars]))
    return hits


def hits_in_text(text, word, before_chars, after_chars, max_hits=None):
    """Public, single-text entry point (search() below is the whole-Proxy-
    History sweep the History Search tab uses; this is the same matching
    logic against one already-in-hand piece of text, reused by Live Word
    Watch's IHttpListener to test each request/response as it happens).
    Returns [(before, match, after), ...].  When ``max_hits`` is supplied,
    scanning stops as soon as that many matches have been found rather than
    constructing a full result list and truncating it afterwards."""
    return _hits_in_text(text, (word or "").lower(), before_chars, after_chars, max_hits)


def search(callbacks, helpers, word, before_chars, after_chars,
           start_packet_no=None, end_packet_no=None):
    """Returns a list of hit dicts, one per occurrence, in Proxy history
    order (request occurrences before response occurrences within the
    same packet). Each dict: {"packet_no", "side", "before", "match",
    "after", "request_bytes", "response_bytes", "http_service"} -- `side`
    is "Request" or "Response"; the byte fields are a snapshot of that
    packet at search time, kept so a result row can still be previewed
    even if Proxy history changes afterwards.  ``start_packet_no`` and
    ``end_packet_no`` are inclusive 1-based Proxy History positions; an
    omitted boundary leaves that end of the history unbounded."""
    word_lower = (word or "").lower()
    results = []
    if not word_lower:
        return results
    packet_no = 0
    for item in callbacks.getProxyHistory():
        packet_no += 1
        if start_packet_no is not None and packet_no < start_packet_no:
            continue
        if end_packet_no is not None and packet_no > end_packet_no:
            break
        request_bytes = item.getRequest()
        response_bytes = item.getResponse()
        http_service = item.getHttpService()
        request_text = helpers.bytesToString(request_bytes) if request_bytes is not None else ""
        response_text = helpers.bytesToString(response_bytes) if response_bytes is not None else ""
        for side, text in (("Request", request_text), ("Response", response_text)):
            for before, match, after in _hits_in_text(text, word_lower, before_chars, after_chars):
                results.append({
                    "packet_no": packet_no, "side": side, "before": before, "match": match, "after": after,
                    "request_bytes": request_bytes, "response_bytes": response_bytes,
                    "http_service": http_service,
                })
    return results
