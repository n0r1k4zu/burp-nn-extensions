# -*- coding: utf-8 -*-
"""Searches the Proxy history's raw request/response bytes for a literal
word (case-insensitive, non-overlapping occurrences) and returns each hit
together with a caller-specified window of surrounding text. Kept
separate from the History Search tab's Swing code
(ui/word_search_panel.py) -- this module only decides what to search,
not how it's presented.
"""


def _find_all_spans(haystack_lower, needle_lower):
    """Returns [(start, end), ...] for every non-overlapping occurrence of
    needle_lower in haystack_lower, scanning left to right."""
    spans = []
    if not needle_lower:
        return spans
    start = 0
    while True:
        idx = haystack_lower.find(needle_lower, start)
        if idx < 0:
            break
        end = idx + len(needle_lower)
        spans.append((idx, end))
        start = end
    return spans


def _hits_in_text(text, word_lower, before_chars, after_chars):
    if not text:
        return []
    text_lower = text.lower()
    hits = []
    for start, end in _find_all_spans(text_lower, word_lower):
        hits.append((text[max(0, start - before_chars):start], text[start:end], text[end:end + after_chars]))
    return hits


def search(callbacks, helpers, word, before_chars, after_chars):
    """Returns a list of hit dicts, one per occurrence, in Proxy history
    order (request occurrences before response occurrences within the
    same packet). Each dict: {"packet_no", "before", "match", "after",
    "request_bytes", "response_bytes", "http_service"} -- the byte fields
    are a snapshot of that packet at search time, kept so a result row can
    still be previewed even if Proxy history changes afterwards."""
    word_lower = (word or "").lower()
    results = []
    if not word_lower:
        return results
    packet_no = 0
    for item in callbacks.getProxyHistory():
        packet_no += 1
        request_bytes = item.getRequest()
        response_bytes = item.getResponse()
        http_service = item.getHttpService()
        request_text = helpers.bytesToString(request_bytes) if request_bytes is not None else ""
        response_text = helpers.bytesToString(response_bytes) if response_bytes is not None else ""
        for before, match, after in _hits_in_text(request_text, word_lower, before_chars, after_chars):
            results.append({
                "packet_no": packet_no, "before": before, "match": match, "after": after,
                "request_bytes": request_bytes, "response_bytes": response_bytes,
                "http_service": http_service,
            })
        for before, match, after in _hits_in_text(response_text, word_lower, before_chars, after_chars):
            results.append({
                "packet_no": packet_no, "before": before, "match": match, "after": after,
                "request_bytes": request_bytes, "response_bytes": response_bytes,
                "http_service": http_service,
            })
    return results
