# -*- coding: utf-8 -*-
"""Searches the Proxy history's raw request/response bytes for a literal
word (case-insensitive, non-overlapping occurrences) and returns each hit
together with a caller-specified window of surrounding text. Kept
separate from the History Search tab's Swing code
(ui/word_search_panel.py) -- this module only decides what to search,
not how it's presented.
"""

from csvlistinput.utils import bytes_to_bytestring, from_bytestring_space, to_bytestring_space
from csvlistinput.statistics_engine import group_display

try:
    _JYTHON_UNICODE = unicode
except NameError:  # CPython test runtime
    _JYTHON_UNICODE = None


def terms_for_byte_text(terms):
    """Convert Swing/CSV Unicode terms into Burp's byte-string space.

    Jython otherwise compares a Unicode search term to a raw HTTP ``str``
    by implicitly ASCII-decoding the packet, which fails for UTF-8 bytes.
    CPython tests intentionally keep native text strings unchanged.
    """
    if _JYTHON_UNICODE is None:
        return terms
    return [to_bytestring_space(term) for term in terms]


def display_text(byte_text):
    """Convert byte-string result slices for Swing only (Jython runtime)."""
    return from_bytestring_space(byte_text) if _JYTHON_UNICODE is not None else byte_text


def message_text(helpers, raw_bytes):
    """Return Burp byte-string text, while retaining CPython test support."""
    if _JYTHON_UNICODE is None:
        return helpers.bytesToString(raw_bytes)
    return bytes_to_bytestring(helpers, raw_bytes)


def parse_search_query(query):
    """Parse a literal-word query into ``(terms, operator)``.

    ``&`` requires every term and ``|`` accepts any term.  Only one operator
    kind is allowed per query so there is no surprising implicit precedence.
    Escape ``&``, ``|`` and ``\\`` with a backslash when they are literal
    search characters (for example ``error\\|warning`` searches for the
    literal text ``error|warning``).  The Japanese yen sign (``¥``), which
    is commonly entered from a Japanese Mac keyboard, is accepted as the
    same escape prefix.
    """
    terms = []
    chars = []
    operator = None
    escaped = False
    escape_prefix = None
    # All grammar tokens are Unicode.  In particular, a Japanese Mac's
    # ``¥`` escape prefix is UTF-8 (c2 a5); comparing it against a Python
    # 2/Jython byte literal would trigger an implicit ASCII decode before
    # the search even starts.
    for char in query or u"":
        if escaped:
            if char in u"&|\\¥":
                chars.append(char)
            else:
                chars.append(escape_prefix)
                chars.append(char)
            escaped = False
            escape_prefix = None
            continue
        if char in u"\\¥":
            escaped = True
            escape_prefix = char
        elif char in u"&|":
            term = u"".join(chars).strip()
            if not term:
                raise ValueError("Each search term must be non-empty.")
            if operator is not None and operator != char:
                raise ValueError("Do not mix '&' and '|'; run separate searches instead.")
            terms.append(term)
            chars = []
            operator = char
        else:
            chars.append(char)
    if escaped:
        chars.append(escape_prefix)
    term = u"".join(chars).strip()
    if not term:
        raise ValueError("Each search term must be non-empty.")
    terms.append(term)

    # Repeating a term cannot change AND/OR semantics, and avoiding duplicate
    # terms prevents duplicate result rows for queries such as ``foo | foo``.
    unique_terms = []
    seen = set()
    for term in terms:
        lowered = term.lower()
        if lowered not in seen:
            seen.add(lowered)
            unique_terms.append(term)
    return unique_terms, operator


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
    terms, operator = parse_search_query(word)
    terms = terms_for_byte_text(terms)
    return hits_in_text_for_terms(text, terms, operator, before_chars, after_chars, max_hits)


def hits_in_text_for_terms(text, terms, operator, before_chars, after_chars, max_hits=None):
    """Return hits in one message for a parsed query.

    For an AND query every term must be present in this text.  History Search
    uses ``hits_in_packet_for_terms`` below instead, allowing its AND terms to
    be split between a request and its response in the same Packet No.
    """
    text_lower = (text or "").lower()
    term_hits = []
    all_terms_found = True
    for term_index, term in enumerate(terms):
        # The live watcher supplies a cap.  Bound each term's span list as
        # well, otherwise a common first term can still allocate millions of
        # spans before the combined result list is truncated.
        spans = _find_all_spans(text_lower, term.lower(), max_hits)
        if not spans:
            all_terms_found = False
            continue
        for start, end in spans:
            term_hits.append((start, term_index,
                              (text[max(0, start - before_chars):start], text[start:end],
                               text[end:end + after_chars])))
    if operator == '&' and not all_terms_found:
        return []
    term_hits.sort(key=lambda item: (item[0], item[1]))
    hits = [item[2] for item in term_hits]
    return hits[:max_hits] if max_hits is not None else hits


def hits_in_packet_for_terms(request_text, response_text, terms, operator,
                             before_chars, after_chars, max_hits=None):
    """Return ``[(side, before, match, after), ...]`` for one transaction.

    An AND expression qualifies when every term appears somewhere in the
    request/response pair represented by the same Packet No.  Results include
    all matching terms so the user can inspect why the packet qualified.
    """
    sides = (("Request", request_text or ""), ("Response", response_text or ""))
    packet_lower = "\n".join(text.lower() for _side, text in sides)
    present = [term.lower() in packet_lower for term in terms]
    if operator == '&' and not all(present):
        return []
    if operator == '|' and not any(present):
        return []

    results = []
    for side, text in sides:
        for before, match, after in hits_in_text_for_terms(
                text, terms, '|', before_chars, after_chars, max_hits):
            results.append((side, before, match, after))
    return results[:max_hits] if max_hits is not None else results


def search(callbacks, helpers, word, before_chars, after_chars,
           start_packet_no=None, end_packet_no=None, cancel_check=None):
    """Returns a list of hit dicts, one per occurrence, in Proxy history
    order (request occurrences before response occurrences within the
    same packet). Each dict: {"packet_no", "side", "before", "match",
    "after", "request_bytes", "response_bytes", "http_service"} -- `side`
    is "Request" or "Response"; the byte fields are a snapshot of that
    packet at search time, kept so a result row can still be previewed
    even if Proxy history changes afterwards.  ``start_packet_no`` and
    ``end_packet_no`` are inclusive 1-based Proxy History positions; an
    omitted boundary leaves that end of the history unbounded."""
    results = []
    terms, operator = parse_search_query(word)
    terms = terms_for_byte_text(terms)
    packet_no = 0
    for item in callbacks.getProxyHistory():
        packet_no += 1
        if cancel_check and cancel_check():
            break
        if start_packet_no is not None and packet_no < start_packet_no:
            continue
        if end_packet_no is not None and packet_no > end_packet_no:
            break
        request_bytes = item.getRequest()
        response_bytes = item.getResponse()
        http_service = item.getHttpService()
        group = group_display(item.getComment() if hasattr(item, 'getComment') else u'')
        request_text = message_text(helpers, request_bytes) if request_bytes is not None else ""
        response_text = message_text(helpers, response_bytes) if response_bytes is not None else ""
        for side, before, match, after in hits_in_packet_for_terms(
                request_text, response_text, terms, operator, before_chars, after_chars):
            results.append({
                "packet_no": packet_no, "side": side, "before": display_text(before),
                "match": display_text(match), "after": display_text(after),
                "group": group,
                "request_bytes": request_bytes, "response_bytes": response_bytes,
                "http_service": http_service,
            })
    return results
