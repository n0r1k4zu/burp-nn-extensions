# -*- coding: utf-8 -*-
"""Best-effort reverse lookup: given a specific (http_service,
request_bytes) pair, find its 1-based position within Burp's Proxy
History. Shared by the Log tab and the Live Word Watch tab, which both
show a "Packet No" column using this same concept (see also
word_search_engine.py's search(), which computes packet numbers by
sweeping Proxy History forward instead of looking one up in reverse).
"""


def find_packet_no(callbacks, helpers, http_service, request_bytes):
    """Returns the 1-based position, or -1 if it isn't there at all --
    most commonly because the request only ever went through a non-Proxy
    tool (e.g. Repeater), which doesn't add entries to Proxy History."""
    if http_service is None or request_bytes is None:
        return -1
    try:
        target_text = helpers.bytesToString(request_bytes)
        target_host = http_service.getHost()
        target_port = http_service.getPort()
        target_proto = http_service.getProtocol()
    except Exception:
        return -1
    no = 0
    for item in callbacks.getProxyHistory():
        no += 1
        try:
            svc = item.getHttpService()
            if svc.getHost() != target_host or svc.getPort() != target_port or svc.getProtocol() != target_proto:
                continue
            if helpers.bytesToString(item.getRequest()) != target_text:
                continue
        except Exception:
            continue
        return no
    return -1
