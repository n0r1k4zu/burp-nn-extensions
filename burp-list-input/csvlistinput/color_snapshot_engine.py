# -*- coding: utf-8 -*-
"""Reads/writes each Proxy history item's setHighlight() color, keyed by
the same (host, port, protocol, request-bytes) identity used elsewhere in
this extension to re-join a live request back to a previously-seen one.
Kept separate from the Color Snapshots tab's Swing code
(ui/color_snapshot_panel.py) -- this module only decides what to read/
write against Burp, not how it's presented.
"""


def _identity(helpers, item):
    req = item.getRequest()
    svc = item.getHttpService()
    req_str = helpers.bytesToString(req) if req is not None else ""
    host = svc.getHost() if svc else ""
    port = svc.getPort() if svc else 0
    proto = svc.getProtocol() if svc else ""
    return (host, port, proto, req_str)


def take_snapshot(callbacks, helpers):
    """Returns (colors, total, colored_count). `colors` maps identity ->
    the item's current highlight color (or None if it has none) for every
    item currently in the Proxy history."""
    colors = {}
    total = 0
    colored_count = 0
    for item in callbacks.getProxyHistory():
        try:
            key = _identity(helpers, item)
        except Exception:
            continue
        color = item.getHighlight()
        colors[key] = color
        total += 1
        if color:
            colored_count += 1
    return colors, total, colored_count


def restore_snapshot(callbacks, helpers, colors):
    """Sets setHighlight() back to the recorded value for every Proxy
    history item whose identity is present in `colors` (including
    explicitly clearing items that had no highlight when snapshotted).
    Items not present in `colors` (added to the history after the
    snapshot was taken) are left untouched. Returns
    (restored_count, skipped_count)."""
    restored = 0
    skipped = 0
    for item in callbacks.getProxyHistory():
        try:
            key = _identity(helpers, item)
        except Exception:
            skipped += 1
            continue
        if key in colors:
            item.setHighlight(colors[key])
            restored += 1
        else:
            skipped += 1
    return restored, skipped
