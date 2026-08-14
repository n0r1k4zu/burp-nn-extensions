# -*- coding: utf-8 -*-
"""Read/write Proxy History comments for Comment Snapshots."""


def _identity(helpers, item):
    req = item.getRequest()
    svc = item.getHttpService()
    return (svc.getHost() if svc else '', svc.getPort() if svc else 0,
            svc.getProtocol() if svc else '',
            helpers.bytesToString(req) if req is not None else '')


def take_snapshot(callbacks, helpers):
    """Return (comments, total, nonempty), preserving duplicate requests."""
    comments = {}
    total = nonempty = 0
    for item in callbacks.getProxyHistory():
        try:
            key = _identity(helpers, item)
            value = item.getComment() or ''
            comments.setdefault(key, []).append(value)
            total += 1
            if value:
                nonempty += 1
        except Exception:
            continue
    return comments, total, nonempty


def restore_snapshot(callbacks, helpers, comments):
    """Restore comments for packets present when the snapshot was taken."""
    positions = {}
    restored = skipped = 0
    for item in callbacks.getProxyHistory():
        try:
            key = _identity(helpers, item)
            values = comments.get(key)
            index = positions.get(key, 0)
            if values is None or index >= len(values):
                skipped += 1
                continue
            item.setComment(values[index])
            positions[key] = index + 1
            restored += 1
        except Exception:
            skipped += 1
    return restored, skipped
