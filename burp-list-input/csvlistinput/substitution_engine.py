# -*- coding: utf-8 -*-
"""Applies a set of Edit objects to a request byte-string, via descending-
offset splicing, plus a synthetic Content-Length-patch edit derived from
the body-region delta. Deliberately does NOT use helpers.buildHttpMessage()
for the header block, to avoid Burp silently renormalizing header
order/formatting when only a handful of bytes actually need to change.
"""

from csvlistinput.models import Edit
from csvlistinput.utils import find_content_length_span


def is_ancestor_path(ancestor_path, descendant_path):
    """True if descendant_path is a nested insertion point found *inside*
    ancestor_path's leaf value (i.e. they occupy overlapping byte ranges
    on any buffer they're both detected against), per the {json}/{xml}
    nesting-marker path convention used by json_offset_parser/xml_offset_scanner."""
    if ancestor_path == descendant_path:
        return False
    if not descendant_path.startswith(ancestor_path):
        return False
    return descendant_path[len(ancestor_path):].startswith('{')


def find_overlap_conflicts(edits):
    """Given a list of Edit (each carrying .path), return the subset whose
    byte ranges overlap another edit's range -- these can't both be
    applied. Uses byte-range overlap directly (authoritative), not just
    the path-prefix heuristic (which is what the UI uses ahead of time,
    since at UI-design time no live buffer/offsets exist yet)."""
    by_start = sorted(edits, key=lambda e: (e.start, e.end))
    conflicts = []
    last_end = None
    for e in by_start:
        if last_end is not None and e.start < last_end:
            conflicts.append(e)
        else:
            last_end = e.end
    return conflicts


def substitute(buf, edits, body_offset=None):
    """Apply `edits` (list[Edit], offsets absolute into `buf`) to `buf`.

    If body_offset is given and any accepted edit touches the body region
    (start >= body_offset), a Content-Length header value patch is added
    automatically (only if such a header exists and parses as an integer).

    Returns (new_buf, applied_edits, skipped_edits) where skipped_edits
    were dropped due to a byte-range overlap with another edit (deeper/
    later-sorted one loses; the UI's ancestor/descendant mapping lock is
    the primary defense, this is just a runtime safety net).
    """
    by_start = sorted(edits, key=lambda e: (e.start, e.end))
    accepted = []
    skipped = []
    last_end = None
    for e in by_start:
        if last_end is not None and e.start < last_end:
            skipped.append(e)
            continue
        accepted.append(e)
        last_end = e.end

    all_edits = list(accepted)

    if body_offset is not None:
        body_touched = any(e.start >= body_offset for e in accepted)
        if body_touched:
            cl_start, cl_end = find_content_length_span(buf, body_offset)
            if cl_start is not None:
                try:
                    old_cl = int(buf[cl_start:cl_end])
                except ValueError:
                    old_cl = None
                if old_cl is not None:
                    delta = sum(len(e.replacement) - (e.end - e.start)
                                for e in accepted if e.start >= body_offset)
                    new_cl = old_cl + delta
                    if new_cl >= 0:
                        all_edits.append(Edit(cl_start, cl_end, str(new_cl), path='__content_length__'))

    all_edits.sort(key=lambda e: e.start, reverse=True)
    new_buf = buf
    for e in all_edits:
        new_buf = new_buf[:e.start] + e.replacement + new_buf[e.end:]

    return new_buf, accepted, skipped
