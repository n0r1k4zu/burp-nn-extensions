# -*- coding: utf-8 -*-
"""Bounded, thread-safe store of extension-internal errors -- the "Errors"
tab's backing store. Distinct from log_store.py's send-history log: this
is specifically for exceptions/failures raised anywhere in this
extension's own code (substitution stages, arming, re-detect, context
menu actions), surfaced in the extension's own UI so they're impossible
to miss instead of being buried in Burp's separate Extender > Extensions
> Errors console (which nothing in this extension's own tabs points at).
"""

import threading
import time


class ErrorEntry(object):
    def __init__(self):
        self.seq_id = None
        self.timestamp = None
        self.source = None    # short label: which part of the extension failed
        self.message = None   # one-line summary (str(exception))
        self.detail = None    # optional longer text (e.g. a traceback)


class ErrorStore(object):
    def __init__(self, max_entries=500):
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.entries = []
        self._next_seq = 1
        self._listeners = []
        self._clear_listeners = []

    def add_listener(self, fn):
        """fn(entry) is called when a new error is appended."""
        with self._lock:
            self._listeners.append(fn)

    def add_clear_listener(self, fn):
        """fn() (no args) is called after clear() empties the store."""
        with self._lock:
            self._clear_listeners.append(fn)

    def append(self, source, message, detail=None, timestamp=None):
        entry = ErrorEntry()
        entry.timestamp = timestamp if timestamp is not None else time.time()
        entry.source = source
        entry.message = message
        entry.detail = detail
        with self._lock:
            entry.seq_id = self._next_seq
            self._next_seq += 1
            self.entries.append(entry)
            if len(self.entries) > self.max_entries:
                self.entries.pop(0)
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(entry)
            except Exception:
                pass
        return entry

    def get_all(self):
        with self._lock:
            return list(self.entries)

    def count(self):
        with self._lock:
            return len(self.entries)

    def clear(self):
        with self._lock:
            self.entries = []
            listeners = list(self._clear_listeners)
        for fn in listeners:
            try:
                fn()
            except Exception:
                pass
