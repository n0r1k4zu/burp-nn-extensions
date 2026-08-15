# -*- coding: utf-8 -*-
"""Thread-safe, bounded, in-memory list of Live Word Watch hits.
UI-agnostic like log_store.py/error_store.py: the panel subscribes via
add_listener()/add_clear_listener() and is responsible for marshalling
onto the Swing EDT itself (this store is appended to from the
IHttpListener network thread, not the EDT).
"""

import threading
import time


class LiveWordHit(object):
    def __init__(self):
        self.seq_id = None
        self.timestamp = None
        # Lazily resolved and cached the same way as the Log tab's
        # "Packet No" column (see proxy_history_lookup.py) -- None means
        # "not looked up yet", -1 means "looked up, not found there".
        self.packet_no = None
        self.side = None  # "Request" or "Response"
        self.region = "Unknown"
        self.tool_label = None
        self.before = ""
        self.match = ""
        self.after = ""
        self.request_bytes = None
        self.response_bytes = None
        self.http_service = None


class LiveWordWatchStore(object):
    def __init__(self, max_entries=1000):
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.entries = []
        self._next_seq = 1
        self._listeners = []
        self._clear_listeners = []

    def add_listener(self, fn):
        """fn(hit) is called when a new hit is appended."""
        with self._lock:
            self._listeners.append(fn)

    def add_clear_listener(self, fn):
        """fn() (no args) is called after clear() empties the store."""
        with self._lock:
            self._clear_listeners.append(fn)

    def append(self, hit):
        with self._lock:
            hit.timestamp = time.time()
            hit.seq_id = self._next_seq
            self._next_seq += 1
            self.entries.append(hit)
            if len(self.entries) > self.max_entries:
                self.entries.pop(0)
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(hit)
            except Exception:
                pass

    def get_all(self):
        with self._lock:
            return list(self.entries)

    def clear(self):
        with self._lock:
            self.entries = []
            listeners = list(self._clear_listeners)
        for fn in listeners:
            try:
                fn()
            except Exception:
                pass
