# -*- coding: utf-8 -*-
"""Bounded, thread-safe store of LogEntry objects. UI-agnostic: the log
panel subscribes via add_listener() and is responsible for marshalling
onto the Swing EDT itself (via SwingUtilities.invokeLater) when the
listener fires from the network thread.
"""

import threading


class LogStore(object):
    def __init__(self, max_entries=500):
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.entries = []
        self._next_seq = 1
        self._listeners = []
        self._update_listeners = []
        self._clear_listeners = []

    def add_listener(self, fn):
        """fn(entry) is called when a brand-new row is appended."""
        with self._lock:
            self._listeners.append(fn)

    def add_update_listener(self, fn):
        """fn(entry) is called when an existing entry already in the store
        is mutated in place (e.g. the response arrived after the request
        row was already logged) -- no new row, just changed content."""
        with self._lock:
            self._update_listeners.append(fn)

    def add_clear_listener(self, fn):
        """fn() (no args) is called after clear() empties the store."""
        with self._lock:
            self._clear_listeners.append(fn)

    def append(self, entry):
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

    def notify_updated(self, entry):
        """Call after mutating an entry already in the store (it's the
        same object reference held internally, so no re-append needed --
        this just tells subscribers to refresh their view of it)."""
        with self._lock:
            listeners = list(self._update_listeners)
        for fn in listeners:
            try:
                fn(entry)
            except Exception:
                pass

    def get_all(self):
        with self._lock:
            return list(self.entries)

    def get(self, index):
        with self._lock:
            if 0 <= index < len(self.entries):
                return self.entries[index]
            return None

    def clear(self):
        with self._lock:
            self.entries = []
            listeners = list(self._clear_listeners)
        for fn in listeners:
            try:
                fn()
            except Exception:
                pass
