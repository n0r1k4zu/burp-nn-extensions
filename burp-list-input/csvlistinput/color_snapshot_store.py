# -*- coding: utf-8 -*-
"""Thread-safe, in-memory history of packet-highlight-color snapshots
(see color_snapshot_engine.py for what actually gets read/written against
Burp). UI-agnostic like log_store.py / error_store.py: the Color
Snapshots panel subscribes via add_listener()/add_remove_listener() and
marshals onto the Swing EDT itself.

Kept in memory only -- like the rest of this extension's session state
(CSV pointer, Match & Replace rules, etc.), snapshots are lost when the
extension is reloaded/unloaded.
"""

import threading
import time


class ColorSnapshotEntry(object):
    def __init__(self):
        self.seq_id = None
        self.timestamp = None
        self.comment = ""
        self.colors = {}   # identity -> highlight color string, or None (no highlight)
        self.total = 0
        self.colored_count = 0


class ColorSnapshotStore(object):
    def __init__(self, max_entries=200):
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.entries = []  # newest first
        self._next_seq = 1
        self._listeners = []
        self._remove_listeners = []

    def add_listener(self, fn):
        """fn(entry) is called when a new snapshot is appended."""
        with self._lock:
            self._listeners.append(fn)

    def add_remove_listener(self, fn):
        """fn() (no args) is called after a snapshot is removed."""
        with self._lock:
            self._remove_listeners.append(fn)

    def append(self, comment, colors, total, colored_count):
        entry = ColorSnapshotEntry()
        entry.comment = comment or ""
        entry.colors = colors
        entry.total = total
        entry.colored_count = colored_count
        with self._lock:
            entry.timestamp = time.time()
            entry.seq_id = self._next_seq
            self._next_seq += 1
            self.entries.insert(0, entry)
            if len(self.entries) > self.max_entries:
                self.entries.pop()
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

    def remove(self, entry):
        with self._lock:
            try:
                self.entries.remove(entry)
            except ValueError:
                return False
            listeners = list(self._remove_listeners)
        for fn in listeners:
            try:
                fn()
            except Exception:
                pass
        return True

    def replace_entries(self, entries):
        """Replace the saved snapshot catalogue (used by settings restore)."""
        with self._lock:
            self.entries = list(entries)[:self.max_entries]
            self._next_seq = max([getattr(entry, 'seq_id', 0) or 0 for entry in self.entries] + [0]) + 1
            listeners = list(self._remove_listeners)
        for fn in listeners:
            try:
                fn()
            except Exception:
                pass
