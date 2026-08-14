# -*- coding: utf-8 -*-
"""In-memory Comment Snapshot history."""

import threading
import time


class CommentSnapshotEntry(object):
    def __init__(self):
        self.seq_id = None
        self.timestamp = None
        self.comment = ''
        self.comments = {}
        self.total = 0
        self.nonempty_count = 0


class CommentSnapshotStore(object):
    def __init__(self, max_entries=200):
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.entries = []
        self._next_seq = 1
        self._listeners = []
        self._remove_listeners = []

    def add_listener(self, fn):
        with self._lock:
            self._listeners.append(fn)

    def add_remove_listener(self, fn):
        with self._lock:
            self._remove_listeners.append(fn)

    def append(self, comment, comments, total, nonempty_count):
        entry = CommentSnapshotEntry()
        entry.comment = comment or ''
        entry.comments = comments
        entry.total = total
        entry.nonempty_count = nonempty_count
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
