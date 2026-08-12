# -*- coding: utf-8 -*-
"""Before/after string-replacement rule lists for Match & Replace.
Two independent instances exist (request-side, response-side) -- see
csv_list_input.py. Loading a CSV appends to the existing list rather than
replacing it, so manually-added rules and CSV-imported rules coexist.
"""

import csv
import threading

from csvlistinput.utils import Utf8CsvRecoder, csv_cell_to_unicode


class ReplaceRule(object):
    def __init__(self, before=u"", after=u"", enabled=True, is_regex=False):
        self.before = before
        self.after = after
        self.enabled = enabled
        self.is_regex = is_regex


_FIELDS = ("enabled", "is_regex", "before", "after")


class ReplaceRuleStore(object):
    def __init__(self):
        self._lock = threading.Lock()
        self.rules = []  # list[ReplaceRule]

    def add_rule(self, before=u"", after=u"", enabled=True, is_regex=False):
        with self._lock:
            self.rules.append(ReplaceRule(before, after, enabled, is_regex))

    def remove_rule(self, index):
        with self._lock:
            if 0 <= index < len(self.rules):
                del self.rules[index]

    def get_rule(self, index):
        with self._lock:
            if 0 <= index < len(self.rules):
                return self.rules[index]
            return None

    def set_field(self, index, field, value):
        """Table cell edit -> mutate the rule in place (same "no
        disconnected copy" discipline as CsvPayloadStore.set_cell /
        CsvTableModel -- edits take effect on the next processed message,
        not just in the display)."""
        if field not in _FIELDS:
            return
        with self._lock:
            if 0 <= index < len(self.rules):
                setattr(self.rules[index], field, value)

    def enabled_rules(self):
        with self._lock:
            return [r for r in self.rules if r.enabled]

    def load_csv(self, file_path, encoding='utf-8'):
        """Expected format: header row `Before, After`. Appends loaded
        rows to the existing rule list as new enabled=True, is_regex=False
        rules rather than replacing what's already there."""
        f = open(file_path, 'rb')
        try:
            reader = csv.reader(Utf8CsvRecoder(f, encoding))
            try:
                headers = next(reader)
            except StopIteration:
                headers = []
            if len(headers) < 2:
                raise ValueError(
                    "CSV must have a header row with at least 2 columns (Before, After) -- "
                    "found %d" % len(headers))
            loaded = 0
            for raw_row in reader:
                if len(raw_row) < 2:
                    continue
                before = csv_cell_to_unicode(raw_row[0])
                after = csv_cell_to_unicode(raw_row[1])
                self.add_rule(before, after, enabled=True, is_regex=False)
                loaded += 1
            return loaded
        finally:
            f.close()
