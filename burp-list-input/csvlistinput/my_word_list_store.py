# -*- coding: utf-8 -*-
"""Thread-safe editable word list used by My Word List Grep."""

import csv
import threading

from csvlistinput.utils import Utf8CsvRecoder, csv_cell_to_unicode

try:
    _TEXT_TYPE = unicode
except NameError:  # CPython test runtime
    _TEXT_TYPE = str


def _ui_text(value):
    """Normalize JTable/Jython strings without UTF-8 decoding them again.

    CSV cells enter this module as bytes and are decoded by ``load``.  Table
    edits, however, are already Java/Jython Unicode strings; routing those
    through csv_cell_to_unicode() can empty/fail the applied list on Jython.
    """
    if isinstance(value, _TEXT_TYPE):
        return value
    return _TEXT_TYPE(value)


class MyWordListStore(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._rows = []

    def snapshot(self):
        with self._lock:
            return [dict(row) for row in self._rows]

    def replace(self, rows):
        normalized = []
        for row in rows:
            word = _ui_text(row.get('word', u'')).strip()
            if word:
                normalized.append({'word': word, 'comment': _ui_text(row.get('comment', u''))})
        with self._lock:
            self._rows = normalized

    def load(self, file_path, encoding='utf-8'):
        rows = []
        f = open(file_path, 'rb')
        try:
            reader = csv.reader(Utf8CsvRecoder(f, encoding))
            first = True
            for raw_row in reader:
                values = [csv_cell_to_unicode(v) for v in raw_row]
                if first:
                    first = False
                    # A conventional header is optional; accepting both makes
                    # small one-column word lists convenient to use.
                    first_cell = values[0].strip().lower() if values else u''
                    if first_cell in (u'word', u'words', u'ワード'):
                        continue
                if not values or not values[0].strip():
                    continue
                rows.append({'word': values[0].strip(), 'comment': values[1] if len(values) > 1 else u''})
        finally:
            f.close()
        self.replace(rows)
        return len(rows)
