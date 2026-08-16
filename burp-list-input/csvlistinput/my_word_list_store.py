# -*- coding: utf-8 -*-
"""Thread-safe editable word list used by My Word List Grep."""

import csv
import threading

from csvlistinput.utils import Utf8CsvRecoder, csv_cell_to_unicode, coerce_boolean

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


def is_regex_enabled(value):
    """Normalize Python and Java Swing Boolean values.

    ``bool(java.lang.Boolean(False))`` is True in Jython because it tests
    object existence, not its boolean value.  Read the actual value instead.
    """
    return coerce_boolean(value)


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
                normalized.append({'word': word, 'is_regex': is_regex_enabled(row.get('is_regex', False)),
                                   'comment': _ui_text(row.get('comment', u''))})
        with self._lock:
            self._rows = normalized

    def load(self, file_path, encoding='utf-8'):
        rows = []
        f = open(file_path, 'rb')
        try:
            reader = csv.reader(Utf8CsvRecoder(f, encoding))
            first = True
            regex_column = None
            comment_column = 1
            for raw_row in reader:
                values = [csv_cell_to_unicode(v) for v in raw_row]
                if first:
                    first = False
                    # A conventional header is optional; accepting both makes
                    # small one-column word lists convenient to use.
                    first_cell = values[0].strip().lower() if values else u''
                    if first_cell in (u'word', u'words', u'ワード'):
                        headers = [value.strip().lower() for value in values]
                        regex_column = headers.index(u'regex') if u'regex' in headers else None
                        comment_column = headers.index(u'comment') if u'comment' in headers else (2 if regex_column == 1 else 1)
                        continue
                if not values or not values[0].strip():
                    continue
                is_regex = (regex_column is not None and regex_column < len(values)
                            and values[regex_column].strip().lower() in (u'1', u'true', u'yes', u'on'))
                comment = values[comment_column] if comment_column < len(values) else u''
                rows.append({'word': values[0].strip(), 'is_regex': is_regex, 'comment': comment})
        finally:
            f.close()
        self.replace(rows)
        return len(rows)
