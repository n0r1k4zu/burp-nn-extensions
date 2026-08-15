# -*- coding: utf-8 -*-
"""CSV payload list loading and thread-safe row-pointer state.

Expected format: header row `No, InsertionPoint1, InsertionPoint2, ...`
(column count is arbitrary/variable). headers[0] is the conventional "No"
label and is not used for substitution -- headers[1:] become the
mappable column names offered in the insertion-point mapping UI.
"""

import csv
import codecs
import threading

from csvlistinput.utils import Utf8CsvRecoder, csv_cell_to_unicode

_DEFAULT_SAMPLE_COLUMN_NAMES = ['param1', 'param2', 'param3']


class CsvLoadWarning(object):
    def __init__(self, row_number, message):
        self.row_number = row_number
        self.message = message

    def __repr__(self):
        return "Row %s: %s" % (self.row_number, self.message)


class CsvPayloadStore(object):
    def __init__(self):
        self._lock = threading.Lock()
        self.file_path = None
        self.headers = []       # full header row, including "No"
        self.column_names = []  # headers[1:] -- the mappable columns
        self.rows = []          # list[list[str]], full rows including the "No" cell
        self.pointer = 0
        self.start_index = 0    # 0-based; where reset() jumps back to (see set_start_row)
        self.load_warnings = []

    def load(self, file_path, encoding='utf-8'):
        with self._lock:
            headers = []
            rows = []
            warnings = []
            f = open(file_path, 'rb')
            try:
                reader = csv.reader(Utf8CsvRecoder(f, encoding))
                try:
                    raw_headers = next(reader)
                except StopIteration:
                    raw_headers = []
                headers = [csv_cell_to_unicode(h) for h in raw_headers]
                if len(headers) < 2:
                    raise ValueError(
                        "CSV must have a header row with at least 2 columns "
                        "(No, InsertionPoint1, ...) -- found %d" % len(headers))
                expected_len = len(headers)
                row_number = 1
                for raw_row in reader:
                    row_number += 1
                    row = [csv_cell_to_unicode(c) for c in raw_row]
                    if len(row) != expected_len:
                        warnings.append(CsvLoadWarning(
                            row_number,
                            "column count %d != header count %d -- row skipped" % (len(row), expected_len)))
                        continue
                    rows.append(row)
            finally:
                f.close()

            self.file_path = file_path
            self.headers = headers
            self.column_names = headers[1:]
            self.rows = rows
            # Respect a previously configured start row (e.g. re-loading the
            # same file after editing it) rather than always jumping to 0.
            self.start_index = max(0, min(self.start_index, len(rows)))
            self.pointer = self.start_index
            self.load_warnings = warnings
            return len(rows), warnings

    def get_column_names(self):
        with self._lock:
            # The un-loaded Target & List Mapping sample is intentionally
            # selectable too, so its param1/param2/param3 columns are visible
            # in the Mapped Column combo before the user imports a real CSV.
            return list(self.column_names or _DEFAULT_SAMPLE_COLUMN_NAMES)

    def row_count(self):
        with self._lock:
            return len(self.rows)

    def pointer_position(self):
        with self._lock:
            return self.pointer, len(self.rows)

    def consume_next_row(self):
        """Read-and-advance under lock. Returns (row_index, no_value,
        {column_name: value}) or (None, None, None) if the list is
        exhausted. `no_value` is the row's own "No" cell (the CSV's own
        row label), distinct from `row_index` (the internal 0-based
        pointer position) -- the Log tab displays `no_value` since that's
        what the user actually put in their CSV."""
        with self._lock:
            if self.pointer >= len(self.rows):
                return None, None, None
            idx = self.pointer
            self.pointer += 1
            row = self.rows[idx]
            no_value = row[0] if row else None
            values = dict(zip(self.column_names, row[1:]))
            return idx, no_value, values

    def reset(self):
        with self._lock:
            self.pointer = self.start_index

    def clear(self):
        with self._lock:
            self.file_path = None
            self.headers = []
            self.column_names = []
            self.rows = []
            self.pointer = 0
            self.start_index = 0
            self.load_warnings = []

    def set_start_row(self, one_based_row):
        """Configure which row Reset jumps back to, and jump the current
        pointer there immediately. `one_based_row` is 1-based (row 1 =
        the first data row after the header), clamped to the available
        row range."""
        with self._lock:
            idx = max(0, one_based_row - 1)
            idx = min(idx, len(self.rows))
            self.start_index = idx
            self.pointer = idx

    def preview_rows(self, limit=20):
        with self._lock:
            return [list(r) for r in self.rows[:limit]]

    def snapshot(self):
        """(headers, rows) copies, for building/refreshing a table view."""
        with self._lock:
            return list(self.headers), [list(r) for r in self.rows]

    def backup_snapshot(self):
        with self._lock:
            return {'headers': list(self.headers), 'rows': [list(r) for r in self.rows],
                    'start_row': self.start_index + 1}

    def restore_snapshot(self, payload):
        headers = list(payload.get('headers', []))
        rows = [list(row) for row in payload.get('rows', [])]
        if headers and len(headers) < 2:
            raise ValueError('Target & List Mapping CSV needs at least No and one value column.')
        for row in rows:
            if len(row) != len(headers):
                raise ValueError('A restored Target & List Mapping CSV row has the wrong number of columns.')
        start_index = max(0, int(payload.get('start_row', 1)) - 1)
        with self._lock:
            self.headers = headers
            self.column_names = headers[1:] if headers else []
            self.rows = rows
            self.start_index = min(start_index, len(rows))
            self.pointer = self.start_index
            self.file_path = None
            self.load_warnings = []

    def save_csv(self, file_path, encoding='utf-8', default_headers=None, default_rows=None):
        """Save the current mapping list. A blank list exports a documented
        example header so users can discover the required CSV format."""
        headers, rows = self.snapshot()
        if not headers:
            headers = list(default_headers or ['No', 'Value1'])
            rows = [list(row) for row in (default_rows or [])]
        actual_encoding = 'utf-8' if encoding == 'utf-8-sig' else encoding
        try:
            unicode
            is_jython = True
        except NameError:
            is_jython = False
        handle = (open(file_path, 'wb') if is_jython else
                  open(file_path, 'w', newline='', encoding=encoding))
        try:
            if encoding == 'utf-8-sig' and is_jython:
                handle.write(codecs.BOM_UTF8)
            writer = csv.writer(handle)
            writer.writerow([self._csv_bytes(value, actual_encoding) for value in headers])
            for row in rows:
                writer.writerow([self._csv_bytes(value, actual_encoding) for value in row])
        finally:
            handle.close()

    def _csv_bytes(self, value, encoding):
        try:
            # Values typed/loaded through Swing are Unicode, while some
            # legacy/Jython table values are already raw bytes.  Calling
            # unicode(raw_bytes) would try ASCII first and fails on bytes
            # such as 0x89; preserve those bytes instead.
            if isinstance(value, unicode):
                return value.encode(encoding)  # Jython/Python 2 csv needs bytes
            return str(value)
        except NameError:  # CPython csv needs text, not bytes
            return str(value)

    def get_cell(self, row_idx, col_idx):
        with self._lock:
            try:
                return self.rows[row_idx][col_idx]
            except IndexError:
                return None

    def set_cell(self, row_idx, col_idx, value):
        """Edit a cell in place -- this directly mutates the data
        consume_next_row() reads from, so table edits actually take
        effect on the next send that uses this row (not just a display
        copy)."""
        with self._lock:
            try:
                self.rows[row_idx][col_idx] = value
            except IndexError:
                pass
