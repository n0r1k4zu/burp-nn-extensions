# -*- coding: utf-8 -*-
"""CSV load/edit/reset panel (requirements (2) and (5))."""

from java.awt import BorderLayout, FlowLayout
from javax.swing import (JButton, JComboBox, JFileChooser, JLabel, JPanel, JScrollPane, JSpinner, JTable,
                          SpinnerNumberModel)
from javax.swing.table import AbstractTableModel

_EXAMPLE_HEADERS = ['No', 'param1', 'param2', 'param3']
_EXAMPLE_ROWS = [['1', 'a', 'b', 'c'], ['2', 'aa', 'bb', 'cc'], ['3', 'aaa', 'bbb', 'ccc']]


class CsvTableModel(AbstractTableModel):
    """Reads/writes csv_store directly -- unlike a DefaultTableModel
    populated via setDataVector(), there is no separate copy of the data
    to fall out of sync: editing a cell here immediately mutates the same
    rows consume_next_row() reads from."""

    def __init__(self, csv_store):
        AbstractTableModel.__init__(self)
        self.csv_store = csv_store
        self.headers = []
        self.row_count = 0
        self.example_rows = []
        self._show_example = True

    def reload(self):
        headers, rows = self.csv_store.snapshot()
        # Show a concrete, non-active example before a CSV is loaded so its
        # shape is immediately understandable without adding dummy payloads
        # to the actual substitution store.
        self.example_rows = [] if headers or not self._show_example else [list(row) for row in _EXAMPLE_ROWS]
        self.headers = headers or list(_EXAMPLE_HEADERS)
        self.row_count = len(rows) if headers else len(self.example_rows)
        self.fireTableStructureChanged()

    def show_empty(self):
        """Keep the useful headers after Clear list, but no sample rows."""
        self._show_example = False
        self.headers = list(_EXAMPLE_HEADERS)
        self.example_rows = []
        self.row_count = 0
        self.fireTableStructureChanged()

    def getRowCount(self):
        return self.row_count

    def getColumnCount(self):
        return len(self.headers)

    def getColumnName(self, col):
        return self.headers[col] if col < len(self.headers) else ""

    def getValueAt(self, row, col):
        if self.example_rows:
            return self.example_rows[row][col]
        value = self.csv_store.get_cell(row, col)
        return value if value is not None else ""

    def isCellEditable(self, row, col):
        return not self.example_rows

    def setValueAt(self, value, row, col):
        self.csv_store.set_cell(row, col, value)
        self.fireTableCellUpdated(row, col)


class CsvPanel(JPanel):
    def __init__(self, csv_store, on_loaded=None, log_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.csv_store = csv_store
        self.on_loaded = on_loaded
        self.log_fn = log_fn

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        self.load_button = JButton("Load CSV...", actionPerformed=self._on_load)
        self.save_button = JButton("Export CSV...", actionPerformed=self._on_save)
        self.clear_list_button = JButton("Clear list", actionPerformed=self._on_clear_list)
        self.encoding_combo = JComboBox(["utf-8", "shift_jis", "cp932", "utf-8-sig"])
        top.add(self.load_button)
        top.add(self.save_button)
        top.add(self.clear_list_button)
        top.add(JLabel("Encoding:"))
        top.add(self.encoding_combo)

        top.add(JLabel("Start row (1-based):"))
        self.start_row_spinner = JSpinner(SpinnerNumberModel(1, 1, 1000000, 1))
        top.add(self.start_row_spinner)
        self.set_start_button = JButton("Set start row", actionPerformed=self._on_set_start_row)
        top.add(self.set_start_button)

        self.reset_button = JButton("Reset pointer", actionPerformed=self._on_reset)
        top.add(self.reset_button)

        # Retained as an internal action-status sink, but intentionally not
        # placed in the compact toolbar: the sample table is self-explanatory.
        self.status_label = JLabel("")
        self.add(top, BorderLayout.NORTH)

        self.table_model = CsvTableModel(csv_store)
        self.table_model.reload()
        self.table = JTable(self.table_model)
        self.add(JScrollPane(self.table), BorderLayout.CENTER)

    def _on_load(self, event):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self)
        if result != JFileChooser.APPROVE_OPTION:
            return
        f = chooser.getSelectedFile()
        encoding = str(self.encoding_combo.getSelectedItem())
        try:
            count, warnings = self.csv_store.load(f.getAbsolutePath(), encoding=encoding)
        except Exception as e:
            self.status_label.setText("Load failed: %s" % e)
            if self.log_fn:
                self.log_fn("CSV load failed: %s" % e)
            return

        # Stop any in-progress cell edit before the table structure changes
        # underneath it, so a half-typed edit doesn't land on the wrong cell.
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        self.table_model.reload()
        self._update_pointer_label()

        msg = "Loaded %d rows, %d columns" % (count, len(self.csv_store.column_names))
        if warnings:
            msg += " (%d rows skipped -- see log)" % len(warnings)
            if self.log_fn:
                for w in warnings:
                    self.log_fn("CSV load warning: %s" % w)
        self.status_label.setText(msg)
        if self.on_loaded:
            self.on_loaded()

    def _on_reset(self, event):
        self.csv_store.reset()
        self._update_pointer_label()

    def _on_save(self, event):
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        chooser = JFileChooser()
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        try:
            self.csv_store.save_csv(chooser.getSelectedFile().getAbsolutePath(),
                                    encoding=str(self.encoding_combo.getSelectedItem()),
                                    default_headers=_EXAMPLE_HEADERS,
                                    default_rows=_EXAMPLE_ROWS if self.table_model.example_rows else None)
            self.status_label.setText('Saved %d row(s) to CSV.' % self.csv_store.row_count())
        except Exception as e:
            self.status_label.setText('Save failed: %s' % e)

    def _on_clear_list(self, event):
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        self.csv_store.clear()
        self.table_model.show_empty()
        self.status_label.setText('List cleared.')
        if self.on_loaded:
            self.on_loaded()

    def _on_set_start_row(self, event):
        try:
            value = int(self.start_row_spinner.getValue())
        except Exception:
            return
        self.csv_store.set_start_row(value)
        self._update_pointer_label()
        if self.log_fn:
            self.log_fn("CSV start row set to %d -- pointer jumped there; "
                        "Reset pointer will return to this row from now on." % value)

    def refresh_pointer_label(self):
        """Called externally (see MainTab) whenever a send may have
        consumed a CSV row, so the "Row N of M" display stays live
        instead of only updating on Load/Reset clicks."""
        self._update_pointer_label()

    def refresh_loaded_csv(self):
        """Refresh headers/rows after Backup & Restore replaces the list."""
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        self.table_model.reload()
        self._update_pointer_label()

    def _update_pointer_label(self):
        pos, total = self.csv_store.pointer_position()
        if not total:
            return
        if pos >= total:
            self.status_label.setText("Exhausted (%d of %d rows used)" % (total, total))
        else:
            # +1: pos is the internal 0-based pointer, displayed to match
            # the 1-based "Start row" numbering used elsewhere in this panel.
            self.status_label.setText("Row %d of %d (next to be consumed)" % (pos + 1, total))
