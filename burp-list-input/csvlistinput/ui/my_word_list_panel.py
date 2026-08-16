# -*- coding: utf-8 -*-
"""Editable My Word List tab."""

import codecs
import csv

from java.awt import BorderLayout, FlowLayout
from java.lang import Boolean
from javax.swing import JButton, JComboBox, JFileChooser, JLabel, JPanel, JScrollPane, JTable
from javax.swing.table import AbstractTableModel
from csvlistinput.my_word_list_store import is_regex_enabled


class _WordListModel(AbstractTableModel):
    COLUMNS = ['List No', 'Regex', 'Word', 'Comment']

    def __init__(self, store):
        AbstractTableModel.__init__(self)
        self.store = store
        self.rows = []
        self.reload()

    def reload(self):
        self.rows = self.store.snapshot()
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        if col == 0:
            return row + 1
        if col == 1:
            return self.rows[row].get('is_regex', False)
        return self.rows[row]['word' if col == 2 else 'comment']

    def getColumnClass(self, col):
        return Boolean if col == 1 else str

    def isCellEditable(self, row, col):
        return col in (1, 2, 3)

    def setValueAt(self, value, row, col):
        if col == 1:
            self.rows[row]['is_regex'] = is_regex_enabled(value)
        elif col in (2, 3):
            self.rows[row]['word' if col == 2 else 'comment'] = value
        if col in (1, 2, 3):
            self.fireTableCellUpdated(row, col)

    def add_row(self):
        self.rows.append({'word': u'', 'is_regex': False, 'comment': u''})
        self.fireTableRowsInserted(len(self.rows) - 1, len(self.rows) - 1)

    def remove_rows(self, rows):
        for row in sorted(rows, reverse=True):
            if 0 <= row < len(self.rows):
                del self.rows[row]
        self.fireTableDataChanged()

    def clear(self):
        self.rows = []
        self.fireTableDataChanged()

    def apply(self):
        self.store.replace(self.rows)
        self.reload()


class MyWordListPanel(JPanel):
    def __init__(self, store, log_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.store = store
        self.log_fn = log_fn
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        self.load_button = JButton('Load CSV...', actionPerformed=self._on_load)
        top.add(self.load_button)
        top.add(JLabel('Encoding:'))
        self.encoding_combo = JComboBox(['utf-8', 'shift_jis', 'cp932', 'utf-8-sig'])
        top.add(self.encoding_combo)
        self.export_button = JButton('Export CSV...', actionPerformed=self._on_export)
        top.add(self.export_button)
        top.add(JButton('Add row', actionPerformed=self._on_add))
        top.add(JButton('Delete selected row(s)', actionPerformed=self._on_delete))
        top.add(JButton('Delete all', actionPerformed=self._on_delete_all))
        self.apply_button = JButton('Apply changes', actionPerformed=self._on_apply)
        top.add(self.apply_button)
        self.status_label = JLabel('0 word(s) loaded')
        top.add(self.status_label)
        self.add(top, BorderLayout.NORTH)
        self.model = _WordListModel(store)
        self.table = JTable(self.model)
        self.add(JScrollPane(self.table), BorderLayout.CENTER)
        self._update_status()

    def _on_load(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        try:
            count = self.store.load(chooser.getSelectedFile().getAbsolutePath(), str(self.encoding_combo.getSelectedItem()))
            self.model.reload()
            self.status_label.setText('Loaded %d word(s). Click Apply changes after editing.' % count)
            if self.log_fn:
                self.log_fn('My Word List: loaded %d word(s)' % count)
        except Exception as e:
            self.status_label.setText('CSV load failed: %s' % e)

    def refresh_from_store(self):
        """Discard any stale table draft after Backup & Restore replaces the
        underlying list, so the visible list and Grep source stay identical."""
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        self.model.reload()
        self._update_status('Restored')

    def _on_add(self, event):
        self.model.add_row()
        row = self.model.getRowCount() - 1
        self.table.setRowSelectionInterval(row, row)
        self.table.editCellAt(row, 2)

    def _on_export(self, event):
        """Export the visible list, including pending edits, as Word,Regex,Comment.

        Export deliberately does not require Apply changes: it is useful for
        saving a draft before making it the active Grep list.
        """
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        chooser = JFileChooser()
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        encoding = str(self.encoding_combo.getSelectedItem())
        file_encoding = 'utf-8' if encoding == 'utf-8-sig' else encoding
        try:
            try:
                unicode
                is_jython = True
            except NameError:
                is_jython = False
            handle = (open(path, 'wb') if is_jython else
                      open(path, 'w', newline='', encoding=encoding))
            try:
                if encoding == 'utf-8-sig' and is_jython:
                    handle.write(codecs.BOM_UTF8)
                writer = csv.writer(handle)
                writer.writerow(['Word', 'Regex', 'Comment'])
                for row in self.model.rows:
                    writer.writerow([self._csv_bytes(row['word'], file_encoding),
                                     '1' if row.get('is_regex', False) else '0',
                                     self._csv_bytes(row['comment'], file_encoding)])
            finally:
                handle.close()
            self.status_label.setText('Exported %d word(s) to CSV.' % self.model.getRowCount())
            if self.log_fn:
                self.log_fn('My Word List: exported %d word(s) to %s' % (self.model.getRowCount(), path))
        except Exception as e:
            self.status_label.setText('CSV export failed: %s' % e)

    def _csv_bytes(self, value, encoding):
        try:
            if isinstance(value, unicode):
                return value.encode(encoding)
            return str(value)
        except NameError:  # CPython compatibility for regression checks
            return str(value)

    def _on_delete(self, event):
        self.model.remove_rows([self.table.convertRowIndexToModel(r) for r in self.table.getSelectedRows()])
        self._update_status('Changes are pending. Click Apply changes.')

    def _on_delete_all(self, event):
        self.model.clear()
        self._update_status('Changes are pending. Click Apply changes.')

    def _on_apply(self, event):
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()
        self.model.apply()
        self._update_status('Applied')
        if self.log_fn:
            self.log_fn('My Word List: applied %d word(s)' % self.model.getRowCount())

    def _update_status(self, prefix=None):
        text = '%d word(s) in the current list' % self.model.getRowCount()
        self.status_label.setText((prefix + ' ' if prefix else '') + text)
