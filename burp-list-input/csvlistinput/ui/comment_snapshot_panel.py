# -*- coding: utf-8 -*-
"""Backup and restore Proxy History Comment fields."""

import time

from java.awt import BorderLayout, FlowLayout
from java.lang import Integer
from javax.swing import (JButton, JLabel, JOptionPane, JPanel, JScrollPane, JTable, JTextField,
                          ListSelectionModel, SwingUtilities)
from javax.swing.table import AbstractTableModel, TableRowSorter

from csvlistinput import comment_snapshot_engine

COLUMNS = ['#', 'Time', 'Snapshot note', 'Comments / Total']


class _Model(AbstractTableModel):
    def __init__(self, store):
        AbstractTableModel.__init__(self); self.store = store; self.rows = []
    def refresh(self): self.rows = self.store.get_all(); self.fireTableDataChanged()
    def getRowCount(self): return len(self.rows)
    def getColumnCount(self): return len(COLUMNS)
    def getColumnName(self, col): return COLUMNS[col]
    def getColumnClass(self, col): return Integer if col == 0 else str
    def entry_at(self, row): return self.rows[row] if 0 <= row < len(self.rows) else None
    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0: return Integer(entry.seq_id)
        if col == 1: return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.timestamp)) if entry.timestamp else ''
        if col == 2: return entry.comment or ''
        return '%d / %d' % (entry.nonempty_count, entry.total)


class CommentSnapshotPanel(JPanel):
    def __init__(self, callbacks, helpers, store, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks, self.helpers, self.store = callbacks, helpers, store
        self.log_fn, self.error_fn = log_fn, error_fn
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel('Snapshot note (optional):'))
        self.note_field = JTextField(24); top.add(self.note_field)
        top.add(JButton('Take snapshot', actionPerformed=self._on_take))
        self.restore_button = JButton('Restore selected', actionPerformed=self._on_restore); top.add(self.restore_button)
        self.delete_button = JButton('Delete selected', actionPerformed=self._on_delete); top.add(self.delete_button)
        self.add(top, BorderLayout.NORTH)
        self.model = _Model(store)
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.add(JScrollPane(self.table), BorderLayout.CENTER)
        self.status = JLabel('Take a snapshot to back up every Proxy History Comment, then restore it later.')
        self.add(self.status, BorderLayout.SOUTH)
        store.add_listener(lambda entry: SwingUtilities.invokeLater(self.model.refresh))
        store.add_remove_listener(lambda: SwingUtilities.invokeLater(self.model.refresh))

    def _selected(self):
        row = self.table.getSelectedRow()
        if row < 0: return None
        return self.model.entry_at(self.table.convertRowIndexToModel(row))

    def _on_take(self, event):
        try:
            comments, total, nonempty = comment_snapshot_engine.take_snapshot(self.callbacks, self.helpers)
            entry = self.store.append(self.note_field.getText(), comments, total, nonempty)
            self.note_field.setText('')
            self.status.setText('Snapshot #%d taken: %d of %d packet comments are non-empty.' % (entry.seq_id, nonempty, total))
        except Exception as error:
            self.status.setText('Snapshot failed: %s' % error)
            if self.error_fn: self.error_fn('Comment Snapshots', str(error))

    def _on_restore(self, event):
        entry = self._selected()
        if entry is None:
            self.status.setText('Select a snapshot first.'); return
        ret = JOptionPane.showConfirmDialog(self, 'Restore Comments from snapshot #%d? Existing comments will be overwritten.' % entry.seq_id,
                                            'Restore Comment Snapshot', JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
        if ret != JOptionPane.YES_OPTION: return
        try:
            restored, skipped = comment_snapshot_engine.restore_snapshot(self.callbacks, self.helpers, entry.comments)
            self.status.setText('Snapshot #%d restored: %d updated, %d skipped.' % (entry.seq_id, restored, skipped))
        except Exception as error:
            self.status.setText('Restore failed: %s' % error)
            if self.error_fn: self.error_fn('Comment Snapshots', str(error))

    def _on_delete(self, event):
        entry = self._selected()
        if entry is None: self.status.setText('Select a snapshot first.'); return
        self.store.remove(entry); self.status.setText('Snapshot #%d deleted.' % entry.seq_id)
