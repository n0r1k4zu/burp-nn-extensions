# -*- coding: utf-8 -*-
"""Color Snapshots tab: backup/restore the Proxy history's packet
highlight colors (Burp's setHighlight()), independent of the CSV/Match &
Replace features -- a checkpoint you can return to after re-coloring
packets by hand or via another tool/extension."""

import time

from java.awt import BorderLayout, FlowLayout
from java.lang import Integer
from javax.swing import (JButton, JLabel, JOptionPane, JPanel, JScrollPane, JTable, JTextField,
                          ListSelectionModel, SwingUtilities)
from javax.swing.table import AbstractTableModel
from javax.swing.table import TableRowSorter

from csvlistinput import color_snapshot_engine
from csvlistinput.ui.sort_helpers import NumericSequenceComparator

COLUMNS = ["#", "Time", "Comment", "Colored / Total"]


class ColorSnapshotTableModel(AbstractTableModel):
    def __init__(self, store):
        AbstractTableModel.__init__(self)
        self.store = store
        self._cache = []

    def refresh(self):
        self._cache = self.store.get_all()
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self._cache)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getColumnClass(self, col):
        return Integer if col == 0 else str

    def entry_at(self, row):
        if 0 <= row < len(self._cache):
            return self._cache[row]
        return None

    def getValueAt(self, row, col):
        e = self._cache[row]
        if col == 0:
            return Integer(e.seq_id) if e.seq_id is not None else None
        if col == 1:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.timestamp)) if e.timestamp else ""
        if col == 2:
            return e.comment or ""
        if col == 3:
            return "%d / %d" % (e.colored_count, e.total)
        return None


class ColorSnapshotPanel(JPanel):
    def __init__(self, callbacks, helpers, color_snapshot_store, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.store = color_snapshot_store
        self.log_fn = log_fn
        self.error_fn = error_fn

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Comment (optional):"))
        self.comment_field = JTextField(24)
        top.add(self.comment_field)
        self.take_button = JButton("Take snapshot", actionPerformed=self._on_take)
        top.add(self.take_button)
        self.restore_button = JButton("Restore selected", actionPerformed=self._on_restore)
        top.add(self.restore_button)
        self.delete_button = JButton("Delete selected", actionPerformed=self._on_delete)
        top.add(self.delete_button)
        self.clear_all_button = JButton("Clear all colors", actionPerformed=self._on_clear_all)
        top.add(self.clear_all_button)
        self.add(top, BorderLayout.NORTH)

        self.table_model = ColorSnapshotTableModel(color_snapshot_store)
        self.table = JTable(self.table_model)
        sorter = TableRowSorter(self.table_model)
        sorter.setComparator(3, NumericSequenceComparator())
        self.table.setRowSorter(sorter)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.add(JScrollPane(self.table), BorderLayout.CENTER)

        self.status_label = JLabel(
            "Take snapshot records every Proxy history packet's current highlight color "
            "(including packets with no color); Restore selected overwrites them back to that state; "
            "Clear all colors resets every packet to no color.")
        self.add(self.status_label, BorderLayout.SOUTH)

        color_snapshot_store.add_listener(self._on_new_entry)
        color_snapshot_store.add_remove_listener(self._on_removed)

    def _on_new_entry(self, entry):
        SwingUtilities.invokeLater(self.table_model.refresh)

    def _on_removed(self):
        SwingUtilities.invokeLater(self.table_model.refresh)

    def _selected_entry(self):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            return None
        model_row = self.table.convertRowIndexToModel(view_row)
        return self.table_model.entry_at(model_row)

    def _on_take(self, event):
        comment = self.comment_field.getText()
        try:
            colors, total, colored_count = color_snapshot_engine.take_snapshot(self.callbacks, self.helpers)
        except Exception as e:
            self.status_label.setText("Snapshot failed: %s" % e)
            if self.error_fn:
                self.error_fn("Color Snapshots", "Failed to take snapshot: %s" % e)
            return
        entry = self.store.append(comment, colors, total, colored_count)
        self.comment_field.setText("")
        self.status_label.setText(
            "Snapshot #%d taken: %d of %d packet(s) currently have a color." % (entry.seq_id, colored_count, total))
        if self.log_fn:
            suffix = (" -- %s" % comment) if comment else ""
            self.log_fn("Color snapshot #%d taken (%d/%d packets colored)%s" % (
                entry.seq_id, colored_count, total, suffix))

    def _on_restore(self, event):
        entry = self._selected_entry()
        if entry is None:
            self.status_label.setText("Select a snapshot from the table first.")
            return
        ret = JOptionPane.showConfirmDialog(
            self,
            "Restore snapshot #%d (%s)?\n\n"
            "This overwrites the highlight color of every packet that existed in the Proxy history "
            "when this snapshot was taken (%d packets) back to its state at that time, including "
            "clearing packets that had no color. Packets added since then are left untouched.\n\n"
            "This cannot be undone -- take a fresh snapshot first if you want to be able to get back "
            "to the current colors." % (entry.seq_id, entry.comment or "no comment", entry.total),
            "Restore Color Snapshot #%d" % entry.seq_id,
            JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
        if ret != JOptionPane.YES_OPTION:
            return
        try:
            restored, skipped = color_snapshot_engine.restore_snapshot(self.callbacks, self.helpers, entry.colors)
        except Exception as e:
            self.status_label.setText("Restore failed: %s" % e)
            if self.error_fn:
                self.error_fn("Color Snapshots", "Failed to restore snapshot #%d: %s" % (entry.seq_id, e))
            return
        self.status_label.setText(
            "Snapshot #%d restored: %d packet(s) updated, %d skipped (added since the snapshot)."
            % (entry.seq_id, restored, skipped))
        if self.log_fn:
            self.log_fn("Color snapshot #%d restored (%d updated, %d skipped)" % (entry.seq_id, restored, skipped))

    def _on_delete(self, event):
        entry = self._selected_entry()
        if entry is None:
            self.status_label.setText("Select a snapshot from the table first.")
            return
        self.store.remove(entry)
        self.status_label.setText("Snapshot #%d deleted." % entry.seq_id)

    def _on_clear_all(self, event):
        ret = JOptionPane.showConfirmDialog(
            self,
            "Clear the highlight color of every packet currently in the Proxy history?\n\n"
            "This sets every packet's color to none, regardless of its current color. This cannot "
            "be undone -- take a snapshot first if you want to be able to get the current colors back.",
            "Clear All Colors",
            JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
        if ret != JOptionPane.YES_OPTION:
            return
        try:
            cleared = color_snapshot_engine.clear_all(self.callbacks)
        except Exception as e:
            self.status_label.setText("Clear failed: %s" % e)
            if self.error_fn:
                self.error_fn("Color Snapshots", "Failed to clear all colors: %s" % e)
            return
        self.status_label.setText("Cleared the color of %d packet(s)." % cleared)
        if self.log_fn:
            self.log_fn("Color Snapshots: cleared the color of %d packet(s)." % cleared)
