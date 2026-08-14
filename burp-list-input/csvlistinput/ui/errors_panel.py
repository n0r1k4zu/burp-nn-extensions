# -*- coding: utf-8 -*-
"""Errors tab: a table of every exception/failure raised anywhere in this
extension's own code (substitution stages across all Burp tools including
Scanner, arming, re-detect, context menu actions), so something going
wrong is immediately visible in the extension's own UI instead of only
showing up in Burp's separate Extender > Extensions > Errors console."""

import time

from java.awt import BorderLayout, FlowLayout
from java.lang import Integer
from javax.swing import JButton, JPanel, JScrollPane, JSplitPane, JTable, JTextArea, ListSelectionModel, \
    SwingUtilities
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel

COLUMNS = ["#", "Time", "Source", "Message"]


class ErrorsTableModel(AbstractTableModel):
    def __init__(self, error_store):
        AbstractTableModel.__init__(self)
        self.error_store = error_store
        self._cache = []

    def refresh(self):
        old_cache = self._cache
        new_cache = self.error_store.get_all()
        self._cache = new_cache
        if len(new_cache) > len(old_cache) and new_cache[:len(old_cache)] == old_cache:
            self.fireTableRowsInserted(len(old_cache), len(new_cache) - 1)
        else:
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
            return time.strftime("%H:%M:%S", time.localtime(e.timestamp)) if e.timestamp else ""
        if col == 2:
            return e.source or ""
        if col == 3:
            return e.message or ""
        return None


class _SelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.panel.table.getSelectedRow()
        if row < 0:
            self.panel._on_selection(-1)
            return
        model_row = self.panel.table.convertRowIndexToModel(row)
        self.panel._on_selection(model_row)


class ErrorsPanel(JPanel):
    def __init__(self, error_store):
        JPanel.__init__(self, BorderLayout())
        self.error_store = error_store

        self.table_model = ErrorsTableModel(error_store)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_SelectionListener(self))

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        self.clear_button = JButton("Clear errors", actionPerformed=self._on_clear)
        toolbar.add(self.clear_button)
        self.add(toolbar, BorderLayout.NORTH)

        self.detail_area = JTextArea(10, 40)
        self.detail_area.setEditable(False)
        self.detail_area.setLineWrap(True)
        self.detail_area.setWrapStyleWord(True)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), JScrollPane(self.detail_area))
        split.setResizeWeight(0.4)
        self.add(split, BorderLayout.CENTER)

        error_store.add_listener(self._on_new_entry)
        error_store.add_clear_listener(self._on_cleared)

    def _on_clear(self, event):
        self.error_store.clear()

    def _on_cleared(self):
        def do_clear():
            self.table_model.refresh()
            self.detail_area.setText("")
        SwingUtilities.invokeLater(do_clear)

    def _on_new_entry(self, entry):
        SwingUtilities.invokeLater(lambda: self.table_model.refresh())

    def _on_selection(self, row):
        entry = self.table_model.entry_at(row)
        if entry is None:
            self.detail_area.setText("")
            return
        text = entry.message or ""
        if entry.detail:
            text = text + "\n\n" + entry.detail
        self.detail_area.setText(text)
        self.detail_area.setCaretPosition(0)
