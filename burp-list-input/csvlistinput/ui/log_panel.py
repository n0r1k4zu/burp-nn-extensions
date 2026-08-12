# -*- coding: utf-8 -*-
"""Send-history log: table of attempts + Burp IMessageEditors for both
the request actually sent and the resulting response (requirement (6) --
verifying substitution really happened, plus confirming what the server
did with it)."""

import time

import jarray
from java.awt import BorderLayout, FlowLayout
from javax.swing import (JButton, JCheckBox, JPanel, JScrollPane, JSplitPane, JTable, ListSelectionModel,
                          SwingUtilities)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel

from burp import IMessageEditorController

COLUMNS = ["#", "Time", "Tool", "Status", "Row#", "Resp", "Host/Path", "Note"]

_EMPTY_BYTES = jarray.zeros(0, 'b')


class LogTableModel(AbstractTableModel):
    def __init__(self, log_store):
        AbstractTableModel.__init__(self)
        self.log_store = log_store
        self._cache = []

    def refresh(self):
        # Prefer a targeted "rows inserted" event over fireTableDataChanged()
        # when this is a pure append (the common case: a new send landed
        # while the user has an earlier row selected) -- a full
        # fireTableDataChanged() resets the JTable's selection, which was
        # silently blanking the message view every time a new log entry
        # arrived. Only fall back to the full reset when rows were
        # removed/reordered (e.g. the max_entries cap trimmed the front).
        old_cache = self._cache
        new_cache = self.log_store.get_all()
        self._cache = new_cache
        if len(new_cache) > len(old_cache) and new_cache[:len(old_cache)] == old_cache:
            self.fireTableRowsInserted(len(old_cache), len(new_cache) - 1)
        else:
            self.fireTableDataChanged()

    def mark_entry_updated(self, entry):
        """Called when an entry already in the table was mutated in place
        (the response arrived after the request row was already shown) --
        refreshes just that row's cells without touching selection."""
        try:
            row = self._cache.index(entry)
        except ValueError:
            return
        self.fireTableRowsUpdated(row, row)

    def getRowCount(self):
        return len(self._cache)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def entry_at(self, row):
        if 0 <= row < len(self._cache):
            return self._cache[row]
        return None

    def getValueAt(self, row, col):
        e = self._cache[row]
        if col == 0:
            return e.seq_id
        if col == 1:
            return time.strftime("%H:%M:%S", time.localtime(e.timestamp)) if e.timestamp else ""
        if col == 2:
            return e.tool_label
        if col == 3:
            return e.status_summary()
        if col == 4:
            return e.csv_row_no if e.csv_row_no is not None else ""
        if col == 5:
            return e.response_status if e.response_status is not None else ""
        if col == 6:
            return e.connection_display or ""
        if col == 7:
            return e.note or ""
        return None


class _EditorController(IMessageEditorController):
    def __init__(self):
        self.current_entry = None

    def getHttpService(self):
        return self.current_entry.http_service if self.current_entry else None

    def getRequest(self):
        return self.current_entry.request_bytes_after if self.current_entry else None

    def getResponse(self):
        return self.current_entry.response_bytes if self.current_entry else None


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


class LogPanel(JPanel):
    def __init__(self, callbacks, log_store):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.log_store = log_store
        self.controller = _EditorController()
        self.request_editor = callbacks.createMessageEditor(self.controller, False)
        self.response_editor = callbacks.createMessageEditor(self.controller, False)

        self.table_model = LogTableModel(log_store)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_SelectionListener(self))

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        self.clear_button = JButton("Clear log", actionPerformed=self._on_clear)
        toolbar.add(self.clear_button)
        # Match & Replace before/after comparison (requirement: be able to
        # check both the pre- and post-replacement request/response). Falls
        # back to the after-bytes when Match & Replace didn't touch that
        # side of a given entry (e.g. plain CSV Insertion Point sends, or a
        # response that had no matching rule), so toggling is always safe.
        self.show_before_checkbox = JCheckBox("Show before Match & Replace", False,
                                               actionPerformed=self._on_toggle_before_after)
        toolbar.add(self.show_before_checkbox)
        self.add(toolbar, BorderLayout.NORTH)

        messages_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                     self.request_editor.getComponent(), self.response_editor.getComponent())
        messages_split.setResizeWeight(0.5)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), messages_split)
        split.setResizeWeight(0.4)
        self.add(split, BorderLayout.CENTER)

        log_store.add_listener(self._on_new_entry)
        log_store.add_update_listener(self._on_entry_updated)
        log_store.add_clear_listener(self._on_cleared)

    def _on_clear(self, event):
        self.log_store.clear()

    def _on_cleared(self):
        def do_clear():
            self.table_model.refresh()
            self.controller.current_entry = None
            self.request_editor.setMessage(_EMPTY_BYTES, True)
            self.response_editor.setMessage(_EMPTY_BYTES, False)
        SwingUtilities.invokeLater(do_clear)

    def _on_new_entry(self, entry):
        SwingUtilities.invokeLater(lambda: self.table_model.refresh())

    def _on_entry_updated(self, entry):
        def do_update():
            self.table_model.mark_entry_updated(entry)
            if self.controller.current_entry is entry:
                self._show_response(entry)
        SwingUtilities.invokeLater(do_update)

    def _request_bytes_to_show(self, entry):
        if entry is None:
            return None
        if self.show_before_checkbox.isSelected() and entry.request_bytes_before is not None:
            return entry.request_bytes_before
        return entry.request_bytes_after

    def _response_bytes_to_show(self, entry):
        if entry is None:
            return None
        if self.show_before_checkbox.isSelected() and entry.response_bytes_before is not None:
            return entry.response_bytes_before
        return entry.response_bytes

    def _on_toggle_before_after(self, event):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            self._on_selection(-1)
            return
        self._on_selection(self.table.convertRowIndexToModel(view_row))

    def _on_selection(self, row):
        entry = self.table_model.entry_at(row)
        self.controller.current_entry = entry
        try:
            request_bytes = self._request_bytes_to_show(entry)
            if request_bytes is not None:
                self.request_editor.setMessage(request_bytes, True)
            else:
                self.request_editor.setMessage(_EMPTY_BYTES, True)
            self._show_response(entry)
        except Exception as e:
            try:
                self.callbacks.printError("CSV List Input: log message editor error: %s" % e)
            except Exception:
                pass

    def _show_response(self, entry):
        response_bytes = self._response_bytes_to_show(entry)
        if response_bytes is not None:
            self.response_editor.setMessage(response_bytes, False)
        else:
            self.response_editor.setMessage(_EMPTY_BYTES, False)
