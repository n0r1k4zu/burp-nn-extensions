# -*- coding: utf-8 -*-
"""History Search tab: search the Proxy history's request/response bytes
for a literal word and list every occurrence with surrounding context,
independent of the CSV/Match & Replace/Color Snapshots features."""

import jarray
from java.awt import BorderLayout, FlowLayout
from javax.swing import (JButton, JLabel, JPanel, JScrollPane, JSpinner, JSplitPane, JTable, JTextField,
                          ListSelectionModel, SpinnerNumberModel, SwingUtilities)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel

from burp import IMessageEditorController

from csvlistinput import word_search_engine

COLUMNS = ["List No", "Packet No", "Req/Resp", "Before", "Match", "After"]
_EMPTY_BYTES = jarray.zeros(0, 'b')
_DEFAULT_CONTEXT_CHARS = 30


class WordSearchTableModel(AbstractTableModel):
    def __init__(self):
        AbstractTableModel.__init__(self)
        self.hits = []

    def set_hits(self, hits):
        self.hits = hits
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.hits)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def hit_at(self, row):
        if 0 <= row < len(self.hits):
            return self.hits[row]
        return None

    def getValueAt(self, row, col):
        h = self.hits[row]
        if col == 0:
            return row + 1
        if col == 1:
            return h["packet_no"]
        if col == 2:
            return h["side"]
        if col == 3:
            return h["before"]
        if col == 4:
            return h["match"]
        if col == 5:
            return h["after"]
        return None


class _EditorController(IMessageEditorController):
    def __init__(self):
        self.current_hit = None

    def getHttpService(self):
        return self.current_hit["http_service"] if self.current_hit else None

    def getRequest(self):
        return self.current_hit["request_bytes"] if self.current_hit else None

    def getResponse(self):
        return self.current_hit["response_bytes"] if self.current_hit else None


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


class WordSearchPanel(JPanel):
    def __init__(self, callbacks, helpers, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.log_fn = log_fn
        self.error_fn = error_fn

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Search word:"))
        self.word_field = JTextField(24)
        top.add(self.word_field)
        top.add(JLabel("Chars before:"))
        self.before_spinner = JSpinner(SpinnerNumberModel(_DEFAULT_CONTEXT_CHARS, 0, 100000, 1))
        top.add(self.before_spinner)
        top.add(JLabel("Chars after:"))
        self.after_spinner = JSpinner(SpinnerNumberModel(_DEFAULT_CONTEXT_CHARS, 0, 100000, 1))
        top.add(self.after_spinner)
        self.search_button = JButton("Search", actionPerformed=self._on_search)
        top.add(self.search_button)
        self.clear_button = JButton("Clear", actionPerformed=self._on_clear)
        top.add(self.clear_button)
        self.add(top, BorderLayout.NORTH)

        self.table_model = WordSearchTableModel()
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_SelectionListener(self))

        self.controller = _EditorController()
        self.request_editor = callbacks.createMessageEditor(self.controller, False)
        self.response_editor = callbacks.createMessageEditor(self.controller, False)
        messages_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                     self.request_editor.getComponent(), self.response_editor.getComponent())
        messages_split.setResizeWeight(0.5)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), messages_split)
        split.setResizeWeight(0.5)
        self.add(split, BorderLayout.CENTER)

        self.status_label = JLabel("Enter a search word and press Search. Select a result row to preview it below.")
        self.add(self.status_label, BorderLayout.SOUTH)

    def _on_search(self, event):
        word = self.word_field.getText()
        if not word:
            self.status_label.setText("Enter a search word first.")
            return
        before_chars = int(self.before_spinner.getValue())
        after_chars = int(self.after_spinner.getValue())
        try:
            hits = word_search_engine.search(self.callbacks, self.helpers, word, before_chars, after_chars)
        except Exception as e:
            self.status_label.setText("Search failed: %s" % e)
            if self.error_fn:
                self.error_fn("History Search", "Search failed: %s" % e)
            return
        self.table_model.set_hits(hits)
        self._show_hit(None)
        self.status_label.setText("%d hit(s) found for \"%s\"." % (len(hits), word))
        if self.log_fn:
            self.log_fn("History Search: %d hit(s) found for \"%s\" (before=%d, after=%d)" % (
                len(hits), word, before_chars, after_chars))

    def _on_clear(self, event):
        self.word_field.setText("")
        self.before_spinner.setValue(_DEFAULT_CONTEXT_CHARS)
        self.after_spinner.setValue(_DEFAULT_CONTEXT_CHARS)
        self.table_model.set_hits([])
        self._show_hit(None)
        self.status_label.setText("Cleared.")

    def _on_selection(self, row):
        self._show_hit(self.table_model.hit_at(row))

    def _show_hit(self, hit):
        self.controller.current_hit = hit
        try:
            req = hit["request_bytes"] if hit else None
            resp = hit["response_bytes"] if hit else None
            self.request_editor.setMessage(req if req is not None else _EMPTY_BYTES, True)
            self.response_editor.setMessage(resp if resp is not None else _EMPTY_BYTES, False)
        except Exception as e:
            try:
                self.callbacks.printError("CSV List Input: history search message editor error: %s" % e)
            except Exception:
                pass
