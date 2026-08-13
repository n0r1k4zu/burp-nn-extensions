# -*- coding: utf-8 -*-
"""History Search tab: search the Proxy history's request/response bytes
for a literal word and list every occurrence with surrounding context,
independent of the CSV/Match & Replace/Color Snapshots features."""

import jarray
from java.awt import BorderLayout, FlowLayout
from javax.swing import (JButton, JComboBox, JLabel, JPanel, JScrollPane, JSpinner, JSplitPane, JTable, JTextField,
                          ListSelectionModel, SpinnerNumberModel, SwingUtilities)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel

from burp import IMessageEditorController

from csvlistinput import decode_engine, word_search_engine

COLUMNS = ["List No", "Packet No", "Req/Resp", "Before", "Match", "After"]
_EMPTY_BYTES = jarray.zeros(0, 'b')
_DEFAULT_CONTEXT_CHARS = 30

# Representative decode-direction transforms only (decode_engine.py also has
# Encode counterparts, not relevant to previewing already-captured traffic).
_DECODE_LABELS = [label for label in decode_engine.TRANSFORM_LABELS if "Decode" in label or label == "ROT13"]
_DEFAULT_DECODE_LABEL = "URL Decode"


def _decode_preview(text, label):
    result = decode_engine.run_all(text, enabled_labels=[label])[0]
    return result.text if result.ok() else "(%s)" % result.error


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

        table_panel = JPanel(BorderLayout())
        table_panel.add(JScrollPane(self.table), BorderLayout.CENTER)

        below_list = JPanel(BorderLayout())
        decode_option = JPanel(FlowLayout(FlowLayout.LEFT))
        decode_option.add(JLabel("Decode:"))
        self.decode_combo = JComboBox(_DECODE_LABELS)
        self.decode_combo.setSelectedItem(_DEFAULT_DECODE_LABEL)
        self.decode_combo.addActionListener(self._on_decode_option_changed)
        decode_option.add(self.decode_combo)
        below_list.add(decode_option, BorderLayout.WEST)

        decoded_fields = JPanel(FlowLayout(FlowLayout.LEFT))
        decoded_fields.add(JLabel("Before:"))
        self.decoded_before_field = JTextField(18)
        self.decoded_before_field.setEditable(False)
        decoded_fields.add(self.decoded_before_field)
        decoded_fields.add(JLabel("Match:"))
        self.decoded_match_field = JTextField(18)
        self.decoded_match_field.setEditable(False)
        decoded_fields.add(self.decoded_match_field)
        decoded_fields.add(JLabel("After:"))
        self.decoded_after_field = JTextField(18)
        self.decoded_after_field.setEditable(False)
        decoded_fields.add(self.decoded_after_field)
        below_list.add(decoded_fields, BorderLayout.CENTER)

        table_panel.add(below_list, BorderLayout.SOUTH)

        self.controller = _EditorController()
        self.request_editor = callbacks.createMessageEditor(self.controller, False)
        self.response_editor = callbacks.createMessageEditor(self.controller, False)
        messages_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                     self.request_editor.getComponent(), self.response_editor.getComponent())
        messages_split.setResizeWeight(0.5)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_panel, messages_split)
        split.setResizeWeight(0.5)
        self.add(split, BorderLayout.CENTER)

        self.status_label = JLabel(
            "Enter a search word and press Search. Select a result row to preview it and its decoded "
            "Before/Match/After below.")
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
        self._update_decode_preview(None)
        self.status_label.setText("%d hit(s) found for \"%s\"." % (len(hits), word))
        if self.log_fn:
            self.log_fn("History Search: %d hit(s) found for \"%s\" (before=%d, after=%d)" % (
                len(hits), word, before_chars, after_chars))

    def _on_clear(self, event):
        self.table_model.set_hits([])
        self._show_hit(None)
        self._update_decode_preview(None)
        self.status_label.setText("Cleared.")

    def _on_selection(self, row):
        hit = self.table_model.hit_at(row)
        self._show_hit(hit)
        self._update_decode_preview(hit)

    def _on_decode_option_changed(self, event):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            self._update_decode_preview(None)
            return
        self._update_decode_preview(self.table_model.hit_at(self.table.convertRowIndexToModel(view_row)))

    def _update_decode_preview(self, hit):
        if hit is None:
            self.decoded_before_field.setText("")
            self.decoded_match_field.setText("")
            self.decoded_after_field.setText("")
            return
        label = str(self.decode_combo.getSelectedItem())
        self.decoded_before_field.setText(_decode_preview(hit["before"], label))
        self.decoded_match_field.setText(_decode_preview(hit["match"], label))
        self.decoded_after_field.setText(_decode_preview(hit["after"], label))

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
