# -*- coding: utf-8 -*-
"""History Search tab: search the Proxy history's request/response bytes
for a literal word and list every occurrence with surrounding context,
independent of the CSV/Match & Replace/Color Snapshots features."""

import jarray
from java.awt import BorderLayout, FlowLayout, Toolkit
from java.awt.event import MouseAdapter
from java.awt.datatransfer import StringSelection
from javax.swing import (JButton, JComboBox, JLabel, JMenuItem, JPanel, JPopupMenu, JScrollPane, JSpinner,
                          JSplitPane, JTable, JTextField, ListSelectionModel, SpinnerNumberModel, SwingUtilities)
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
_NONE_DECODE_LABEL = "None"


def _decode_preview(text, label):
    if label == _NONE_DECODE_LABEL:
        return text
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


class _TablePopupListener(MouseAdapter):
    """Select the clicked result cell, then expose an explicit copy action.
    JTable's row selection alone makes the Before/Match/After values hard
    to copy independently, especially in Burp's embedded Swing UI."""
    def __init__(self, panel):
        self.panel = panel

    def mousePressed(self, event):
        self._show_if_popup(event)

    def mouseReleased(self, event):
        self._show_if_popup(event)

    def _show_if_popup(self, event):
        if not event.isPopupTrigger():
            return
        row = self.panel.table.rowAtPoint(event.getPoint())
        col = self.panel.table.columnAtPoint(event.getPoint())
        if row < 0 or col < 0:
            return
        self.panel.table.changeSelection(row, col, False, False)
        self.panel.copy_popup.show(self.panel.table, event.getX(), event.getY())


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
        query_help = JLabel("AND: hoge & piyo   OR: hoge | piyo   Literal &: Win \\& / Mac ¥&")
        query_help.setToolTipText("Use \\| or ¥| for a literal '|', and \\\\ or ¥¥ for a literal escape character.")
        top.add(query_help)
        top.add(JLabel("Chars before:"))
        self.before_spinner = JSpinner(SpinnerNumberModel(_DEFAULT_CONTEXT_CHARS, 0, 100000, 1))
        top.add(self.before_spinner)
        top.add(JLabel("Chars after:"))
        self.after_spinner = JSpinner(SpinnerNumberModel(_DEFAULT_CONTEXT_CHARS, 0, 100000, 1))
        top.add(self.after_spinner)
        top.add(JLabel("Packet No range:"))
        self.start_packet_field = JTextField(6)
        self.start_packet_field.setToolTipText("Start packet number (blank: first packet)")
        top.add(self.start_packet_field)
        top.add(JLabel("to"))
        self.end_packet_field = JTextField(6)
        self.end_packet_field.setToolTipText("End packet number (blank: last packet)")
        top.add(self.end_packet_field)
        self.all_packets_button = JButton("All", actionPerformed=self._on_all_packets)
        self.all_packets_button.setToolTipText("Search all HTTP History packets")
        top.add(self.all_packets_button)
        self.search_button = JButton("Search", actionPerformed=self._on_search)
        top.add(self.search_button)
        self.clear_button = JButton("Clear", actionPerformed=self._on_clear)
        top.add(self.clear_button)
        self.add(top, BorderLayout.NORTH)

        self.table_model = WordSearchTableModel()
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        # Make Before / Match / After individually selectable, so their
        # values can be copied without selecting an entire result row.
        self.table.setCellSelectionEnabled(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_SelectionListener(self))
        self.copy_popup = JPopupMenu()
        self.copy_popup.add(JMenuItem("Copy selected cell", actionPerformed=self._copy_selected_cell))
        self.table.addMouseListener(_TablePopupListener(self))

        table_panel = JPanel(BorderLayout())
        table_panel.add(JScrollPane(self.table), BorderLayout.CENTER)

        below_list = JPanel(BorderLayout())
        decode_option = JPanel(FlowLayout(FlowLayout.LEFT))
        decode_option.add(JLabel("Decode:"))
        self.decode_combo = JComboBox([_NONE_DECODE_LABEL] + _DECODE_LABELS)
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
            start_packet_no = self._packet_no_or_none(self.start_packet_field.getText(), "start")
            end_packet_no = self._packet_no_or_none(self.end_packet_field.getText(), "end")
            if (start_packet_no is not None and end_packet_no is not None
                    and start_packet_no > end_packet_no):
                raise ValueError("Start Packet No must not exceed End Packet No.")
        except ValueError as e:
            self.status_label.setText(str(e))
            return
        try:
            hits = word_search_engine.search(self.callbacks, self.helpers, word, before_chars, after_chars,
                                             start_packet_no, end_packet_no)
        except Exception as e:
            self.status_label.setText("Search failed: %s" % e)
            if self.error_fn:
                self.error_fn("History Search", "Search failed: %s" % e)
            return
        self.table_model.set_hits(hits)
        self._show_hit(None)
        self._update_decode_preview(None)
        range_text = self._range_display(start_packet_no, end_packet_no)
        self.status_label.setText("%d hit(s) found for \"%s\" in %s." % (len(hits), word, range_text))
        if self.log_fn:
            self.log_fn("History Search: %d hit(s) found for \"%s\" (%s, before=%d, after=%d)" % (
                len(hits), word, range_text, before_chars, after_chars))

    def _packet_no_or_none(self, text, boundary_name):
        value = str(text).strip()
        if not value:
            return None
        try:
            packet_no = int(value)
        except ValueError:
            raise ValueError("%s Packet No must be a positive integer." % boundary_name.capitalize())
        if packet_no < 1:
            raise ValueError("%s Packet No must be a positive integer." % boundary_name.capitalize())
        return packet_no

    def _range_display(self, start_packet_no, end_packet_no):
        if start_packet_no is None and end_packet_no is None:
            return "all HTTP History"
        return "Packet No %s to %s" % (start_packet_no if start_packet_no is not None else "first",
                                        end_packet_no if end_packet_no is not None else "last")

    def _on_clear(self, event):
        self.table_model.set_hits([])
        self._show_hit(None)
        self._update_decode_preview(None)
        self.status_label.setText("Cleared.")

    def _on_all_packets(self, event):
        """Explicitly restore the Packet No filter to all HTTP History."""
        self.start_packet_field.setText("")
        self.end_packet_field.setText("")
        self.status_label.setText("Packet No range set to all HTTP History.")

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

    def _copy_selected_cell(self, event):
        row = self.table.getSelectedRow()
        col = self.table.getSelectedColumn()
        if row < 0 or col < 0:
            return
        value = self.table.getValueAt(row, col)
        if value is None:
            return
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(str(value)), None)
            self.status_label.setText("Copied selected cell.")
        except Exception as e:
            self.status_label.setText("Copy failed: %s" % e)

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
