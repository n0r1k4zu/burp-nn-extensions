# -*- coding: utf-8 -*-
"""Packet Grep tab: search the Proxy history's request/response bytes
for a literal word and list every occurrence with surrounding context,
independent of the CSV/Match & Replace/Color Snapshots features."""

import jarray
from threading import Thread
from java.awt import BorderLayout, FlowLayout, Toolkit
from java.awt.event import MouseAdapter
from java.awt.datatransfer import StringSelection
from java.lang import Integer, Runnable
from java.util.regex import Pattern
from javax.swing import (JButton, JComboBox, JLabel, JMenuItem, JPanel, JPopupMenu, JScrollPane, JSpinner,
                          JSplitPane, JTable, JTextField, ListSelectionModel, SpinnerNumberModel, SwingUtilities)
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.table import AbstractTableModel, TableRowSorter
from javax.swing import RowFilter

from burp import IMessageEditorController

from csvlistinput import decode_engine, word_search_engine

COLUMNS = ["List No", "Packet No", "Group", "Req/Resp", "Region", "Before", "Match", "After"]
_EMPTY_BYTES = jarray.zeros(0, 'b')
_DEFAULT_CONTEXT_CHARS = 30

# Representative decode-direction transforms only (decode_engine.py also has
# Encode counterparts, not relevant to previewing already-captured traffic).
_DECODE_LABELS = [label for label in decode_engine.TRANSFORM_LABELS if "Decode" in label or label == "ROT13"]
_DEFAULT_DECODE_LABEL = "URL Decode"
_NONE_DECODE_LABEL = "None"


class _UiRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


class _ResultFilterListener(DocumentListener):
    def __init__(self, panel):
        self.panel = panel

    def insertUpdate(self, event):
        self.panel._apply_result_filter()

    def removeUpdate(self, event):
        self.panel._apply_result_filter()

    def changedUpdate(self, event):
        self.panel._apply_result_filter()


def _decode_preview(text, label):
    if label == _NONE_DECODE_LABEL:
        return text
    result = decode_engine.run_all(text, enabled_labels=[label])[0]
    return result.text if result.ok() else "(%s)" % result.error


class WordSearchTableModel(AbstractTableModel):
    def __init__(self, include_word_list_comment=False):
        AbstractTableModel.__init__(self)
        self.hits = []
        self.include_word_list_comment = include_word_list_comment

    def set_hits(self, hits):
        self.hits = hits
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.hits)

    def getColumnCount(self):
        return len(COLUMNS) + (1 if self.include_word_list_comment else 0)

    def getColumnName(self, col):
        if self.include_word_list_comment and col == len(COLUMNS):
            return "My Word List Comment"
        return COLUMNS[col]

    def getColumnClass(self, col):
        return Integer if col in (0, 1) else str

    def hit_at(self, row):
        if 0 <= row < len(self.hits):
            return self.hits[row]
        return None

    def getValueAt(self, row, col):
        h = self.hits[row]
        if col == 0:
            return Integer(row + 1)
        if col == 1:
            return h["packet_no"]
        if col == 2:
            return h.get("group", "")
        if col == 3:
            return h["side"]
        if col == 4:
            return h.get("region", "Unknown")
        if col == 5:
            return h["before"]
        if col == 6:
            return h["match"]
        if col == 7:
            return h["after"]
        if self.include_word_list_comment and col == len(COLUMNS):
            return h.get("word_list_comment", "")
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
    def __init__(self, callbacks, helpers, log_fn=None, error_fn=None, word_list_store=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.log_fn = log_fn
        self.error_fn = error_fn
        self._search_worker = None
        self._cancel_requested = False
        self.word_list_store = word_list_store
        self.is_word_list_grep = word_list_store is not None
        self.grep_label = "My Word List Grep" if self.is_word_list_grep else "Packet Grep"

        start_row = JPanel(FlowLayout(FlowLayout.LEFT))
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        if not self.is_word_list_grep:
            top.add(JLabel("Search word:"))
            self.word_field = JTextField(24)
            top.add(self.word_field)
            # Explicit Unicode escapes avoid Jython/Swing treating the
            # Japanese-Mac yen escape prefix as an ASCII byte string.
            query_help = JLabel(u"AND: hoge & piyo   OR: hoge | piyo   Literal &: Win \\& / Mac \u00a5&")
            query_help.setToolTipText(
                u"Use \\| or \u00a5| for a literal '|', and \\\\ or \u00a5\u00a5 for a literal escape character.")
            top.add(query_help)
        else:
            self.word_field = None
            top.add(JLabel("Searches every applied My Word List word."))
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
        self.search_button = JButton("My Word List Grep Start" if self.is_word_list_grep else "Search",
                                     actionPerformed=self._on_search)
        if self.is_word_list_grep:
            start_row.add(self.search_button)
        else:
            top.add(self.search_button)
        self.cancel_button = JButton("Cancel", actionPerformed=self._on_cancel)
        self.cancel_button.setEnabled(False)
        top.add(self.cancel_button)
        self.clear_button = JButton("Clear", actionPerformed=self._on_clear)
        top.add(self.clear_button)
        if self.is_word_list_grep:
            north = JPanel(BorderLayout())
            north.add(start_row, BorderLayout.NORTH)
            north.add(top, BorderLayout.CENTER)
            self.add(north, BorderLayout.NORTH)
        else:
            self.add(top, BorderLayout.NORTH)

        self.table_model = WordSearchTableModel(self.is_word_list_grep)
        self.table = JTable(self.table_model)
        self.result_sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.result_sorter)
        # Make Before / Match / After individually selectable, so their
        # values can be copied without selecting an entire result row.
        self.table.setCellSelectionEnabled(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_SelectionListener(self))
        self.copy_popup = JPopupMenu()
        self.copy_popup.add(JMenuItem("Copy selected cell", actionPerformed=self._copy_selected_cell))
        self.table.addMouseListener(_TablePopupListener(self))

        table_panel = JPanel(BorderLayout())
        result_filter_row = JPanel(FlowLayout(FlowLayout.LEFT))
        result_filter_row.add(JLabel("Find in results:"))
        self.result_filter_field = JTextField(28)
        self.result_filter_field.setToolTipText(
            "Filter current result rows only; this does not run a new %s." % self.grep_label)
        self.result_filter_field.getDocument().addDocumentListener(_ResultFilterListener(self))
        result_filter_row.add(self.result_filter_field)
        result_filter_row.add(JLabel("(all result columns)"))
        table_panel.add(result_filter_row, BorderLayout.NORTH)
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
            ("Enter a search word and press Search." if not self.is_word_list_grep else
             "Apply words in My Word List, then press My Word List Grep Start.") + " Select a result row to preview it and its decoded "
            "Before/Match/After below.")
        self.add(self.status_label, BorderLayout.SOUTH)

    def _on_search(self, event):
        if self._search_worker is not None:
            return
        if self.is_word_list_grep:
            words = self.word_list_store.snapshot()
            if not words:
                self.status_label.setText("My Word List is empty. Add a Word and click Apply changes.")
                return
            word = None
        else:
            word = self.word_field.getText()
            if not word:
                self.status_label.setText("Enter a search word first.")
                return
            words = None
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
        self.search_button.setEnabled(False)
        self.search_button.setText("Searching...")
        self.cancel_button.setEnabled(True)
        self.status_label.setText("Searching Proxy history in the background...")
        self._cancel_requested = False
        self._search_worker = Thread(target=self._search_worker_run,
                                     args=(word, words, before_chars, after_chars, start_packet_no, end_packet_no))
        self._search_worker.setDaemon(True)
        self._search_worker.start()

    def _search_worker_run(self, word, words, before_chars, after_chars, start_packet_no, end_packet_no):
        try:
            warnings = []
            if words is None:
                hits = word_search_engine.search(self.callbacks, self.helpers, word, before_chars, after_chars,
                                                 start_packet_no, end_packet_no,
                                                 cancel_check=lambda: self._cancel_requested)
            else:
                hits = []
                for row in words:
                    if self._cancel_requested:
                        break
                    try:
                        # Store.replace() canonicalizes this field to a real
                        # Python bool.  Require *that exact* True value here:
                        # no Java Boolean/String object can accidentally turn
                        # a Regex-OFF row into a regex search.
                        if row.get('is_regex') is True:
                            word_hits = word_search_engine.search_regex(
                                self.callbacks, self.helpers, row['word'], before_chars, after_chars,
                                start_packet_no, end_packet_no, cancel_check=lambda: self._cancel_requested)
                        else:
                            word_hits = word_search_engine.search_literal(
                                self.callbacks, self.helpers, row['word'], before_chars, after_chars,
                                start_packet_no, end_packet_no, cancel_check=lambda: self._cancel_requested)
                    except ValueError as error:
                        warnings.append('%s: %s' % (row['word'], error))
                        continue
                    for hit in word_hits:
                        hit['word_list_comment'] = row.get('comment', '')
                    hits.extend(word_hits)
            SwingUtilities.invokeLater(_UiRunnable(
                lambda: self._search_finished(hits, word, before_chars, after_chars,
                                               start_packet_no, end_packet_no, self._cancel_requested, warnings)))
        except Exception as e:
            SwingUtilities.invokeLater(_UiRunnable(lambda error=e: self._search_failed(error)))

    def _restore_search_buttons(self):
        self._search_worker = None
        self.search_button.setEnabled(True)
        self.search_button.setText("My Word List Grep Start" if self.is_word_list_grep else "Search")
        self.cancel_button.setEnabled(False)

    def _search_finished(self, hits, word, before_chars, after_chars, start_packet_no, end_packet_no, cancelled,
                         warnings=None):
        self.table_model.set_hits(hits)
        self._show_hit(None)
        self._update_decode_preview(None)
        range_text = self._range_display(start_packet_no, end_packet_no)
        self._restore_search_buttons()
        prefix = "Cancelled: " if cancelled else ""
        description = 'My Word List (%d word(s))' % len(self.word_list_store.snapshot()) if self.is_word_list_grep else '"%s"' % word
        warning_text = (' %d invalid regex row(s) skipped.' % len(warnings)) if warnings else ''
        self.status_label.setText("%s%d hit(s) found for %s in %s.%s" %
                                  (prefix, len(hits), description, range_text, warning_text))
        if self.log_fn:
            self.log_fn("%s: %d hit(s) found for %s (%s, before=%d, after=%d)" % (
                self.grep_label, len(hits), description, range_text, before_chars, after_chars))
        if warnings and self.error_fn:
            self.error_fn('My Word List Grep', 'Invalid regular expression row(s): %s' % '; '.join(warnings))

    def _search_failed(self, error):
        self._restore_search_buttons()
        self.status_label.setText("Search failed: %s" % error)
        if self.error_fn:
            self.error_fn(self.grep_label, "Search failed: %s" % error)

    def _on_cancel(self, event):
        if self._search_worker is None:
            return
        self._cancel_requested = True
        self.status_label.setText("Cancel requested; finishing the current packet...")
        self.cancel_button.setEnabled(False)

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
        self.result_filter_field.setText("")
        self.result_sorter.setRowFilter(None)
        self._show_hit(None)
        self._update_decode_preview(None)
        self.status_label.setText("Cleared.")

    def _apply_result_filter(self):
        query = str(self.result_filter_field.getText())
        if not query:
            self.result_sorter.setRowFilter(None)
            return
        self.result_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(query)))

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
