# -*- coding: utf-8 -*-
"""Live Word Watch tab: like History Search, but instead of sweeping the
existing Proxy History on demand, it watches live traffic through the
enabled tools and appends a hit the moment the configured word is seen
in a request or response -- same result shape (List No / Packet No /
Req/Resp / Before / Match / After), same row-preview and inline-decode
UI as the History Search tab."""

import jarray
from java.awt import BorderLayout, FlowLayout, GridLayout
from java.awt.event import ActionListener
from javax.swing import (BoxLayout, JButton, JCheckBox, JComboBox, JLabel, JPanel, JScrollPane, JSpinner,
                          JSplitPane, JTable, JTextField, ListSelectionModel, SpinnerNumberModel,
                          SwingUtilities)
from javax.swing.event import ChangeListener, DocumentListener, ListSelectionListener
from javax.swing.table import AbstractTableModel

from burp import IMessageEditorController

from csvlistinput import decode_engine
from csvlistinput.constants import TOOL_FLAG_LABELS
from csvlistinput.proxy_history_lookup import find_packet_no

COLUMNS = ["List No", "Packet No", "Req/Resp", "Before", "Match", "After"]
_EMPTY_BYTES = jarray.zeros(0, 'b')

# Same representative decode-direction subset as the History Search tab
# (see word_search_panel.py) -- kept in sync deliberately, not imported
# from there, since the two tabs are independent Swing components.
_DECODE_LABELS = [label for label in decode_engine.TRANSFORM_LABELS if "Decode" in label or label == "ROT13"]
_DEFAULT_DECODE_LABEL = "URL Decode"


def _decode_preview(text, label):
    result = decode_engine.run_all(text, enabled_labels=[label])[0]
    return result.text if result.ok() else "(%s)" % result.error


class LiveWordWatchTableModel(AbstractTableModel):
    def __init__(self, store, callbacks, helpers):
        AbstractTableModel.__init__(self)
        self.store = store
        self.callbacks = callbacks
        self.helpers = helpers
        self._cache = []

    def refresh(self):
        # Same "targeted rows-inserted vs full reset" discipline as
        # log_panel.LogTableModel -- hits stream in continuously, so
        # preserving the user's current selection on a pure append matters
        # here even more than it does for the Log tab.
        old_cache = self._cache
        new_cache = self.store.get_all()
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

    def hit_at(self, row):
        if 0 <= row < len(self._cache):
            return self._cache[row]
        return None

    def getValueAt(self, row, col):
        h = self._cache[row]
        if col == 0:
            return h.seq_id
        if col == 1:
            return self._packet_no_display(h)
        if col == 2:
            return h.side
        if col == 3:
            return h.before
        if col == 4:
            return h.match
        if col == 5:
            return h.after
        return None

    def _packet_no_display(self, h):
        if h.packet_no is None:
            h.packet_no = find_packet_no(self.callbacks, self.helpers, h.http_service, h.request_bytes)
        return h.packet_no if h.packet_no != -1 else "-"


class _EditorController(IMessageEditorController):
    def __init__(self):
        self.current_hit = None

    def getHttpService(self):
        return self.current_hit.http_service if self.current_hit else None

    def getRequest(self):
        return self.current_hit.request_bytes if self.current_hit else None

    def getResponse(self):
        return self.current_hit.response_bytes if self.current_hit else None


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


class _WordFieldListener(DocumentListener):
    """Same pattern as insertion_point_panel._FilterListener / decode_panel
    ._DocChangeListener -- fires the same handler on any edit."""

    def __init__(self, panel):
        self.panel = panel

    def insertUpdate(self, event):
        self.panel._on_word_changed()

    def removeUpdate(self, event):
        self.panel._on_word_changed()

    def changedUpdate(self, event):
        self.panel._on_word_changed()


class _ContextSpinnerListener(ChangeListener):
    def __init__(self, panel, which):
        self.panel = panel
        self.which = which

    def stateChanged(self, event):
        self.panel._on_context_changed(self.which)


class _FlagToggleListener(ActionListener):
    def __init__(self, panel, flag, checkbox):
        self.panel = panel
        self.flag = flag
        self.checkbox = checkbox

    def actionPerformed(self, event):
        self.panel._on_flag_toggle(self.flag, self.checkbox)


class LiveWordWatchPanel(JPanel):
    def __init__(self, callbacks, helpers, settings, store, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.settings = settings
        self.store = store
        self.error_fn = error_fn
        # Coalesces bursts of hits (e.g. a common search word matching
        # many times in one large response) into a single EDT refresh
        # instead of one invokeLater() per hit -- a burst of thousands of
        # individually-queued refreshes was enough to flood the EDT and
        # freeze the whole Burp UI (not just this tab), since Swing's
        # event queue is shared application-wide.
        self._refresh_pending = False

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

        enable_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.enabled_checkbox = JCheckBox("Live Word Watch: Enabled", settings.enabled,
                                           actionPerformed=self._on_enabled_toggle)
        enable_row.add(self.enabled_checkbox)
        top.add(enable_row)

        word_row = JPanel(FlowLayout(FlowLayout.LEFT))
        word_row.add(JLabel("Search word:"))
        self.word_field = JTextField(settings.word, 24)
        self.word_field.getDocument().addDocumentListener(_WordFieldListener(self))
        word_row.add(self.word_field)
        word_row.add(JLabel("Chars before:"))
        self.before_spinner = JSpinner(SpinnerNumberModel(settings.before_chars, 0, 100000, 1))
        self.before_spinner.addChangeListener(_ContextSpinnerListener(self, "before"))
        word_row.add(self.before_spinner)
        word_row.add(JLabel("Chars after:"))
        self.after_spinner = JSpinner(SpinnerNumberModel(settings.after_chars, 0, 100000, 1))
        self.after_spinner.addChangeListener(_ContextSpinnerListener(self, "after"))
        word_row.add(self.after_spinner)
        self.clear_button = JButton("Clear", actionPerformed=self._on_clear)
        word_row.add(self.clear_button)
        top.add(word_row)

        top.add(JLabel("Tool flags to watch:"))
        flags_panel = JPanel(GridLayout(0, 4))
        self.flag_checkboxes = {}
        for flag, label in TOOL_FLAG_LABELS:
            cb = JCheckBox(label, flag in settings.enabled_tool_flags)
            cb.addActionListener(_FlagToggleListener(self, flag, cb))
            flags_panel.add(cb)
            self.flag_checkboxes[flag] = cb
        top.add(flags_panel)

        self.add(top, BorderLayout.NORTH)

        self.table_model = LiveWordWatchTableModel(store, callbacks, helpers)
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
            "Enable and enter a search word to start watching live traffic. Hits appear below as they happen.")
        self.add(self.status_label, BorderLayout.SOUTH)

        store.add_listener(self._on_new_hit)
        store.add_clear_listener(self._on_cleared)

    def _on_enabled_toggle(self, event):
        self.settings.enabled = self.enabled_checkbox.isSelected()
        self.status_label.setText("Watching for \"%s\"..." % self.settings.word if self.settings.enabled
                                   else "Stopped.")

    def _on_word_changed(self):
        self.settings.word = self.word_field.getText()

    def _on_context_changed(self, which):
        if which == "before":
            self.settings.before_chars = int(self.before_spinner.getValue())
        else:
            self.settings.after_chars = int(self.after_spinner.getValue())

    def _on_flag_toggle(self, flag, checkbox):
        if checkbox.isSelected():
            self.settings.enabled_tool_flags.add(flag)
        else:
            self.settings.enabled_tool_flags.discard(flag)

    def _on_clear(self, event):
        self.store.clear()

    def _on_new_hit(self, hit):
        # Called from the IHttpListener network thread, potentially many
        # times in a tight loop for one message -- only schedule an EDT
        # refresh if one isn't already pending, so a burst collapses into
        # a single repaint instead of flooding the EDT (see __init__).
        if self._refresh_pending:
            return
        self._refresh_pending = True
        SwingUtilities.invokeLater(self._do_refresh)

    def _do_refresh(self):
        self._refresh_pending = False
        self.table_model.refresh()

    def _on_cleared(self):
        def do_clear():
            self.table_model.refresh()
            self._show_hit(None)
            self._update_decode_preview(None)
        SwingUtilities.invokeLater(do_clear)

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
        self.decoded_before_field.setText(_decode_preview(hit.before, label))
        self.decoded_match_field.setText(_decode_preview(hit.match, label))
        self.decoded_after_field.setText(_decode_preview(hit.after, label))

    def _show_hit(self, hit):
        self.controller.current_hit = hit
        try:
            req = hit.request_bytes if hit else None
            resp = hit.response_bytes if hit else None
            self.request_editor.setMessage(req if req is not None else _EMPTY_BYTES, True)
            self.response_editor.setMessage(resp if resp is not None else _EMPTY_BYTES, False)
        except Exception as e:
            try:
                self.callbacks.printError("CSV List Input: live word watch message editor error: %s" % e)
            except Exception:
                pass
