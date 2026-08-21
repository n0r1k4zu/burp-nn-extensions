# -*- coding: utf-8 -*-
"""Target & Replace with Decode & Encode tab: rewrites a specific Insertion
Point's value even when it's wrapped in an encoding (URL/Base64/Hex/HTML
Entity/Unicode escapes/ROT13) by decoding it, running a find/replace
(plain or regex) on the decoded text, and re-encoding before sending.

The target is armed independently of Target & List Mapping -- right-click
a request and choose "Send to Target & Replace with Decode & Encode" (a separate
menu item/armed target from "Send to Target & List Mapping", see
context_menu.py). Everything else (master Enabled toggle, tool-flag
selection) is also independent of Target & List Mapping's own Active
toggle and flags, matching the pattern established by Match & Replace.
"""

import re
import traceback

from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout
from java.awt.event import ActionListener
from java.lang import Boolean, Integer, String
from javax.swing import (BoxLayout, DefaultCellEditor, JButton, JCheckBox, JComboBox, JLabel, JPanel,
                          JScrollPane, JSplitPane, JTable, JTextArea, JTextField, ListSelectionModel, RowFilter)
from javax.swing.event import DocumentListener, ListSelectionListener, TableModelListener
from javax.swing.table import AbstractTableModel, TableRowSorter

from csvlistinput import codec_engine, detection_engine
from csvlistinput.constants import TOOL_FLAG_LABELS
from csvlistinput.utils import coerce_boolean, to_display_text

COLUMNS = ["Enabled", "Insertion Points", "Type", "Nesting", "Original Value", "Codec", "Regex", "Find", "Replace With"]
_EDITABLE_COLUMNS = (0, 5, 6, 7, 8)
_BOOLEAN_COLUMNS = (0, 6)

_NOT_ARMED_TEXT = ("No target armed. Right-click a request in Repeater / Proxy history and choose "
                    "'Send to Target & Replace with Decode & Encode'.")


class DecodeReplaceTableModel(AbstractTableModel):
    def __init__(self, armed_target, settings):
        AbstractTableModel.__init__(self)
        self.armed_target = armed_target
        self.settings = settings

    def getRowCount(self):
        return len(self.armed_target.template_points)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getColumnClass(self, col):
        if col == 3:
            return Integer
        return Boolean if col in _BOOLEAN_COLUMNS else String

    def _point(self, row):
        return self.armed_target.template_points[row]

    def getValueAt(self, row, col):
        p = self._point(row)
        rule = self.settings.get_rule(p.path)
        if col == 0:
            return rule.enabled
        if col == 1:
            return p.path
        if col == 2:
            return (p.type + " (recovered)") if p.recovered else p.type
        if col == 3:
            return Integer(p.nesting_depth)
        if col == 4:
            preview = p.original_value if p.original_value is not None else ""
            preview = preview.replace("\n", "\\n").replace("\r", "\\r")
            if len(preview) > 80:
                preview = preview[:77] + "..."
            return preview
        if col == 5:
            return rule.codec
        if col == 6:
            return rule.is_regex
        if col == 7:
            return rule.find
        if col == 8:
            return rule.replace_with
        return None

    def isCellEditable(self, row, col):
        return col in _EDITABLE_COLUMNS

    def setValueAt(self, value, row, col):
        p = self._point(row)
        rule = self.settings.get_rule(p.path)
        if col == 0:
            rule.enabled = coerce_boolean(value)
        elif col == 5:
            rule.codec = value
        elif col == 6:
            rule.is_regex = coerce_boolean(value)
        elif col == 7:
            rule.find = value
        elif col == 8:
            rule.replace_with = value
        self.fireTableCellUpdated(row, col)

    def refresh(self):
        self.fireTableDataChanged()


class _FlagToggleListener(ActionListener):
    def __init__(self, panel, flag, checkbox):
        self.panel = panel
        self.flag = flag
        self.checkbox = checkbox

    def actionPerformed(self, event):
        self.panel._on_flag_toggle(self.flag, self.checkbox)


class _RowSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self.panel._refresh_detail()


class _TableChangeListener(TableModelListener):
    """Fires on every cell edit, including a Codec combo change for the
    selected row -- keeps the Decoded Value preview live as the user
    tweaks it, not just when the row selection itself changes."""

    def __init__(self, panel):
        self.panel = panel

    def tableChanged(self, event):
        self.panel._refresh_detail()


class _FilterListener(DocumentListener):
    def __init__(self, panel):
        self.panel = panel

    def insertUpdate(self, event):
        self.panel._apply_filter()

    def removeUpdate(self, event):
        self.panel._apply_filter()

    def changedUpdate(self, event):
        self.panel._apply_filter()


def _make_detail_area():
    area = JTextArea(4, 30)
    area.setEditable(False)
    area.setLineWrap(True)
    area.setWrapStyleWord(False)
    return area, JScrollPane(area)


class DecodeReplacePanel(JPanel):
    def __init__(self, armed_target, decode_replace_settings, helpers, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.armed_target = armed_target
        self.settings = decode_replace_settings
        self.helpers = helpers
        self.log_fn = log_fn
        self.error_fn = error_fn

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

        self.summary_label = JLabel(_NOT_ARMED_TEXT)
        top.add(self.summary_label)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.enabled_checkbox = JCheckBox("Target & Replace with Decode & Encode: Enabled",
                                           decode_replace_settings.enabled,
                                           actionPerformed=self._on_enabled_toggle)
        self.redetect_button = JButton("Re-detect insertion points", actionPerformed=self._on_redetect)
        self.diagnostics_checkbox = JCheckBox(
            "Log DIAGNOSTIC entries for non-enabled tools hitting the same host/path",
            armed_target.log_diagnostics_for_other_tools, actionPerformed=self._on_diagnostics_toggle)
        self.lenient_checkbox = JCheckBox(
            "Attempt lenient recovery for malformed nested JSON (experimental)",
            armed_target.allow_lenient_json, actionPerformed=self._on_lenient_toggle)
        controls.add(self.enabled_checkbox)
        controls.add(self.redetect_button)
        controls.add(self.diagnostics_checkbox)
        controls.add(self.lenient_checkbox)
        top.add(controls)

        top.add(JLabel("Tool flags to apply this feature for (independent of Target & List Mapping's flags):"))
        flags_panel = JPanel(GridLayout(0, 4))
        self.flag_checkboxes = {}
        for flag, label in TOOL_FLAG_LABELS:
            cb = JCheckBox(label, flag in decode_replace_settings.enabled_tool_flags)
            cb.addActionListener(_FlagToggleListener(self, flag, cb))
            flags_panel.add(cb)
            self.flag_checkboxes[flag] = cb
        top.add(flags_panel)

        self.add(top, BorderLayout.NORTH)

        self.table_model = DecodeReplaceTableModel(armed_target, decode_replace_settings)
        self.table = JTable(self.table_model)
        self.row_sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.row_sorter)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_RowSelectionListener(self))
        self.table_model.addTableModelListener(_TableChangeListener(self))
        self._configure_editors()

        filter_row = JPanel(FlowLayout(FlowLayout.LEFT))
        filter_row.add(JLabel("Filter (path contains):"))
        self.filter_field = JTextField(30)
        self.filter_field.getDocument().addDocumentListener(_FilterListener(self))
        filter_row.add(self.filter_field)
        self.match_count_label = JLabel("")
        filter_row.add(self.match_count_label)

        # Selecting a row shows its full Original Value alongside a live
        # preview of that value decoded with the row's current Codec
        # choice -- lets the user confirm the Codec is right (and see
        # what Find/Replace will actually operate on) before wiring up a
        # rule.
        self.original_value_detail, original_scroll = _make_detail_area()
        self.decoded_value_detail, decoded_scroll = _make_detail_area()
        detail_panel = JPanel(BorderLayout())
        original_block = JPanel(BorderLayout())
        original_block.add(JLabel("Original Value (full):"), BorderLayout.NORTH)
        original_block.add(original_scroll, BorderLayout.CENTER)
        decoded_block = JPanel(BorderLayout())
        decoded_block.add(JLabel("Decoded Value (using selected Codec):"), BorderLayout.NORTH)
        decoded_block.add(decoded_scroll, BorderLayout.CENTER)
        detail_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, original_block, decoded_block)
        detail_split.setResizeWeight(0.5)
        detail_panel.add(detail_split, BorderLayout.CENTER)

        # A standalone left-to-right decoder. It is deliberately separate
        # from the row's rule Codec so pasted inspection text never changes
        # how an insertion point will be rewritten on send.
        selection_panel = JPanel(BorderLayout())
        selection_controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.selection_codec_combo = JComboBox(list(codec_engine.CODEC_NAMES))
        self.selection_codec_combo.setEditable(True)
        self.selection_decode_button = JButton("Decode pasted text", actionPerformed=self._on_selection_decode)
        selection_controls.add(JLabel("Decode chain:"))
        selection_controls.add(self.selection_codec_combo)
        selection_controls.add(self.selection_decode_button)
        selection_controls.add(JLabel("3+ layers: URL -> Base64 -> URL"))
        self.selection_input_detail, selection_input_scroll = _make_detail_area()
        self.selection_input_detail.setEditable(True)
        self.selection_decode_detail, selection_result_scroll = _make_detail_area()
        input_block = JPanel(BorderLayout())
        input_block.add(JLabel("Paste text to decode:"), BorderLayout.NORTH)
        input_block.add(selection_input_scroll, BorderLayout.CENTER)
        result_block = JPanel(BorderLayout())
        result_block.add(JLabel("Decoded result:"), BorderLayout.NORTH)
        result_block.add(selection_result_scroll, BorderLayout.CENTER)
        selection_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, input_block, result_block)
        selection_split.setResizeWeight(0.5)
        selection_panel.add(selection_controls, BorderLayout.NORTH)
        selection_panel.add(selection_split, BorderLayout.CENTER)
        detail_panel.add(selection_panel, BorderLayout.SOUTH)
        detail_panel.setPreferredSize(Dimension(100, 245))

        table_panel = JPanel(BorderLayout())
        table_panel.add(filter_row, BorderLayout.NORTH)
        table_panel.add(JScrollPane(self.table), BorderLayout.CENTER)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_panel, detail_panel)
        main_split.setResizeWeight(0.7)
        self.add(main_split, BorderLayout.CENTER)
        self._apply_filter()

    def _configure_editors(self):
        codec_col = self.table.getColumnModel().getColumn(5)
        codec_combo = JComboBox(list(codec_engine.CODEC_NAMES))
        codec_combo.setEditable(True)
        codec_col.setCellEditor(DefaultCellEditor(codec_combo))

    def _apply_filter(self):
        text = self.filter_field.getText() if self.filter_field.getText() else ""
        if not text:
            self.row_sorter.setRowFilter(None)
        else:
            try:
                self.row_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + re.escape(text), 1))
            except Exception:
                self.row_sorter.setRowFilter(None)
        self._update_match_count()

    def _update_match_count(self):
        self.match_count_label.setText("%d / %d rows" % (
            self.table.getRowCount(), self.table_model.getRowCount()))

    def _on_enabled_toggle(self, event):
        self.settings.enabled = self.enabled_checkbox.isSelected()

    def _on_diagnostics_toggle(self, event):
        self.armed_target.log_diagnostics_for_other_tools = self.diagnostics_checkbox.isSelected()

    def _on_lenient_toggle(self, event):
        self.armed_target.allow_lenient_json = self.lenient_checkbox.isSelected()

    def _on_flag_toggle(self, flag, checkbox):
        if checkbox.isSelected():
            self.settings.enabled_tool_flags.add(flag)
        else:
            self.settings.enabled_tool_flags.discard(flag)

    def _on_selection_decode(self, event):
        selected = self.selection_input_detail.getText()
        if not selected:
            self.selection_decode_detail.setText("Paste text into the left area first.")
            return
        codec_name = self.selection_codec_combo.getEditor().getItem()
        if codec_name is None:
            self.selection_decode_detail.setText("Choose or enter a Decode chain first.")
            return
        try:
            decoded = codec_engine.decode_value(codec_name, selected)
            self.selection_decode_detail.setText(decoded)
        except Exception as e:
            self.selection_decode_detail.setText(
                u"(decode failed with Codec=%s: %s)" % (codec_name, e))
        self.selection_decode_detail.setCaretPosition(0)

    def _refresh_detail(self):
        row = self.table.getSelectedRow()
        if row < 0 or not (0 <= row < len(self.armed_target.template_points)):
            self.original_value_detail.setText("")
            self.decoded_value_detail.setText("")
            return
        model_row = self.table.convertRowIndexToModel(row)
        if not (0 <= model_row < len(self.armed_target.template_points)):
            return
        p = self.armed_target.template_points[model_row]
        rule = self.settings.get_rule(p.path)
        original = p.original_value if p.original_value is not None else u""
        self.original_value_detail.setText(original)
        self.original_value_detail.setCaretPosition(0)
        try:
            decoded = codec_engine.decode_value(rule.codec, original)
            self.decoded_value_detail.setText(decoded)
        except Exception as e:
            self.decoded_value_detail.setText(u"(decode failed with Codec=%s: %s)" % (rule.codec, e))
        self.decoded_value_detail.setCaretPosition(0)

    def _on_redetect(self, event):
        target = self.armed_target
        if not target.is_armed():
            if self.log_fn:
                self.log_fn("No target armed yet.")
            return
        try:
            def on_detect_error(msg):
                if self.log_fn:
                    self.log_fn("Insertion Point detection: %s" % msg)
                if self.error_fn:
                    self.error_fn("Target & Replace with Decode & Encode: Re-detect", msg)

            lenient_flag = target.allow_lenient_json
            points = detection_engine.detect(self.helpers, target.original_request_bytes, target.http_service,
                                              on_error=on_detect_error, lenient=lenient_flag)
            target.arm(target.connection_signature, points, target.http_service, target.original_request_bytes,
                       label=target.label)
            if self.log_fn:
                self.log_fn("Re-detected %d insertion points." % len(points))
            self.refresh()
        except Exception as e:
            if self.log_fn:
                self.log_fn("Re-detect failed: %s" % e)
            if self.error_fn:
                self.error_fn("Target & Replace with Decode & Encode: Re-detect", to_display_text(e), traceback.format_exc())

    def refresh(self):
        target = self.armed_target
        if target.is_armed():
            self.summary_label.setText("Target: %s  |  %s  |  %d insertion points" % (
                target.label or "?", target.connection_signature, len(target.template_points)))
        else:
            self.summary_label.setText(_NOT_ARMED_TEXT)
        self.table_model.refresh()
        self._apply_filter()
        self._refresh_detail()
