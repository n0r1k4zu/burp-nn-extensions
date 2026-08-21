# -*- coding: utf-8 -*-
"""Parameters tab: a range-scoped, de-duplicated Proxy History inventory."""

from threading import Thread

from java.awt import BorderLayout, Color, FlowLayout
from java.awt.event import ActionListener
from java.lang import Integer, Runnable
from java.util import Comparator
from java.util.regex import Pattern
from javax.swing import (JButton, JCheckBox, JLabel, JPanel, JScrollPane, JTable, JTextField, JSplitPane,
                          JComboBox, JTextArea, ListSelectionModel, SwingUtilities, Timer)
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing import RowFilter

from csvlistinput import codec_engine, parameter_inventory_engine
from csvlistinput.utils import to_display_text

COLUMNS = ["#", "Group", "Region", "Identified Parameter", "Occurrences", "Packet No"]
VALUE_COLUMNS = ["#", "Group", "Region", "Value", "Occurrences", "Packet No"]
_NONE_DECODE_LABEL = "None"
_CODEC_LAYER_LABELS = ["None", "URL", "Base64", "Hex", "HTML Entity", "Unicode \\uXXXX", "ROT13"]
_HIGH_COLOR = Color(255, 204, 204)
_MEDIUM_COLOR = Color(255, 239, 184)


class _UiRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


class ParametersTableModel(AbstractTableModel):
    def __init__(self):
        AbstractTableModel.__init__(self)
        self.rows = []

    def set_rows(self, rows):
        self.rows = rows
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getColumnClass(self, col):
        return Integer if col in (0, 4) else str

    def row_at(self, row):
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0:
            return Integer(row + 1)
        if col == 1:
            return ', '.join(entry.get('groups', []))
        if col == 2:
            return ', '.join(entry.get('regions', []))
        if col == 3:
            return entry['path']
        if col == 4:
            return Integer(entry['count'])
        if col == 5:
            return ','.join(str(no) for no in entry['packet_nos'])
        return None


class _RiskRenderer(DefaultTableCellRenderer):
    def __init__(self, panel):
        DefaultTableCellRenderer.__init__(self)
        self.panel = panel

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column)
        if is_selected:
            return component
        # Focus controls presentation only.  Risk classification can still
        # be calculated by Aggressive mode while Focus is off.
        if not self.panel.focus_checkbox.isSelected():
            component.setForeground(Color.WHITE)
            component.setBackground(table.getBackground())
            return component
        entry = table.getModel().row_at(table.convertRowIndexToModel(row))
        if entry and entry['risk'] == 'high':
            component.setForeground(Color.BLACK)
            component.setBackground(_HIGH_COLOR)
        elif entry and entry['risk'] == 'medium':
            component.setForeground(Color.BLACK)
            component.setBackground(_MEDIUM_COLOR)
        else:
            # Burp's dark theme uses a black table background; explicitly
            # restore a readable foreground for unhighlighted rows.
            component.setForeground(Color.WHITE)
            component.setBackground(table.getBackground())
        return component


class ParameterValuesTableModel(AbstractTableModel):
    def __init__(self):
        AbstractTableModel.__init__(self)
        self.rows = []

    def set_rows(self, rows):
        self.rows = rows
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(VALUE_COLUMNS)

    def getColumnName(self, col):
        return VALUE_COLUMNS[col]

    def getColumnClass(self, col):
        return Integer if col in (0, 4) else str

    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0:
            return Integer(row + 1)
        if col == 1:
            return ', '.join(entry.get('groups', []))
        if col == 2:
            return ', '.join(entry.get('regions', []))
        if col == 3:
            return entry['value']
        if col == 4:
            return Integer(entry['count'])
        if col == 5:
            return ','.join(str(no) for no in entry['packet_nos'])
        return None


class _ParameterSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.panel._show_selected_values()


class _ValueSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.panel._update_decoded_value()


class _FilterListener(DocumentListener):
    def __init__(self, panel, which):
        self.panel = panel
        self.which = which

    def insertUpdate(self, event):
        self.panel._apply_filter(self.which)

    def removeUpdate(self, event):
        self.panel._apply_filter(self.which)

    def changedUpdate(self, event):
        self.panel._apply_filter(self.which)


class _ManualDecodeListener(DocumentListener):
    def __init__(self, panel):
        self.panel = panel

    def insertUpdate(self, event):
        self.panel._update_manual_decode()

    def removeUpdate(self, event):
        self.panel._update_manual_decode()

    def changedUpdate(self, event):
        self.panel._update_manual_decode()


class _FilterTimerListener(ActionListener):
    """Jython-compatible adapter for javax.swing.Timer's Java constructor."""
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._on_filter_timer(event)


class _PacketNosComparator(Comparator):
    """Sort comma-separated Packet Nos as integer sequences, not text."""
    def compare(self, left, right):
        def numbers(value):
            try:
                return [int(part) for part in str(value).split(',') if part]
            except ValueError:
                return []
        a = numbers(left)
        b = numbers(right)
        return (a > b) - (a < b)


class ParametersPanel(JPanel):
    def __init__(self, callbacks, helpers, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.log_fn = log_fn
        self.error_fn = error_fn
        self.start_packet_no = None
        self.end_packet_no = None
        self._scan_worker = None
        self._cancel_requested = False
        self._pending_filters = set()
        self._filter_timer = Timer(180, _FilterTimerListener(self))
        self._filter_timer.setRepeats(False)

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Packet No range:"))
        self.start_packet_field = JTextField(6)
        self.start_packet_field.setToolTipText("Start packet number (blank: first packet)")
        top.add(self.start_packet_field)
        top.add(JLabel("to"))
        self.end_packet_field = JTextField(6)
        self.end_packet_field.setToolTipText("End packet number (blank: last packet)")
        top.add(self.end_packet_field)
        self.all_button = JButton("All", actionPerformed=self._on_all_history)
        self.all_button.setToolTipText("Use all HTTP History packets")
        top.add(self.all_button)
        self.scan_button = JButton("Build parameter list", actionPerformed=self._on_scan)
        top.add(self.scan_button)
        self.cancel_button = JButton("Cancel", actionPerformed=self._on_cancel)
        self.cancel_button.setEnabled(False)
        top.add(self.cancel_button)
        self.clear_button = JButton("Clear", actionPerformed=self._on_clear)
        top.add(self.clear_button)
        self.focus_checkbox = JCheckBox(
            "Focus (color noteworthy parameters)", False,
            actionPerformed=self._on_focus_toggle)
        self.focus_checkbox.setToolTipText("Color high-risk candidates red and medium-risk candidates yellow.")
        top.add(self.focus_checkbox)
        self.aggressive_checkbox = JCheckBox(
            "Aggressive (broader candidate detection)", False,
            actionPerformed=self._on_aggressive_toggle)
        self.aggressive_checkbox.setToolTipText(
            "Broaden name heuristics for authorization, money, authentication and PII candidates.")
        top.add(self.aggressive_checkbox)
        top.add(JLabel("Focus colors: red = high impact, yellow = candidate"))
        self.add(top, BorderLayout.NORTH)

        self.table_model = ParametersTableModel()
        self.table = JTable(self.table_model)
        self.table_sorter = TableRowSorter(self.table_model)
        self.table_sorter.setComparator(5, _PacketNosComparator())
        self.table.setRowSorter(self.table_sorter)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        renderer = _RiskRenderer(self)
        for column in range(len(COLUMNS)):
            self.table.getColumnModel().getColumn(column).setCellRenderer(renderer)
        self.table.getSelectionModel().addListSelectionListener(_ParameterSelectionListener(self))

        self.values_table_model = ParameterValuesTableModel()
        self.values_table = JTable(self.values_table_model)
        self.values_table_sorter = TableRowSorter(self.values_table_model)
        self.values_table_sorter.setComparator(5, _PacketNosComparator())
        self.values_table.setRowSorter(self.values_table_sorter)
        self.values_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.values_table.getSelectionModel().addListSelectionListener(_ValueSelectionListener(self))
        values_panel = JPanel(BorderLayout())
        values_header = JPanel(FlowLayout(FlowLayout.LEFT))
        self.values_label = JLabel("Select a parameter above to display its unique values.")
        values_header.add(self.values_label)
        values_header.add(JLabel("Find values:"))
        self.value_filter_field = JTextField(16)
        self.value_filter_field.getDocument().addDocumentListener(_FilterListener(self, 'values'))
        values_header.add(self.value_filter_field)
        values_header.add(JLabel("Selected value Decode:"))
        values_header.add(JLabel("Outer:"))
        self.decode_outer_combo = JComboBox(_CODEC_LAYER_LABELS)
        self.decode_outer_combo.setSelectedItem(_NONE_DECODE_LABEL)
        self.decode_outer_combo.addActionListener(self._on_decode_changed)
        values_header.add(self.decode_outer_combo)
        values_header.add(JLabel("Inner:"))
        self.decode_inner_combo = JComboBox(_CODEC_LAYER_LABELS)
        self.decode_inner_combo.setSelectedItem(_NONE_DECODE_LABEL)
        self.decode_inner_combo.addActionListener(self._on_decode_changed)
        values_header.add(self.decode_inner_combo)
        values_panel.add(values_header, BorderLayout.NORTH)
        self.decoded_value_area = JTextArea(6, 60)
        self.decoded_value_area.setEditable(False)
        self.decoded_value_area.setLineWrap(True)
        self.decoded_value_area.setWrapStyleWord(False)
        decoded_panel = JPanel(BorderLayout())
        decoded_panel.add(JLabel("Decoded Value:"), BorderLayout.NORTH)
        decoded_panel.add(JScrollPane(self.decoded_value_area), BorderLayout.CENTER)
        selected_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.values_table), decoded_panel)
        selected_split.setResizeWeight(0.62)
        selected_split.setOneTouchExpandable(True)
        values_panel.add(selected_split, BorderLayout.CENTER)

        # Independent paste-and-decode workbench.  This is deliberately below
        # the selected-value preview so users can inspect arbitrary text
        # without changing the selected parameter/value row.
        manual_panel = JPanel(BorderLayout())
        manual_header = JPanel(FlowLayout(FlowLayout.LEFT))
        manual_header.add(JLabel("Manual Decode (paste left -> result right):"))
        manual_header.add(JLabel("Outer:"))
        self.manual_outer_combo = JComboBox(_CODEC_LAYER_LABELS)
        self.manual_outer_combo.setSelectedItem(_NONE_DECODE_LABEL)
        self.manual_outer_combo.addActionListener(self._on_manual_decode_changed)
        manual_header.add(self.manual_outer_combo)
        manual_header.add(JLabel("Inner:"))
        self.manual_inner_combo = JComboBox(_CODEC_LAYER_LABELS)
        self.manual_inner_combo.setSelectedItem(_NONE_DECODE_LABEL)
        self.manual_inner_combo.addActionListener(self._on_manual_decode_changed)
        manual_header.add(self.manual_inner_combo)
        manual_panel.add(manual_header, BorderLayout.NORTH)
        self.manual_input_area = JTextArea(5, 40)
        self.manual_input_area.setLineWrap(True); self.manual_input_area.setWrapStyleWord(False)
        self.manual_input_area.getDocument().addDocumentListener(_ManualDecodeListener(self))
        self.manual_output_area = JTextArea(5, 40)
        self.manual_output_area.setEditable(False)
        self.manual_output_area.setLineWrap(True); self.manual_output_area.setWrapStyleWord(False)
        manual_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.manual_input_area),
                                  JScrollPane(self.manual_output_area))
        manual_split.setResizeWeight(0.5); manual_split.setOneTouchExpandable(True)
        manual_panel.add(manual_split, BorderLayout.CENTER)
        values_panel.add(manual_panel, BorderLayout.SOUTH)

        parameter_list_panel = JPanel(BorderLayout())
        parameter_filter = JPanel(FlowLayout(FlowLayout.LEFT))
        parameter_filter.add(JLabel("Find in results:"))
        self.parameter_filter_field = JTextField(24)
        self.parameter_filter_field.setToolTipText(
            "Filter the current parameter result rows; this does not rebuild the parameter inventory.")
        self.parameter_filter_field.getDocument().addDocumentListener(_FilterListener(self, 'parameters'))
        parameter_filter.add(self.parameter_filter_field)
        parameter_list_panel.add(parameter_filter, BorderLayout.NORTH)
        parameter_list_panel.add(JScrollPane(self.table), BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, parameter_list_panel, values_panel)
        split.setResizeWeight(0.55)
        self.add(split, BorderLayout.CENTER)

        self.status_label = JLabel("Range: all HTTP History. Build parameter list to scan request parameters.")
        self.add(self.status_label, BorderLayout.SOUTH)

    def _selected_range(self):
        try:
            start_packet_no = self._parse_packet_no(self.start_packet_field.getText(), "Start")
            end_packet_no = self._parse_packet_no(self.end_packet_field.getText(), "End")
            if (start_packet_no is not None and end_packet_no is not None
                    and start_packet_no > end_packet_no):
                raise ValueError("Start Packet No must not exceed End Packet No.")
        except ValueError as e:
            return None, None, to_display_text(e)
        return start_packet_no, end_packet_no, None

    def _on_all_history(self, event):
        self.start_packet_no = None
        self.end_packet_no = None
        self.start_packet_field.setText("")
        self.end_packet_field.setText("")
        self.status_label.setText("Range set to all HTTP History.")

    def _parse_packet_no(self, value, label):
        value = str(value).strip()
        if not value:
            return None
        try:
            number = int(value)
        except ValueError:
            raise ValueError("%s Packet No must be a positive integer." % label)
        if number < 1:
            raise ValueError("%s Packet No must be a positive integer." % label)
        return number

    def _range_label(self, start_packet_no=None, end_packet_no=None):
        if start_packet_no is None and end_packet_no is None:
            return "all HTTP History"
        return "Packet No %s to %s" % (start_packet_no if start_packet_no is not None else "first",
                                        end_packet_no if end_packet_no is not None else "last")

    def _on_scan(self, event):
        if self._scan_worker is not None:
            return
        start_packet_no, end_packet_no, error = self._selected_range()
        if error:
            self.status_label.setText(error)
            return
        self._cancel_requested = False
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Building...")
        self.cancel_button.setEnabled(True)
        self.cancel_button.setText("Cancel build")
        self.status_label.setText("Building parameter list in the background...")
        self._scan_worker = Thread(target=self._scan_worker_run,
                                    args=(start_packet_no, end_packet_no))
        self._scan_worker.setDaemon(True)
        self._scan_worker.start()

    def _scan_worker_run(self, start_packet_no, end_packet_no):
        try:
            rows = parameter_inventory_engine.collect(
                self.callbacks, self.helpers, start_packet_no, end_packet_no,
                cancel_check=lambda: self._cancel_requested,
                aggressive_focus=self.aggressive_checkbox.isSelected())
            cancelled = self._cancel_requested
            SwingUtilities.invokeLater(_UiRunnable(
                lambda: self._scan_finished(rows, cancelled, start_packet_no, end_packet_no)))
        except Exception as e:
            SwingUtilities.invokeLater(_UiRunnable(lambda error=e: self._scan_failed(error)))

    def _restore_scan_buttons(self):
        self._scan_worker = None
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Build parameter list")
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText("Cancel")

    def _scan_finished(self, rows, cancelled, start_packet_no, end_packet_no):
        self.table_model.set_rows(rows)
        self.values_table_model.set_rows([])
        self.values_label.setText("Select a parameter above to display its unique values.")
        self.decoded_value_area.setText("")
        high = sum(1 for row in rows if row['risk'] == 'high')
        medium = sum(1 for row in rows if row['risk'] == 'medium')
        self._restore_scan_buttons()
        prefix = "Cancelled: " if cancelled else ""
        self.status_label.setText("%s%d unique parameter(s) in %s (red: %d, yellow: %d)." % (
            prefix,
            len(rows), self._range_label(start_packet_no, end_packet_no), high, medium))
        if self.log_fn:
            self.log("Parameters: %d unique parameter(s) inventoried from %s." % (
                len(rows), self._range_label(start_packet_no, end_packet_no)))

    def _scan_failed(self, error):
        self._restore_scan_buttons()
        self.status_label.setText("Parameter inventory failed: %s" % error)
        if self.error_fn:
            self.error_fn("Parameters", "Parameter inventory failed: %s" % error)

    def _on_cancel(self, event):
        if self._scan_worker is None:
            return
        self._cancel_requested = True
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText("Stopping...")
        self.status_label.setText("Cancel requested; finishing the current packet...")

    def _on_clear(self, event):
        self.table_model.set_rows([])
        self.values_table_model.set_rows([])
        self.parameter_filter_field.setText("")
        self.value_filter_field.setText("")
        self.values_label.setText("Select a parameter above to display its unique values.")
        self.decoded_value_area.setText("")
        self.status_label.setText("Cleared.")

    def _on_focus_toggle(self, event):
        """Toggle coloring without changing the underlying classification."""
        self.table.repaint()
        self.status_label.setText("Focus %s." % ("enabled" if self.focus_checkbox.isSelected() else "disabled"))

    def _on_aggressive_toggle(self, event):
        """Reclassify current rows immediately; the next build uses it too."""
        aggressive = self.aggressive_checkbox.isSelected()
        for row in self.table_model.rows:
            row['risk'] = parameter_inventory_engine.risk_level(row.get('path', ''), aggressive)
        self.table_model.fireTableDataChanged()
        self.status_label.setText("Aggressive detection %s. Rebuild to rescan the selected range." %
                                  ("enabled" if aggressive else "disabled"))

    def log(self, message):
        self.log_fn(message)

    def _show_selected_values(self):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            self.values_table_model.set_rows([])
            self.values_label.setText("Select a parameter above to display its unique values.")
            self.decoded_value_area.setText("")
            return
        entry = self.table_model.row_at(self.table.convertRowIndexToModel(view_row))
        rows = parameter_inventory_engine.value_rows(entry)
        self.values_table_model.set_rows(rows)
        self.values_label.setText("Values for %s (%d unique value(s)):" % (entry['path'], len(rows)))
        self.decoded_value_area.setText("")

    def _on_decode_changed(self, event):
        self._update_decoded_value()

    def _update_decoded_value(self):
        view_row = self.values_table.getSelectedRow()
        if view_row < 0:
            self.decoded_value_area.setText("")
            return
        row = self.values_table_model.rows[self.values_table.convertRowIndexToModel(view_row)]
        codec_name = self._selected_codec_chain()
        try:
            result_text = row['value'] if codec_name == _NONE_DECODE_LABEL else codec_engine.decode_value(
                codec_name, row['value'])
            result_text = self._display_decoded(result_text)
        except Exception as error:
            result_text = "(decode failed with Codec=%s: %s)" % (codec_name, error)
        self.decoded_value_area.setText(result_text)
        self.decoded_value_area.setCaretPosition(0)

    def _selected_codec_chain(self):
        outer = str(self.decode_outer_combo.getSelectedItem())
        inner = str(self.decode_inner_combo.getSelectedItem())
        if outer == _NONE_DECODE_LABEL:
            return inner
        if inner == _NONE_DECODE_LABEL:
            return outer
        return outer + " -> " + inner

    def _manual_codec_chain(self):
        outer = str(self.manual_outer_combo.getSelectedItem())
        inner = str(self.manual_inner_combo.getSelectedItem())
        if outer == _NONE_DECODE_LABEL:
            return inner
        if inner == _NONE_DECODE_LABEL:
            return outer
        return outer + " -> " + inner

    def _on_manual_decode_changed(self, event):
        self._update_manual_decode()

    def _update_manual_decode(self):
        text = self.manual_input_area.getText()
        if not text:
            self.manual_output_area.setText("")
            return
        codec_name = self._manual_codec_chain()
        try:
            result = text if codec_name == _NONE_DECODE_LABEL else codec_engine.decode_value(codec_name, text)
            self.manual_output_area.setText(self._display_decoded(result))
        except Exception as error:
            self.manual_output_area.setText("(decode failed with Codec=%s: %s)" % (codec_name, error))
        self.manual_output_area.setCaretPosition(0)

    def _display_decoded(self, value):
        if value is None:
            return u''
        try:
            if isinstance(value, unicode):
                return value
        except NameError:
            if isinstance(value, str):
                return value
        try:
            return value.decode('utf-8')
        except Exception:
            try:
                return value.decode('latin-1')
            except Exception:
                return to_display_text(value)

    def _apply_filter(self, which):
        self._pending_filters.add(which)
        self._filter_timer.restart()

    def _on_filter_timer(self, event):
        pending = list(self._pending_filters)
        self._pending_filters.clear()
        for which in pending:
            self._apply_filter_now(which)

    def _apply_filter_now(self, which):
        field = self.parameter_filter_field if which == 'parameters' else self.value_filter_field
        sorter = self.table_sorter if which == 'parameters' else self.values_table_sorter
        query = field.getText()
        if not query:
            sorter.setRowFilter(None)
            return
        # Treat text literally, so a parameter value such as ``[1]`` or
        # ``?`` never becomes an invalid Java regular expression.
        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(to_display_text(query))))
