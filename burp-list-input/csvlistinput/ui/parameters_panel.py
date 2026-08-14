# -*- coding: utf-8 -*-
"""Parameters tab: a range-scoped, de-duplicated Proxy History inventory."""

from java.awt import BorderLayout, Color, FlowLayout
from java.lang import Integer
from java.util import Comparator
from java.util.regex import Pattern
from javax.swing import (JButton, JLabel, JPanel, JScrollPane, JTable, JTextField, JSplitPane,
                          JComboBox, JTextArea, ListSelectionModel)
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing import RowFilter

from csvlistinput import decode_engine, parameter_inventory_engine

COLUMNS = ["#", "Identified Parameter", "Occurrences", "Packet Nos"]
VALUE_COLUMNS = ["#", "Value", "Occurrences", "Packet Nos"]
_NONE_DECODE_LABEL = "None"
_DECODE_LABELS = [_NONE_DECODE_LABEL] + [
    label for label in decode_engine.TRANSFORM_LABELS if "Decode" in label or label == "ROT13"]
_HIGH_COLOR = Color(255, 204, 204)
_MEDIUM_COLOR = Color(255, 239, 184)


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
        return Integer if col in (0, 2) else str

    def row_at(self, row):
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0:
            return Integer(row + 1)
        if col == 1:
            return entry['path']
        if col == 2:
            return Integer(entry['count'])
        if col == 3:
            return ','.join(str(no) for no in entry['packet_nos'])
        return None


class _RiskRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column)
        if is_selected:
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
        return Integer if col in (0, 2) else str

    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0:
            return Integer(row + 1)
        if col == 1:
            return entry['value']
        if col == 2:
            return Integer(entry['count'])
        if col == 3:
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
        self.clear_button = JButton("Clear", actionPerformed=self._on_clear)
        top.add(self.clear_button)
        top.add(JLabel("Red: authorization/money/account fields   Yellow: tokens, identifiers, PII candidates"))
        self.add(top, BorderLayout.NORTH)

        self.table_model = ParametersTableModel()
        self.table = JTable(self.table_model)
        self.table_sorter = TableRowSorter(self.table_model)
        self.table_sorter.setComparator(3, _PacketNosComparator())
        self.table.setRowSorter(self.table_sorter)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        renderer = _RiskRenderer()
        for column in range(len(COLUMNS)):
            self.table.getColumnModel().getColumn(column).setCellRenderer(renderer)
        self.table.getSelectionModel().addListSelectionListener(_ParameterSelectionListener(self))

        self.values_table_model = ParameterValuesTableModel()
        self.values_table = JTable(self.values_table_model)
        self.values_table_sorter = TableRowSorter(self.values_table_model)
        self.values_table_sorter.setComparator(3, _PacketNosComparator())
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
        values_header.add(JLabel("Decode selected value:"))
        self.decode_combo = JComboBox(_DECODE_LABELS)
        self.decode_combo.setSelectedItem(_NONE_DECODE_LABEL)
        self.decode_combo.addActionListener(self._on_decode_changed)
        values_header.add(self.decode_combo)
        values_panel.add(values_header, BorderLayout.NORTH)
        values_center = JPanel(BorderLayout())
        values_center.add(JScrollPane(self.values_table), BorderLayout.CENTER)
        self.decoded_value_area = JTextArea(2, 30)
        self.decoded_value_area.setEditable(False)
        self.decoded_value_area.setLineWrap(True)
        self.decoded_value_area.setWrapStyleWord(False)
        decoded_panel = JPanel(BorderLayout())
        decoded_panel.add(JLabel("Decoded Value:"), BorderLayout.NORTH)
        decoded_panel.add(JScrollPane(self.decoded_value_area), BorderLayout.CENTER)
        values_center.add(decoded_panel, BorderLayout.SOUTH)
        values_panel.add(values_center, BorderLayout.CENTER)

        parameter_list_panel = JPanel(BorderLayout())
        parameter_filter = JPanel(FlowLayout(FlowLayout.LEFT))
        parameter_filter.add(JLabel("Find parameters:"))
        self.parameter_filter_field = JTextField(24)
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
            return None, None, str(e)
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
        start_packet_no, end_packet_no, error = self._selected_range()
        if error:
            self.status_label.setText(error)
            return
        try:
            rows = parameter_inventory_engine.collect(
                self.callbacks, self.helpers, start_packet_no, end_packet_no)
        except Exception as e:
            self.status_label.setText("Parameter inventory failed: %s" % e)
            if self.error_fn:
                self.error_fn("Parameters", "Parameter inventory failed: %s" % e)
            return
        self.table_model.set_rows(rows)
        self.values_table_model.set_rows([])
        self.values_label.setText("Select a parameter above to display its unique values.")
        self.decoded_value_area.setText("")
        high = sum(1 for row in rows if row['risk'] == 'high')
        medium = sum(1 for row in rows if row['risk'] == 'medium')
        self.status_label.setText("%d unique parameter(s) in %s (red: %d, yellow: %d)." % (
            len(rows), self._range_label(start_packet_no, end_packet_no), high, medium))
        if self.log_fn:
            self.log("Parameters: %d unique parameter(s) inventoried from %s." % (
                len(rows), self._range_label(start_packet_no, end_packet_no)))

    def _on_clear(self, event):
        self.table_model.set_rows([])
        self.values_table_model.set_rows([])
        self.parameter_filter_field.setText("")
        self.value_filter_field.setText("")
        self.values_label.setText("Select a parameter above to display its unique values.")
        self.decoded_value_area.setText("")
        self.status_label.setText("Cleared.")

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
        label = str(self.decode_combo.getSelectedItem())
        if label == _NONE_DECODE_LABEL:
            result_text = row['value']
        else:
            result = decode_engine.run_all(row['value'], enabled_labels=[label])[0]
            result_text = result.text if result.ok() else "(%s)" % result.error
        self.decoded_value_area.setText(result_text)
        self.decoded_value_area.setCaretPosition(0)

    def _apply_filter(self, which):
        field = self.parameter_filter_field if which == 'parameters' else self.value_filter_field
        sorter = self.table_sorter if which == 'parameters' else self.values_table_sorter
        query = field.getText()
        if not query:
            sorter.setRowFilter(None)
            return
        # Treat text literally, so a parameter value such as ``[1]`` or
        # ``?`` never becomes an invalid Java regular expression.
        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(str(query))))
