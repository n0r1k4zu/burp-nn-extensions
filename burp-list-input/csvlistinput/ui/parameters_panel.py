# -*- coding: utf-8 -*-
"""Parameters tab: a range-scoped, de-duplicated Proxy History inventory."""

from java.awt import BorderLayout, Color, FlowLayout
from javax.swing import (JButton, JLabel, JMenuItem, JOptionPane, JPanel, JPopupMenu, JScrollPane, JTable,
                          JSplitPane, ListSelectionModel)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer

from csvlistinput import parameter_inventory_engine

COLUMNS = ["#", "Identified Parameter", "Occurrences", "Packet Nos"]
VALUE_COLUMNS = ["#", "Value", "Occurrences", "Packet Nos"]
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

    def row_at(self, row):
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0:
            return row + 1
        if col == 1:
            return entry['path']
        if col == 2:
            return entry['count']
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

    def getValueAt(self, row, col):
        entry = self.rows[row]
        if col == 0:
            return row + 1
        if col == 1:
            return entry['value']
        if col == 2:
            return entry['count']
        if col == 3:
            return ','.join(str(no) for no in entry['packet_nos'])
        return None


class _ParameterSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.panel._show_selected_values()


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
        # JMenuBar is a top-level window component.  Embedded in Burp's
        # suite-tab JPanel it can break layout/rendering, so expose the
        # same Range sub-menu through an ordinary ASCII-only toolbar button.
        self.range_button = JButton("Range...", actionPerformed=self._show_range_menu)
        self.range_popup = JPopupMenu()
        self.range_popup.add(JMenuItem("Set Packet No range...", actionPerformed=self._on_set_range))
        self.range_popup.add(JMenuItem("All HTTP History", actionPerformed=self._on_all_history))
        top.add(self.range_button)
        self.scan_button = JButton("Build parameter list", actionPerformed=self._on_scan)
        top.add(self.scan_button)
        top.add(JLabel("Red: authorization/money/account fields   Yellow: tokens, identifiers, PII candidates"))
        self.add(top, BorderLayout.NORTH)

        self.table_model = ParametersTableModel()
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        renderer = _RiskRenderer()
        for column in range(len(COLUMNS)):
            self.table.getColumnModel().getColumn(column).setCellRenderer(renderer)
        self.table.getSelectionModel().addListSelectionListener(_ParameterSelectionListener(self))

        self.values_table_model = ParameterValuesTableModel()
        self.values_table = JTable(self.values_table_model)
        self.values_table.setAutoCreateRowSorter(True)
        self.values_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        values_panel = JPanel(BorderLayout())
        self.values_label = JLabel("Select a parameter above to display its unique values.")
        values_panel.add(self.values_label, BorderLayout.NORTH)
        values_panel.add(JScrollPane(self.values_table), BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), values_panel)
        split.setResizeWeight(0.55)
        self.add(split, BorderLayout.CENTER)

        self.status_label = JLabel("Range: all HTTP History. Build parameter list to scan request parameters.")
        self.add(self.status_label, BorderLayout.SOUTH)

    def _show_range_menu(self, event):
        self.range_popup.show(self.range_button, 0, self.range_button.getHeight())

    def _on_set_range(self, event):
        start = JOptionPane.showInputDialog(self, "Start Packet No (blank: first packet):",
                                             "Set Packet No range", JOptionPane.QUESTION_MESSAGE)
        if start is None:
            return
        end = JOptionPane.showInputDialog(self, "End Packet No (blank: last packet):",
                                           "Set Packet No range", JOptionPane.QUESTION_MESSAGE)
        if end is None:
            return
        try:
            self.start_packet_no = self._parse_packet_no(start, "Start")
            self.end_packet_no = self._parse_packet_no(end, "End")
            if (self.start_packet_no is not None and self.end_packet_no is not None
                    and self.start_packet_no > self.end_packet_no):
                raise ValueError("Start Packet No must not exceed End Packet No.")
        except ValueError as e:
            self.status_label.setText(str(e))
            return
        self.status_label.setText("Range set to %s." % self._range_label())

    def _on_all_history(self, event):
        self.start_packet_no = None
        self.end_packet_no = None
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

    def _range_label(self):
        if self.start_packet_no is None and self.end_packet_no is None:
            return "all HTTP History"
        return "Packet No %s to %s" % (self.start_packet_no if self.start_packet_no is not None else "first",
                                        self.end_packet_no if self.end_packet_no is not None else "last")

    def _on_scan(self, event):
        try:
            rows = parameter_inventory_engine.collect(
                self.callbacks, self.helpers, self.start_packet_no, self.end_packet_no)
        except Exception as e:
            self.status_label.setText("Parameter inventory failed: %s" % e)
            if self.error_fn:
                self.error_fn("Parameters", "Parameter inventory failed: %s" % e)
            return
        self.table_model.set_rows(rows)
        self.values_table_model.set_rows([])
        self.values_label.setText("Select a parameter above to display its unique values.")
        high = sum(1 for row in rows if row['risk'] == 'high')
        medium = sum(1 for row in rows if row['risk'] == 'medium')
        self.status_label.setText("%d unique parameter(s) in %s (red: %d, yellow: %d)." % (
            len(rows), self._range_label(), high, medium))
        if self.log_fn:
            self.log("Parameters: %d unique parameter(s) inventoried from %s." % (len(rows), self._range_label()))

    def log(self, message):
        self.log_fn(message)

    def _show_selected_values(self):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            self.values_table_model.set_rows([])
            self.values_label.setText("Select a parameter above to display its unique values.")
            return
        entry = self.table_model.row_at(self.table.convertRowIndexToModel(view_row))
        rows = parameter_inventory_engine.value_rows(entry)
        self.values_table_model.set_rows(rows)
        self.values_label.setText("Values for %s (%d unique value(s)):" % (entry['path'], len(rows)))
