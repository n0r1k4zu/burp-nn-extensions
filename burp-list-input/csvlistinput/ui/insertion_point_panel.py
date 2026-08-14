# -*- coding: utf-8 -*-
"""Insertion Point list + CSV column mapping table (requirement (3))."""

import re

from java.awt import BorderLayout, Dimension, FlowLayout
from java.lang import Integer
from javax.swing import (DefaultCellEditor, JComboBox, JLabel, JPanel, JScrollPane, JSplitPane, JTable,
                          JTextArea, JTextField, ListSelectionModel, RowFilter, ScrollPaneConstants)
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.table import AbstractTableModel, TableRowSorter

from csvlistinput.constants import EscapeMode
from csvlistinput.substitution_engine import is_ancestor_path

COLUMNS = ["Insertion Points", "Type", "Nesting", "Original Value", "Mapped Column", "Escape Mode"]
UNMAPPED = "(unmapped)"


class InsertionPointTableModel(AbstractTableModel):
    def __init__(self, armed_target, csv_store):
        AbstractTableModel.__init__(self)
        self.armed_target = armed_target
        self.csv_store = csv_store

    def getRowCount(self):
        return len(self.armed_target.template_points)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getColumnClass(self, col):
        return Integer if col == 2 else str

    def _point(self, row):
        return self.armed_target.template_points[row]

    def getValueAt(self, row, col):
        p = self._point(row)
        if col == 0:
            return p.path
        if col == 1:
            return (p.type + " (recovered)") if p.recovered else p.type
        if col == 2:
            return Integer(p.nesting_depth)
        if col == 3:
            preview = p.original_value if p.original_value is not None else ""
            preview = preview.replace("\n", "\\n").replace("\r", "\\r")
            if len(preview) > 80:
                preview = preview[:77] + "..."
            return preview
        if col == 4:
            return self.armed_target.get_mapping(p.path) or UNMAPPED
        if col == 5:
            return self.armed_target.get_escape_override(p.path)
        return None

    def _has_conflict(self, row):
        """True if some OTHER already-mapped point is an ancestor or
        descendant of this one (overlapping byte ranges once a live
        buffer exists) -- mapping both simultaneously is nonsensical."""
        p = self._point(row)
        if self.armed_target.get_mapping(p.path):
            return False  # already mapped itself; let the user unmap it freely
        mapped_others = [k for k, v in self.armed_target.mapping.items() if v and k != p.path]
        return any(is_ancestor_path(k, p.path) or is_ancestor_path(p.path, k) for k in mapped_others)

    def isCellEditable(self, row, col):
        if col == 4:
            return not self._has_conflict(row)
        if col == 5:
            return True
        return False

    def setValueAt(self, value, row, col):
        p = self._point(row)
        if col == 4:
            self.armed_target.set_mapping(p.path, None if value == UNMAPPED else value)
            self.fireTableDataChanged()  # other rows' conflict-disabled state may have changed
        elif col == 5:
            self.armed_target.set_escape_override(p.path, value)
            self.fireTableCellUpdated(row, col)

    def refresh(self):
        self.fireTableDataChanged()


class _FilterListener(DocumentListener):
    def __init__(self, panel):
        self.panel = panel

    def insertUpdate(self, event):
        self.panel._apply_filter()

    def removeUpdate(self, event):
        self.panel._apply_filter()

    def changedUpdate(self, event):
        self.panel._apply_filter()


class _RowSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        self.panel._on_selection_changed()


def _make_detail_area():
    area = JTextArea(3, 40)
    area.setEditable(False)
    area.setLineWrap(True)
    area.setWrapStyleWord(False)  # paths/values have no natural word breaks; wrap at any character
    scroll = JScrollPane(area)
    scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER)
    return area, scroll


class InsertionPointPanel(JPanel):
    def __init__(self, armed_target, csv_store):
        JPanel.__init__(self, BorderLayout())
        self.armed_target = armed_target
        self.csv_store = csv_store
        self.table_model = InsertionPointTableModel(armed_target, csv_store)
        self.table = JTable(self.table_model)
        self.row_sorter = TableRowSorter(self.table_model)
        self.table.setRowSorter(self.row_sorter)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(_RowSelectionListener(self))
        self._configure_editors()

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Filter (path contains):"))
        self.filter_field = JTextField(30)
        self.filter_field.getDocument().addDocumentListener(_FilterListener(self))
        top.add(self.filter_field)
        self.match_count_label = JLabel("")
        top.add(self.match_count_label)
        self.add(top, BorderLayout.NORTH)

        # Table cells truncate long paths/values for display -- selecting a
        # row mirrors its full, untruncated Path and Original Value here so
        # they're actually readable (and selectable/copyable) regardless of
        # length.
        self.path_detail, path_scroll = _make_detail_area()
        self.value_detail, value_scroll = _make_detail_area()
        detail_panel = JPanel(BorderLayout())
        path_block = JPanel(BorderLayout())
        path_block.add(JLabel("Path (full):"), BorderLayout.NORTH)
        path_block.add(path_scroll, BorderLayout.CENTER)
        value_block = JPanel(BorderLayout())
        value_block.add(JLabel("Original Value (full):"), BorderLayout.NORTH)
        value_block.add(value_scroll, BorderLayout.CENTER)
        detail_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, path_block, value_block)
        detail_split.setResizeWeight(0.5)
        detail_panel.add(detail_split, BorderLayout.CENTER)
        detail_panel.setPreferredSize(Dimension(100, 110))

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), detail_panel)
        main_split.setResizeWeight(0.75)
        self.add(main_split, BorderLayout.CENTER)
        self._apply_filter()

    def _configure_editors(self):
        mapped_col = self.table.getColumnModel().getColumn(4)
        combo = JComboBox([UNMAPPED] + self.csv_store.get_column_names())
        mapped_col.setCellEditor(DefaultCellEditor(combo))

        escape_col = self.table.getColumnModel().getColumn(5)
        escape_combo = JComboBox(list(EscapeMode.ALL))
        escape_col.setCellEditor(DefaultCellEditor(escape_combo))

    def _apply_filter(self):
        text = self.filter_field.getText() if self.filter_field.getText() else ""
        if not text:
            self.row_sorter.setRowFilter(None)
        else:
            try:
                self.row_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + re.escape(text), 0))
            except Exception:
                self.row_sorter.setRowFilter(None)
        self._update_match_count()

    def _update_match_count(self):
        self.match_count_label.setText("%d / %d rows" % (self.table.getRowCount(), self.table_model.getRowCount()))

    def _on_selection_changed(self):
        view_row = self.table.getSelectedRow()
        if view_row < 0:
            self.path_detail.setText("")
            self.value_detail.setText("")
            return
        model_row = self.table.convertRowIndexToModel(view_row)
        if not (0 <= model_row < len(self.armed_target.template_points)):
            return
        p = self.armed_target.template_points[model_row]
        self.path_detail.setText(p.path)
        self.value_detail.setText(p.original_value if p.original_value is not None else "")
        self.path_detail.setCaretPosition(0)
        self.value_detail.setCaretPosition(0)

    def refresh(self):
        self._configure_editors()  # CSV column list may have changed since last load
        self.table_model.refresh()
        self._update_match_count()
