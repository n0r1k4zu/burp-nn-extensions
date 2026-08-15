# -*- coding: utf-8 -*-
"""Match & Replace tab: master enable toggle (7), tool-flag selection (4),
packet-region scope shared by both lists (5), and left/right request/
response rule tables (1)(2)(3)."""

from java.awt import BorderLayout, FlowLayout, GridLayout
from java.awt.event import ActionListener
from java.lang import Boolean, String
from javax.swing import (BoxLayout, JButton, JCheckBox, JComboBox, JFileChooser, JLabel, JPanel,
                          JScrollPane, JSplitPane, JTable, ListSelectionModel)
from javax.swing.table import AbstractTableModel

from csvlistinput.constants import TOOL_FLAG_LABELS

COLUMNS = ["Enabled", "Regex", "Before", "After"]


class ReplaceRuleTableModel(AbstractTableModel):
    """Reads/writes the ReplaceRuleStore directly (same discipline as
    csv_panel.CsvTableModel) -- a cell edit takes effect on the next
    processed message, not just in the display."""

    def __init__(self, store):
        AbstractTableModel.__init__(self)
        self.store = store

    def getRowCount(self):
        return len(self.store.rules)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getColumnClass(self, col):
        return Boolean if col in (0, 1) else String

    def getValueAt(self, row, col):
        rule = self.store.rules[row]
        if col == 0:
            return rule.enabled
        if col == 1:
            return rule.is_regex
        if col == 2:
            return rule.before
        if col == 3:
            return rule.after
        return None

    def isCellEditable(self, row, col):
        return True

    def setValueAt(self, value, row, col):
        field = ["enabled", "is_regex", "before", "after"][col]
        self.store.set_field(row, field, value)
        self.fireTableCellUpdated(row, col)

    def refresh(self):
        self.fireTableDataChanged()


class _RuleListPanel(JPanel):
    def __init__(self, title, store):
        JPanel.__init__(self, BorderLayout())
        self.store = store
        self.table_model = ReplaceRuleTableModel(store)
        self.table = JTable(self.table_model)
        self.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel(title))
        self.add_button = JButton("Add rule", actionPerformed=self._on_add)
        self.remove_button = JButton("Remove selected", actionPerformed=self._on_remove)
        self.load_button = JButton("Load CSV...", actionPerformed=self._on_load)
        self.save_button = JButton("Export CSV...", actionPerformed=self._on_save)
        self.encoding_combo = JComboBox(["utf-8", "shift_jis", "cp932", "utf-8-sig"])
        top.add(self.add_button)
        top.add(self.remove_button)
        top.add(self.load_button)
        top.add(self.save_button)
        top.add(JLabel("Encoding:"))
        top.add(self.encoding_combo)
        self.status_label = JLabel("")
        top.add(self.status_label)

        self.add(top, BorderLayout.NORTH)
        self.add(JScrollPane(self.table), BorderLayout.CENTER)

    def _stop_editing(self):
        if self.table.isEditing():
            self.table.getCellEditor().stopCellEditing()

    def _on_add(self, event):
        self._stop_editing()
        self.store.add_rule()
        self.table_model.refresh()

    def _on_remove(self, event):
        self._stop_editing()
        rows = sorted(self.table.getSelectedRows(), reverse=True)
        for row in rows:
            self.store.remove_rule(row)
        self.table_model.refresh()

    def _on_load(self, event):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self)
        if result != JFileChooser.APPROVE_OPTION:
            return
        f = chooser.getSelectedFile()
        encoding = str(self.encoding_combo.getSelectedItem())
        try:
            count = self.store.load_csv(f.getAbsolutePath(), encoding=encoding)
        except Exception as e:
            self.status_label.setText("Load failed: %s" % e)
            return
        self.table_model.refresh()
        self.status_label.setText("Loaded %d rule(s) (appended)" % count)

    def _on_save(self, event):
        self._stop_editing()
        chooser = JFileChooser()
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        try:
            self.store.save_csv(chooser.getSelectedFile().getAbsolutePath(),
                                encoding=str(self.encoding_combo.getSelectedItem()))
            self.status_label.setText('Saved %d rule(s).' % len(self.store.snapshot()))
        except Exception as e:
            self.status_label.setText('Save failed: %s' % e)


class _ReplaceFlagToggleListener(ActionListener):
    def __init__(self, panel, flag, checkbox):
        self.panel = panel
        self.flag = flag
        self.checkbox = checkbox

    def actionPerformed(self, event):
        self.panel._on_flag_toggle(self.flag, self.checkbox)


class _ScopeToggleListener(ActionListener):
    def __init__(self, panel, field, checkbox):
        self.panel = panel
        self.field = field
        self.checkbox = checkbox

    def actionPerformed(self, event):
        self.panel._on_scope_toggle(self.field, self.checkbox)


class _ScopeAllToggleListener(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._on_scope_all_toggle()


class ReplacePanel(JPanel):
    def __init__(self, settings, request_store, response_store):
        JPanel.__init__(self, BorderLayout())
        self.settings = settings
        self._pre_all_state = {}

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

        enable_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.enabled_checkbox = JCheckBox("Match & Replace: Enabled", settings.enabled,
                                           actionPerformed=self._on_enabled_toggle)
        enable_row.add(self.enabled_checkbox)
        self.scope_only_checkbox = JCheckBox("Scope only", settings.scope_only,
                                              actionPerformed=self._on_scope_only_toggle)
        self.scope_only_checkbox.setToolTipText("Apply Match & Replace only when the request URL is in Burp Suite scope.")
        enable_row.add(self.scope_only_checkbox)
        top.add(enable_row)

        top.add(JLabel("Tool flags to apply Match & Replace for (independent of the armed target's flags):"))
        flags_panel = JPanel(GridLayout(0, 4))
        self.flag_checkboxes = {}
        for flag, label in TOOL_FLAG_LABELS:
            cb = JCheckBox(label, flag in settings.enabled_tool_flags)
            cb.addActionListener(_ReplaceFlagToggleListener(self, flag, cb))
            flags_panel.add(cb)
            self.flag_checkboxes[flag] = cb
        top.add(flags_panel)

        top.add(JLabel("Packet parts to scan (shared by both the request and response rule lists below):"))
        scope_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.scope_checkboxes = {}
        for field, label in (("scope_method", "Method"), ("scope_path", "Path"),
                              ("scope_headers", "Headers"), ("scope_body", "Body")):
            cb = JCheckBox(label, getattr(settings, field))
            cb.addActionListener(_ScopeToggleListener(self, field, cb))
            scope_row.add(cb)
            self.scope_checkboxes[field] = cb
        self.scope_all_checkbox = JCheckBox("All", settings.scope_all_selected())
        self.scope_all_checkbox.addActionListener(_ScopeAllToggleListener(self))
        scope_row.add(self.scope_all_checkbox)
        top.add(scope_row)

        self.add(top, BorderLayout.NORTH)

        self.request_panel = _RuleListPanel("Request replacements:", request_store)
        self.response_panel = _RuleListPanel("Response replacements:", response_store)
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.request_panel, self.response_panel)
        split.setResizeWeight(0.5)
        self.add(split, BorderLayout.CENTER)

    def _on_enabled_toggle(self, event):
        self.settings.enabled = self.enabled_checkbox.isSelected()

    def _on_scope_only_toggle(self, event):
        self.settings.scope_only = self.scope_only_checkbox.isSelected()

    def _on_flag_toggle(self, flag, checkbox):
        if checkbox.isSelected():
            self.settings.enabled_tool_flags.add(flag)
        else:
            self.settings.enabled_tool_flags.discard(flag)

    def _on_scope_toggle(self, field, checkbox):
        setattr(self.settings, field, checkbox.isSelected())

    def _on_scope_all_toggle(self):
        turning_on = self.scope_all_checkbox.isSelected()
        if turning_on:
            self._pre_all_state = dict((f, cb.isSelected()) for f, cb in self.scope_checkboxes.items())
            for f, cb in self.scope_checkboxes.items():
                cb.setSelected(True)
                cb.setEnabled(False)
                setattr(self.settings, f, True)
        else:
            for f, cb in self.scope_checkboxes.items():
                cb.setEnabled(True)
                prev = self._pre_all_state.get(f, True)
                cb.setSelected(prev)
                setattr(self.settings, f, prev)

    def refresh(self):
        """Re-pull rows from the stores -- needed when a rule was added
        from outside this panel (e.g. the right-click "Add selection to
        Match & Replace" context menu action)."""
        self.request_panel.table_model.refresh()
        self.response_panel.table_model.refresh()
