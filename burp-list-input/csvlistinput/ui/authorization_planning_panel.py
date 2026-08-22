# -*- coding: utf-8 -*-
"""HTTP Historyから認可テスト計画用の受動カタログを作るSwing UI。"""

import re
import time
from threading import Thread

from java.awt import BorderLayout, Color, FlowLayout
from java.awt.event import ActionListener
from java.lang import Integer, Runnable
from java.util import Comparator
from java.util.regex import Pattern
from javax.swing import (BorderFactory, JButton, JCheckBox, JLabel, JPanel, JProgressBar,
                         JScrollPane, JSplitPane, JTabbedPane, JTable, JTextArea, JTextField,
                         ListSelectionModel, RowFilter, SwingUtilities, Timer)
from javax.swing.event import DocumentListener, ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter

from csvlistinput import authorization_planning_engine
from csvlistinput.utils import to_display_text

try:
    _INTEGER_TYPES = (int, long)
except NameError:
    _INTEGER_TYPES = (int,)


def _text(value):
    """Engine値をSwingへ渡す境界で必ずUnicodeへ正規化する。"""
    return to_display_text(value)


def _join(values, separator=u', '):
    if values is None:
        return u''
    if isinstance(values, dict):
        parts = []
        for key in sorted(values.keys(), key=lambda item: _text(item).lower()):
            parts.append(u'%s=%s' % (_text(key), _join(values.get(key))))
        return separator.join(parts)
    if isinstance(values, (list, tuple, set)):
        return separator.join([_join(value) for value in values])
    return _text(values)


def _integer(value, default=0):
    try:
        return Integer(int(value))
    except Exception:
        return Integer(default)


def _count(value):
    if value is None:
        return 0
    if isinstance(value, _INTEGER_TYPES):
        return int(value)
    try:
        return len(value)
    except Exception:
        return 1


def _packet_text(value):
    return _join(value, u',') if isinstance(value, (list, tuple, set)) else _text(value)


def _classification(parameter):
    values = []
    for key in ('candidate_framework_classification', 'candidate_classification',
                'framework_classification', 'classification', 'candidate'):
        value = parameter.get(key)
        if value not in (None, u'', ''):
            values.append(_join(value))
    if 'recovered' in parameter:
        recovered = parameter.get('recovered')
        if recovered is True:
            values.append(u'Recovered: yes')
        elif recovered is False:
            values.append(u'Recovered: no')
        elif recovered not in (None, u'', ''):
            values.append(u'Recovered: %s' % _join(recovered))
    return u' / '.join(values)


def _score_reasons(row):
    score = row.get('score')
    reasons = _join(row.get('reasons') or row.get('reason'))
    if score in (None, u'', ''):
        return reasons
    return u'%s%s' % (_text(score), (u' - ' + reasons) if reasons else u'')


class _UiRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


class _NaturalNumberComparator(Comparator):
    """Packet No等の数列を辞書順ではなく整数列として比較する。"""
    def compare(self, left, right):
        def numbers(value):
            try:
                return [int(part) for part in re.findall(r'\d+', _text(value))]
            except Exception:
                return []
        a, b = numbers(left), numbers(right)
        return (a > b) - (a < b)


class _RowsModel(AbstractTableModel):
    def __init__(self, columns, integer_columns=None):
        AbstractTableModel.__init__(self)
        self.columns = columns
        self.integer_columns = set(integer_columns or [])
        self.rows = []
        self.entries = []

    def set_rows(self, rows, entries=None):
        self.rows = rows or []
        self.entries = entries if entries is not None else self.rows
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, column):
        return self.columns[column]

    def getColumnClass(self, column):
        return Integer if column in self.integer_columns else str

    def getValueAt(self, row, column):
        try:
            return self.rows[row][column]
        except Exception:
            return u''

    def entry_at(self, row):
        return self.entries[row] if 0 <= row < len(self.entries) else None


class _OperationSelectionListener(ListSelectionListener):
    def __init__(self, panel):
        self.panel = panel

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            self.panel._show_selected_operation()


class _FindDocumentListener(DocumentListener):
    def __init__(self, panel):
        self.panel = panel

    def insertUpdate(self, event):
        self.panel._queue_filter()

    def removeUpdate(self, event):
        self.panel._queue_filter()

    def changedUpdate(self, event):
        self.panel._queue_filter()


class _FindTimerListener(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._apply_filter()


class _PriorityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column)
        if is_selected:
            return component
        component.setBackground(table.getBackground())
        component.setForeground(table.getForeground())
        model_row = table.convertRowIndexToModel(row)
        priority = _text(table.getModel().getValueAt(model_row, 0)).upper()
        if column == 2:
            origin = _text(value).lower()
            if u'standard' in origin:
                component.setBackground(Color(55, 95, 145)); component.setForeground(Color.WHITE)
            elif u'custom' in origin:
                component.setBackground(Color(105, 65, 135)); component.setForeground(Color.WHITE)
            elif u'managed' in origin or u'namespaced' in origin:
                component.setBackground(Color(45, 115, 110)); component.setForeground(Color.WHITE)
            elif origin:
                component.setBackground(Color(90, 90, 90)); component.setForeground(Color.WHITE)
        elif priority == u'P0' and column in (0, 1, 8, 9):
            component.setBackground(Color(145, 45, 52))
            component.setForeground(Color.WHITE)
        elif priority == u'P1' and column in (0, 1, 8, 9):
            component.setBackground(Color(230, 190, 75))
            component.setForeground(Color.BLACK)
        return component


class _SemanticRenderer(DefaultTableCellRenderer):
    """由来と観測されたデータ操作を、別の列・色体系で表示する。"""
    def __init__(self, origin_column, interaction_column):
        DefaultTableCellRenderer.__init__(self)
        self.origin_column = origin_column
        self.interaction_column = interaction_column

    def getTableCellRendererComponent(self, table, value, is_selected, has_focus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, is_selected, has_focus, row, column)
        if is_selected:
            return component
        component.setBackground(table.getBackground())
        component.setForeground(table.getForeground())
        value_text = _text(value).lower()
        if column == self.origin_column:
            if u'standard' in value_text:
                component.setBackground(Color(55, 95, 145)); component.setForeground(Color.WHITE)
            elif u'custom' in value_text:
                component.setBackground(Color(105, 65, 135)); component.setForeground(Color.WHITE)
            elif u'managed' in value_text or u'namespaced' in value_text:
                component.setBackground(Color(45, 115, 110)); component.setForeground(Color.WHITE)
            elif value_text:
                component.setBackground(Color(90, 90, 90)); component.setForeground(Color.WHITE)
        elif column == self.interaction_column:
            if (u'write' in value_text or u'create' in value_text or u'update' in value_text or
                    u'delete' in value_text or u'mutation' in value_text):
                component.setBackground(Color(205, 145, 55)); component.setForeground(Color.BLACK)
            elif (u'read' in value_text or u'list' in value_text or u'search' in value_text or
                  u'query' in value_text):
                component.setBackground(Color(65, 115, 140)); component.setForeground(Color.WHITE)
        return component


class _LocalFilterTimer(ActionListener):
    def __init__(self, binding): self.binding = binding
    def actionPerformed(self, event): self.binding.apply()


class _LocalFilterDocument(DocumentListener):
    def __init__(self, binding): self.binding = binding
    def insertUpdate(self, event): self.binding.queue()
    def removeUpdate(self, event): self.binding.queue()
    def changedUpdate(self, event): self.binding.queue()


class _LocalFilterBinding(object):
    def __init__(self, panel, field, sorter):
        self.panel = panel
        self.field = field
        self.sorter = sorter
        self.timer = Timer(180, _LocalFilterTimer(self))
        self.timer.setRepeats(False)
        self.listener = _LocalFilterDocument(self)
        field.getDocument().addDocumentListener(self.listener)

    def queue(self): self.timer.restart()

    def apply(self):
        query = _text(self.field.getText())
        self.panel._local_queries[self.sorter] = query
        self.panel._apply_sorter_filter(self.sorter)


class AuthorizationPlanningPanel(JPanel):
    """指定範囲のHTTP Historyのみを解析する受動的な計画作成画面。"""

    OPERATION_COLUMNS = [u'#', u'Protocol', u'Route Classification', u'Route Confidence', u'Route Evidence',
                         u'Destination Label', u'Destination Confidence', u'Destination Source',
                         u'Group', u'Traffic Class', u'Origin', u'Origin Confidence',
                         u'Origin Reason', u'Host', u'Method', u'Path', u'Operation/Descriptor',
                         u'Calling Descriptor', u'Behavior', u'Data Interaction',
                         u'Interaction Confidence', u'Interaction Reasons', u'CRUD Intents',
                         u'GraphQL Kind', u'GraphQL Operation', u'GraphQL Metadata', u'Salesforce Features',
                         u'Request Content Types', u'Response Content Types', u'Occurrences',
                         u'Packet No', u'Status', u'Parameters', u'Candidates']
    PARAMETER_COLUMNS = [u'#', u'Region', u'Type', u'Nesting', u'Parameter Path', u'Occurrences',
                         u'Packet No', u'Sample Values', u'Candidate/Framework classification',
                         u'Score/Reasons']
    RESPONSE_COLUMNS = [u'#', u'Response Field/Schema Path', u'Type', u'Occurrences', u'Packet No',
                        u'Sample Values']
    PLAN_COLUMNS = [u'Priority', u'Score', u'Origin', u'Operation', u'Candidate Path', u'Type',
                    u'Sample Values', u'Packet No', u'Reasons', u'Recommended Tests']
    SESSION_COLUMNS = [u'Fingerprint', u'Auth Kind', u'Groups', u'Hosts', u'Occurrences', u'Packet No']
    GAP_COLUMNS = [u'Packet No', u'Stage', u'Reason']
    RESOURCE_COLUMNS = [u'#', u'Score', u'Type', u'Source', u'Value', u'Groups', u'Paths',
                        u'Operations', u'Occurrences', u'Packet No', u'Reasons']
    ACCESS_COLUMNS = [u'#', u'Subject/Context', u'Auth Kind', u'Groups', u'Operation', u'Origin',
                      u'Data Interaction', u'Occurrences', u'Packet No', u'State', u'Evidence']
    OBJECT_COLUMNS = [u'#', u'Object', u'Kind', u'Data Interactions', u'CRUD Intents', u'Operations',
                      u'Fields', u'Groups', u'Auth Kinds', u'Confidence', u'Packet No', u'Reasons']
    FIELD_COLUMNS = [u'#', u'Object', u'Field', u'Kind/Type', u'Focus Type', u'Sources', u'CRUD Intents',
                     u'Operations', u'Groups', u'Auth Kinds', u'Confidence', u'Packet No', u'Reasons']
    APP_COLUMNS = [u'#', u'App ID', u'Host', u'Default App', u'Default Confidence', u'Default Reasons',
                   u'Features', u'Endpoints', u'Operations', u'Groups', u'Sessions', u'Packet No']
    ENDPOINT_COLUMNS = [u'#', u'Route Classification', u'Route Confidence', u'Route Evidence',
                        u'Destination Label', u'Destination Confidence', u'Destination Source',
                        u'Protocol', u'Host', u'Method', u'Normalized Path', u'Data Interaction',
                        u'Request Content Types', u'Response Content Types', u'Status', u'Parameters',
                        u'Operations', u'Groups', u'Sessions', u'Occurrences', u'Packet No']
    PACKET_COLUMNS = [u'Packet No', u'Route Classification', u'Destination Label', u'Protocol', u'Host',
                      u'Method', u'Normalized Path', u'Status', u'Group', u'Operations', u'Operation Count']
    COVERAGE_COLUMNS = [u'#', u'Category', u'Severity', u'Scope', u'Operation', u'State', u'Reason',
                        u'Recommendation', u'Evidence']

    def __init__(self, callbacks, helpers, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.log_fn = log_fn
        self.error_fn = error_fn
        self._worker = None
        self._cancel_requested = False
        self._last_progress_update = 0.0
        self._packet_items = {}
        self._sorters = []
        self._local_filter_bindings = []
        self._local_queries = {}
        self._filter_timer = Timer(180, _FindTimerListener(self))
        self._filter_timer.setRepeats(False)
        try:
            self._empty_bytes = helpers.stringToBytes('')
        except Exception:
            self._empty_bytes = None

        self.add(self._build_toolbar(), BorderLayout.NORTH)
        self.tabs = JTabbedPane()
        self.tabs.addTab(u'Overview', self._build_overview())
        self.tabs.addTab(u'Operation Catalog', self._build_operations())
        self.tabs.addTab(u'Operation x Subject', self._build_access_matrix())
        self.tabs.addTab(u'Objects & Fields', self._build_objects_fields())
        self.tabs.addTab(u'Apps & Endpoints', self._build_apps_endpoints())
        self.tabs.addTab(u'Test Plan', self._build_plan())
        self.tabs.addTab(u'Sessions', self._build_sessions())
        self.tabs.addTab(u'Planning Coverage', self._build_coverage())
        self.tabs.addTab(u'Technical Gaps', self._build_gaps())
        self.tabs.addTab(u'Resource Corpus', self._build_resources())
        self.add(self.tabs, BorderLayout.CENTER)

        bottom = JPanel(BorderLayout())
        self.status_label = JLabel(u'Range: all HTTP History. Build the passive planning catalog to begin.')
        bottom.add(self.status_label, BorderLayout.CENTER)
        self.progress = JProgressBar(0, 100)
        self.progress.setStringPainted(True)
        self.progress.setString(u'Idle')
        bottom.add(self.progress, BorderLayout.EAST)
        self.add(bottom, BorderLayout.SOUTH)

    def _build_toolbar(self):
        panel = JPanel(FlowLayout(FlowLayout.LEFT))
        panel.add(JLabel(u'Packet No range:'))
        self.start_field = JTextField(6)
        self.start_field.setToolTipText(u'Start packet number (blank: first packet)')
        panel.add(self.start_field)
        panel.add(JLabel(u'to'))
        self.end_field = JTextField(6)
        self.end_field.setToolTipText(u'End packet number (blank: last packet)')
        panel.add(self.end_field)
        self.all_button = JButton(u'All', actionPerformed=self._on_all)
        panel.add(self.all_button)
        self.scope_only_checkbox = JCheckBox(u'Target scope only (Burp Target scope)', False)
        self.scope_only_checkbox.setToolTipText(
            u'ONの場合、BurpのTarget scopeに含まれるHTTP Historyだけを受動解析します。'
            u'リクエストは送信しません。既定はOFFです。')
        panel.add(self.scope_only_checkbox)
        panel.add(JLabel(u'Destination rule:'))
        self.destination_rules_field = JTextField(26)
        self.destination_rules_field.setToolTipText(
            u'Optional: Label | Host regex | Path regex. Example: '
            u'On-prem | ^portal\\.example\\.test$ | ^/web11/.+/(Login|Entry|Message)$ . '
            u'Labels are user annotations based on specifications; HTTP alone does not prove physical destination.')
        panel.add(self.destination_rules_field)
        self.build_button = JButton(u'Build planning catalog', actionPerformed=self._on_build)
        panel.add(self.build_button)
        self.cancel_button = JButton(u'Cancel', actionPerformed=self._on_cancel)
        self.cancel_button.setEnabled(False)
        panel.add(self.cancel_button)
        self.clear_button = JButton(u'Clear', actionPerformed=self._on_clear)
        panel.add(self.clear_button)
        panel.add(JLabel(u'Find in results:'))
        self.find_field = JTextField(22)
        self.find_field.setToolTipText(u'Filter all catalog tables without rebuilding the analysis.')
        self.find_field.getDocument().addDocumentListener(_FindDocumentListener(self))
        panel.add(self.find_field)
        return panel

    def _new_table(self, model, packet_columns=None, priority=False, semantic=None):
        table = JTable(model)
        table.setAutoCreateRowSorter(False)
        sorter = TableRowSorter(model)
        for column in packet_columns or []:
            sorter.setComparator(column, _NaturalNumberComparator())
        table.setRowSorter(sorter)
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        table.setCellSelectionEnabled(True)
        self._sorters.append(sorter)
        if priority:
            renderer = _PriorityRenderer()
            for column in range(model.getColumnCount()):
                table.getColumnModel().getColumn(column).setCellRenderer(renderer)
        elif semantic:
            renderer = _SemanticRenderer(semantic[0], semantic[1])
            for column in range(model.getColumnCount()):
                table.getColumnModel().getColumn(column).setCellRenderer(renderer)
        return table

    def _table_with_find(self, table, hint=None):
        panel = JPanel(BorderLayout())
        row = JPanel(FlowLayout(FlowLayout.LEFT))
        row.add(JLabel(u'Find in this table:'))
        field = JTextField(22)
        if hint:
            field.setToolTipText(_text(hint))
        row.add(field)
        panel.add(row, BorderLayout.NORTH)
        panel.add(JScrollPane(table), BorderLayout.CENTER)
        binding = _LocalFilterBinding(self, field, table.getRowSorter())
        self._local_filter_bindings.append(binding)
        return panel

    def _build_overview(self):
        panel = JPanel(BorderLayout())
        # Value列は件数(Integer)と分類内訳(Unicode)が混在するためObject扱いにする。
        self.summary_model = _RowsModel([u'Metric', u'Value'])
        self.summary_table = self._new_table(self.summary_model)
        panel.add(self._table_with_find(self.summary_table), BorderLayout.CENTER)
        note = JTextArea(
            u'Classification definitions:\n'
            u'  Standard = platform/framework operation; Custom = organization code; Managed = package namespace; '
            u'Unknown = insufficient evidence.\n'
            u'Origin describes implementation provenance, not risk. Data Interaction describes observed behavior, not an authorization verdict.\n'
            u'Target scope only limits the selected Packet No range to URLs in Burp Target scope; it remains passive.\n'
            u'Passive/no requests sent. Origin is heuristic. Authentication secrets are not copied into catalog columns; '
            u'the representative Burp message viewer still shows the original History message. '
            u'Review observed evidence before forming a test hypothesis.')
        note.setEditable(False)
        note.setLineWrap(True)
        note.setWrapStyleWord(True)
        note.setRows(5)
        note.setBackground(panel.getBackground())
        note.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        panel.add(note, BorderLayout.SOUTH)
        return panel

    def _build_operations(self):
        self.operation_model = _RowsModel(self.OPERATION_COLUMNS, [0, 29, 32, 33])
        self.operation_table = self._new_table(self.operation_model, [30], semantic=(10, 19))
        self.operation_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.operation_table.getSelectionModel().addListSelectionListener(_OperationSelectionListener(self))

        self.parameter_model = _RowsModel(self.PARAMETER_COLUMNS, [0, 5])
        self.parameter_table = self._new_table(self.parameter_model, [6])
        self.parameter_table.setCellSelectionEnabled(True)
        parameter_panel = JPanel(BorderLayout())
        parameter_panel.add(self._table_with_find(self.parameter_table), BorderLayout.CENTER)

        self.response_model = _RowsModel(self.RESPONSE_COLUMNS, [0, 3])
        self.response_table = self._new_table(self.response_model, [4])
        self.response_table.setCellSelectionEnabled(True)
        response_panel = JPanel(BorderLayout())
        response_panel.add(self._table_with_find(self.response_table), BorderLayout.CENTER)

        detail_tabs = JTabbedPane()
        detail_tabs.addTab(u'Parameters', parameter_panel)
        detail_tabs.addTab(u'Response Fields', response_panel)

        self.request_editor = self.callbacks.createMessageEditor(None, False)
        self.response_editor = self.callbacks.createMessageEditor(None, False)
        messages = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                              self.request_editor.getComponent(), self.response_editor.getComponent())
        messages.setResizeWeight(0.5)
        messages.setOneTouchExpandable(True)
        lower = JSplitPane(JSplitPane.VERTICAL_SPLIT, detail_tabs, messages)
        lower.setResizeWeight(0.42)
        lower.setOneTouchExpandable(True)
        operation_list = self._table_with_find(
            self.operation_table, u'Operation Catalogだけを絞り込みます。')
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, operation_list, lower)
        split.setResizeWeight(0.45)
        split.setOneTouchExpandable(True)
        return split

    def _build_access_matrix(self):
        panel = JPanel(BorderLayout())
        self.access_model = _RowsModel(self.ACCESS_COLUMNS, [0, 7])
        self.access_table = self._new_table(self.access_model, [8], semantic=(5, 6))
        panel.add(self._table_with_find(self.access_table), BorderLayout.CENTER)
        note = JLabel(u'Observed sparse rows only. Missing rows are not Denied; use Planning Coverage for missing evidence.')
        note.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        panel.add(note, BorderLayout.SOUTH)
        return panel

    def _build_objects_fields(self):
        self.object_model = _RowsModel(self.OBJECT_COLUMNS, [0, 6])
        self.object_table = self._new_table(self.object_model, [10])
        self.field_model = _RowsModel(self.FIELD_COLUMNS, [0])
        self.field_table = self._new_table(self.field_model, [11])
        tabs = JTabbedPane()
        tabs.addTab(u'Objects', self._table_with_find(self.object_table))
        tabs.addTab(u'Fields', self._table_with_find(self.field_table))
        return tabs

    def _build_apps_endpoints(self):
        self.app_model = _RowsModel(self.APP_COLUMNS, [0, 7])
        self.app_table = self._new_table(self.app_model, [11])
        self.endpoint_model = _RowsModel(self.ENDPOINT_COLUMNS, [0, 19])
        self.endpoint_table = self._new_table(self.endpoint_model, [20])
        self.packet_model = _RowsModel(self.PACKET_COLUMNS, [0, 10])
        self.packet_table = self._new_table(self.packet_model, [0])
        tabs = JTabbedPane()
        tabs.addTab(u'Aura Applications', self._table_with_find(self.app_table))
        tabs.addTab(u'All HTTP Endpoints', self._table_with_find(self.endpoint_table,
            u'Includes non-Aura custom/backend routes. Destination Label is only a user-configured annotation.'))
        tabs.addTab(u'Packet Coverage', self._table_with_find(self.packet_table,
            u'Every analyzed packet should have one or more Operation IDs unless Technical Gaps records an extraction failure.'))
        return tabs

    def _build_coverage(self):
        panel = JPanel(BorderLayout())
        self.coverage_summary_model = _RowsModel([u'Metric', u'Value'])
        self.coverage_summary_table = self._new_table(self.coverage_summary_model)
        self.coverage_model = _RowsModel(self.COVERAGE_COLUMNS, [0])
        self.coverage_table = self._new_table(self.coverage_model)
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           self._table_with_find(self.coverage_summary_table),
                           self._table_with_find(self.coverage_table))
        split.setResizeWeight(0.25)
        split.setOneTouchExpandable(True)
        panel.add(split, BorderLayout.CENTER)
        note = JLabel(u'Coverage state is Observed, Not observed, or Unknown. Passive evidence never proves Denied.')
        note.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        panel.add(note, BorderLayout.SOUTH)
        return panel

    def _build_plan(self):
        panel = JPanel(BorderLayout())
        self.plan_model = _RowsModel(self.PLAN_COLUMNS, [1])
        self.plan_table = self._new_table(self.plan_model, [7], priority=True)
        panel.add(self._table_with_find(self.plan_table), BorderLayout.CENTER)
        note = JLabel(u'P0/P1 are planning priorities, not vulnerability findings. Validate each hypothesis manually.')
        note.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        panel.add(note, BorderLayout.SOUTH)
        return panel

    def _build_sessions(self):
        self.session_model = _RowsModel(self.SESSION_COLUMNS, [4])
        self.session_table = self._new_table(self.session_model, [5])
        return self._table_with_find(self.session_table)

    def _build_gaps(self):
        self.gap_model = _RowsModel(self.GAP_COLUMNS)
        self.gap_table = self._new_table(self.gap_model, [0])
        return self._table_with_find(self.gap_table)

    def _build_resources(self):
        self.resource_model = _RowsModel(self.RESOURCE_COLUMNS, [0, 1, 8])
        self.resource_table = self._new_table(self.resource_model, [9])
        return self._table_with_find(self.resource_table)

    def _selected_range(self):
        try:
            start = self._parse_packet_no(self.start_field.getText(), u'Start')
            end = self._parse_packet_no(self.end_field.getText(), u'End')
            if start is not None and end is not None and start > end:
                raise ValueError(u'Start Packet No must not exceed End Packet No.')
            return start, end, None
        except ValueError as error:
            return None, None, _text(error)

    def _parse_packet_no(self, value, label):
        value = _text(value).strip()
        if not value:
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(u'%s Packet No must be a positive integer.' % _text(label))
        if number < 1:
            raise ValueError(u'%s Packet No must be a positive integer.' % _text(label))
        return number

    def _range_label(self, start, end):
        if start is None and end is None:
            return u'all HTTP History'
        return u'Packet No %s to %s' % (_text(start if start is not None else u'first'),
                                        _text(end if end is not None else u'last'))

    def _on_all(self, event):
        self.start_field.setText(u'')
        self.end_field.setText(u'')
        self.status_label.setText(
            u'Range set to all HTTP History. Target scope filtering follows the checkbox setting.')

    def _on_build(self, event):
        if self._worker is not None:
            return
        start, end, error = self._selected_range()
        if error:
            self.status_label.setText(error)
            return
        # 前回のFind条件が新しいcatalogを全件非表示にし、「未検出」に見えることを防ぐ。
        self.find_field.setText(u'')
        for binding in self._local_filter_bindings:
            binding.field.setText(u'')
        self._local_queries.clear()
        self._apply_filter()
        scope_only = bool(self.scope_only_checkbox.isSelected())
        self._cancel_requested = False
        self._last_progress_update = 0.0
        self.build_button.setEnabled(False)
        self.build_button.setText(u'Building catalog...')
        self.cancel_button.setEnabled(True)
        self.cancel_button.setText(u'Cancel')
        self.clear_button.setEnabled(False)
        self.scope_only_checkbox.setEnabled(False)
        self.destination_rules_field.setEnabled(False)
        self.progress.setIndeterminate(True)
        self.progress.setString(u'Reading history...')
        scope_text = u'Burp Target scope only' if scope_only else u'all targets in the selected range'
        self.status_label.setText(
            u'Building the authorization planning catalog in the background (%s)...' % scope_text)
        destination_rules = _text(self.destination_rules_field.getText())
        self._worker = Thread(target=self._worker_run, args=(start, end, scope_only, destination_rules))
        self._worker.setDaemon(True)
        self._worker.start()

    def _worker_run(self, start, end, scope_only, destination_rules=u''):
        try:
            result = authorization_planning_engine.analyze_history(
                self.callbacks, self.helpers, start, end,
                cancel_check=lambda: self._cancel_requested,
                progress_fn=self._on_worker_progress,
                scope_only=scope_only, destination_rules=destination_rules)
            result = result or {}
            # 大きな疎行列・catalogのUnicode整形はworker側で済ませ、EDTでは
            # 各modelへ一括set_rowsするだけにする。
            access_source = (result.get('access_matrix') or result.get('subject_operation_matrix') or
                             result.get('context_matrix') or [])
            prepared_v2 = {
                'access': self._format_access_matrix(access_source),
                'objects_fields': self._format_objects_fields(result),
                'apps_endpoints': self._format_apps_endpoints(result),
                'packets': self._format_packet_catalog(result.get('packet_catalog') or result.get('packets') or []),
                'coverage': self._format_coverage(result)
            }
            cancelled = self._cancel_requested
            SwingUtilities.invokeLater(_UiRunnable(
                lambda: self._build_finished(result, cancelled, start, end, prepared_v2, scope_only)))
        except Exception as error:
            SwingUtilities.invokeLater(_UiRunnable(lambda caught=error: self._build_failed(caught)))

    def _on_worker_progress(self, processed, total):
        """Workerからの進捗を間引き、実際のSwing更新はEDTへ渡す。"""
        now = time.time()
        if now - self._last_progress_update < 0.12 and processed != total:
            return
        self._last_progress_update = now
        try:
            current = int(processed)
            maximum = int(total)
        except Exception:
            return
        SwingUtilities.invokeLater(_UiRunnable(
            lambda: self._set_progress(current, maximum)))

    def _set_progress(self, processed, total):
        if self._worker is None:
            return
        if total > 0:
            self.progress.setIndeterminate(False)
            self.progress.setMaximum(total)
            self.progress.setValue(min(processed, total))
            self.progress.setString(u'%d / %d packets' % (processed, total))
        else:
            self.progress.setIndeterminate(True)
            self.progress.setString(u'%d packets' % processed)
        self.status_label.setText(u'Analyzing HTTP History: %d%s' % (
            processed, (u' / %d packets' % total) if total > 0 else u' packets'))

    def _restore_buttons(self):
        self._worker = None
        self.build_button.setEnabled(True)
        self.build_button.setText(u'Build planning catalog')
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText(u'Cancel')
        self.clear_button.setEnabled(True)
        self.scope_only_checkbox.setEnabled(True)
        self.destination_rules_field.setEnabled(True)
        self.progress.setIndeterminate(False)

    def _on_cancel(self, event):
        if self._worker is None:
            return
        self._cancel_requested = True
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText(u'Stopping...')
        self.status_label.setText(u'Cancel requested; finishing the current packet...')
        self.progress.setString(u'Stopping after current packet...')

    def _build_finished(self, result, cancelled, start, end, prepared_v2=None, scope_only=False):
        self._restore_buttons()
        operations = result.get('operations') or []
        sessions = result.get('sessions') or []
        gaps = result.get('gaps') or []
        plan_rows = result.get('plan_rows') or []
        resources = result.get('resources') or []
        packets = result.get('packets') or []
        self._packet_items = {}
        for packet in packets:
            packet_no = packet.get('packet_no')
            if packet_no is not None and packet.get('item') is not None:
                self._packet_items[_text(packet_no)] = packet.get('item')

        self.summary_model.set_rows(self._summary_rows(
            result.get('summary') or {}, operations, resources, scope_only))
        self._set_operations(operations)
        self._set_plan(plan_rows)
        self._set_sessions(sessions)
        self._set_gaps(gaps)
        self._set_resources(resources)
        if prepared_v2 is None:
            prepared_v2 = {}
        self._set_access_matrix(prepared=prepared_v2.get('access'))
        self._set_objects_fields(prepared=prepared_v2.get('objects_fields'))
        self._set_apps_endpoints(prepared=prepared_v2.get('apps_endpoints'))
        self._set_packet_catalog(prepared=prepared_v2.get('packets'))
        self._set_coverage(prepared=prepared_v2.get('coverage'))
        self._show_operation(None)
        self._apply_filter()

        prefix = u'Cancelled; partial catalog: ' if cancelled else u'Completed: '
        scope_text = u'Burp Target scope only' if scope_only else u'scope filter OFF'
        summary = result.get('summary') or {}
        scope_detail = u''
        if scope_only:
            scope_detail = u'; %s considered, %s excluded out of scope' % (
                _text(summary.get('packets_considered', len(packets))),
                _text(summary.get('packets_excluded_out_of_scope', 0)))
        self.status_label.setText(
            u'%s%d operation(s), %d plan row(s), %d matrix row(s), %d technical gap(s) from %s (%s%s).' %
            (prefix, len(operations), len(plan_rows), self.access_model.getRowCount(), len(gaps),
             self._range_label(start, end), scope_text, scope_detail))
        self.progress.setValue(self.progress.getMaximum())
        self.progress.setString(u'Cancelled (partial)' if cancelled else u'Complete')
        if self.log_fn:
            self.log_fn(u'Authorization Planning: %d operation(s), %d plan row(s), %d resource(s) cataloged from %s; %s%s.' %
                        (len(operations), len(plan_rows), len(resources), self._range_label(start, end),
                         scope_text,
                         u' (cancelled; partial)' if cancelled else u''))

    def _build_failed(self, error):
        self._restore_buttons()
        message = u'Authorization planning failed: %s' % _text(error)
        self.status_label.setText(message)
        self.progress.setValue(0)
        self.progress.setString(u'Failed')
        if self.error_fn:
            self.error_fn(u'Authorization Planning', message)

    def _summary_rows(self, summary, operations, resources, scope_only=False):
        labels = {
            'packets': u'Packets analyzed', 'packet_count': u'Packets analyzed',
            'operations': u'Operations', 'operation_count': u'Operations',
            'sessions': u'Sessions', 'session_count': u'Sessions',
            'gaps': u'Technical parser gaps', 'gap_count': u'Technical parser gaps',
            'technical_gaps': u'Technical gaps', 'planning_gaps': u'Planning coverage gaps',
            'packets_selected_by_range': u'Packets selected by Packet No range',
            'packets_considered': u'Packets considered for Target scope filtering',
            'packets_in_scope': u'Packets in Burp Target scope',
            'packets_filtered_out': u'Packets excluded by Target scope',
            'scope_filtered_packets': u'Packets excluded by Target scope',
            'packets_excluded_out_of_scope': u'Packets excluded by Target scope',
            'scope_lookup_failures': u'Target scope lookup failures',
            'scope_only': u'Target scope filter (engine)',
            'plan_rows': u'Test plan rows', 'plan_row_count': u'Test plan rows',
            'resources': u'Resource candidates', 'resource_count': u'Resource candidates',
            'traffic_classes': u'Traffic classes'
        }
        rows = []
        seen_labels = set()
        rows.append([u'Target scope filter',
                     u'Enabled (Burp Target scope only)' if scope_only else u'Disabled'])
        for key in sorted(summary.keys(), key=lambda value: _text(value).lower()):
            normalized_key = _text(key)
            label = labels.get(normalized_key, normalized_key.replace(u'_', u' ').title())
            if label in seen_labels:
                continue
            seen_labels.add(label)
            value = summary.get(key)
            if isinstance(value, _INTEGER_TYPES):
                # Summary Value列は内訳文字列も入るため、型をUnicodeに統一する。
                value = _text(value)
            else:
                value = _join(value)
            rows.append([label, value])
        if u'Operations' not in seen_labels:
            rows.append([u'Operations', _text(len(operations))])
        if u'Resource candidates' not in seen_labels:
            rows.append([u'Resource candidates', _text(len(resources))])
        response_paths = set()
        for operation in operations:
            for field in self._response_entries(operation):
                path = _text(field.get('path') or field.get('name') or field.get('field'))
                if path:
                    response_paths.add(path)
        rows.append([u'Distinct response fields/schema paths', _text(len(response_paths))])
        return rows

    def _set_operations(self, operations):
        rows = []
        for index, entry in enumerate(operations):
            operation_parts = []
            for value in (entry.get('operation_name'), entry.get('descriptor'), entry.get('operation_id')):
                text = _text(value)
                if text and text not in operation_parts:
                    operation_parts.append(text)
            operation = u' | '.join(operation_parts)
            graphql = entry.get('graphql') or entry.get('graphql_metadata') or {}
            if not isinstance(graphql, dict):
                graphql = {}
            graphql_details = {}
            for key in ('objects', 'fields', 'field_paths', 'has_filter', 'has_pagination',
                        'variables_present', 'parse_confidence', 'reasons'):
                if key in graphql:
                    graphql_details[key] = graphql.get(key)
            rows.append([
                _integer(index + 1), _text(entry.get('protocol_kind')),
                _text(entry.get('route_classification')), _text(entry.get('route_confidence')),
                _join(entry.get('route_evidence')), _text(entry.get('destination_label')),
                _text(entry.get('destination_confidence')), _text(entry.get('destination_source')),
                _join(entry.get('observed_groups') or entry.get('groups')),
                _join(entry.get('traffic_classes') or entry.get('traffic_class')), _text(entry.get('origin')),
                _text(entry.get('origin_confidence')), _text(entry.get('origin_reason')),
                _text(entry.get('host')), _text(entry.get('method')), _text(entry.get('path')),
                operation, _text(entry.get('calling_descriptor')), _text(entry.get('behavior')),
                _text(entry.get('data_interaction')), _text(entry.get('data_interaction_confidence')),
                _join(entry.get('data_interaction_reasons') or entry.get('interaction_reason')),
                _join(entry.get('crud_intents')), _text(graphql.get('kind')),
                _text(graphql.get('operation_name')), _join(graphql_details),
                _join(entry.get('salesforce_features') or
                                                             entry.get('sf_feature_flags')),
                _join(entry.get('request_content_types')), _join(entry.get('response_content_types')),
                _integer(entry.get('occurrences')), _packet_text(entry.get('packet_nos') or entry.get('packet_no')),
                _join(entry.get('status_codes')), _integer(_count(entry.get('parameters'))),
                _integer(_count(entry.get('resource_candidates')))])
        self.operation_model.set_rows(rows, operations)

    def _set_plan(self, plan_rows):
        rows = []
        for entry in plan_rows:
            rows.append([
                _text(entry.get('priority')), _integer(entry.get('score')), _text(entry.get('origin')),
                _text(entry.get('operation') or entry.get('operation_id')), _text(entry.get('candidate_path')),
                _text(entry.get('candidate_type') or entry.get('type')), _join(entry.get('sample_values')),
                _packet_text(entry.get('packet_nos') or entry.get('packet_no')), _join(entry.get('reasons')),
                _join(entry.get('recommended_tests'), u'; ')])
        self.plan_model.set_rows(rows, plan_rows)

    def _set_sessions(self, sessions):
        rows = []
        for entry in sessions:
            packet_nos = entry.get('packet_nos') or entry.get('packet_no') or []
            occurrences = entry.get('occurrences')
            if occurrences is None:
                occurrences = _count(packet_nos)
            rows.append([
                _text(entry.get('fingerprint')), _text(entry.get('auth_kind')),
                _join(entry.get('observed_groups') or entry.get('groups')), _join(entry.get('hosts')),
                _integer(occurrences), _packet_text(packet_nos)])
        self.session_model.set_rows(rows, sessions)

    def _set_gaps(self, gaps):
        rows = []
        for entry in gaps:
            rows.append([_packet_text(entry.get('packet_no')), _text(entry.get('stage')),
                         _text(entry.get('reason'))])
        self.gap_model.set_rows(rows, gaps)

    def _set_resources(self, resources):
        rows = []
        for index, entry in enumerate(resources):
            rows.append([
                _integer(index + 1), _integer(entry.get('score')),
                _text(entry.get('type') or entry.get('candidate_type')),
                _join(entry.get('source') or entry.get('sources')), _text(entry.get('value')),
                _join(entry.get('groups') or entry.get('observed_groups')),
                _join(entry.get('paths')), _join(entry.get('operations') or entry.get('operation_ids')),
                _integer(entry.get('occurrences')),
                _packet_text(entry.get('packet_nos') or entry.get('packet_no')),
                _join(entry.get('reasons'))])
        self.resource_model.set_rows(rows, resources)

    def _dict_rows(self, value, identity_key=None, row_keys=None):
        """list/dict/named-mapの契約差を、疎な行のまま吸収する。"""
        if not value:
            return []
        if isinstance(value, (list, tuple)):
            return [item if isinstance(item, dict) else {identity_key or 'value': item}
                    for item in value]
        if not isinstance(value, dict):
            return [{identity_key or 'value': value}]
        for key in row_keys or ('rows', 'items'):
            nested = value.get(key)
            if isinstance(nested, (list, tuple)):
                return self._dict_rows(nested, identity_key)
        rows = []
        for name, detail in value.items():
            if isinstance(detail, dict):
                row = dict(detail)
                if identity_key:
                    row.setdefault(identity_key, name)
                rows.append(row)
            elif isinstance(detail, (list, tuple)):
                for item in detail:
                    row = dict(item) if isinstance(item, dict) else {'value': item}
                    if identity_key:
                        row.setdefault(identity_key, name)
                    rows.append(row)
            else:
                row = {'value': detail}
                if identity_key:
                    row[identity_key] = name
                rows.append(row)
        return rows

    def _flatten_access_rows(self, value):
        if isinstance(value, dict) and not any(key in value for key in ('rows', 'matrix', 'items')):
            nested_rows = []
            for subject, operations in value.items():
                if isinstance(operations, dict) and not any(
                        key in operations for key in ('operation_id', 'operation', 'session_fingerprint')):
                    for operation_id, cell in operations.items():
                        entry = dict(cell) if isinstance(cell, dict) else {'evidence': cell}
                        entry.setdefault('subject', subject)
                        entry.setdefault('operation_id', operation_id)
                        nested_rows.append(entry)
                else:
                    entry = dict(operations) if isinstance(operations, dict) else {'evidence': operations}
                    entry.setdefault('subject', subject)
                    nested_rows.append(entry)
            if nested_rows:
                return nested_rows
        direct = self._dict_rows(value, row_keys=('rows', 'matrix', 'items'))
        # Named nested matrix: subject -> operation -> evidence cell.
        flattened = []
        for row in direct:
            if ('operation_id' in row or 'operation' in row or 'session_fingerprint' in row or
                    'subject' in row or 'context' in row):
                flattened.append(row)
                continue
            for subject, operations in row.items():
                if not isinstance(operations, dict):
                    continue
                for operation_id, cell in operations.items():
                    entry = dict(cell) if isinstance(cell, dict) else {'evidence': cell}
                    entry.setdefault('subject', subject)
                    entry.setdefault('operation_id', operation_id)
                    flattened.append(entry)
        return flattened if flattened else direct

    def _format_access_matrix(self, value):
        entries = self._flatten_access_rows(value)
        rows = []
        for index, entry in enumerate(entries):
            subject = (entry.get('subject') or entry.get('context') or
                       entry.get('session_context') or entry.get('session_fingerprint'))
            rows.append([
                _integer(index + 1), _text(subject), _text(entry.get('auth_kind')),
                _join(entry.get('groups') or entry.get('observed_groups')),
                _text(entry.get('operation') or entry.get('operation_id')),
                _text(entry.get('origin')), _text(entry.get('data_interaction')),
                _integer(entry.get('occurrences')), _packet_text(entry.get('packet_nos')),
                u'Observed' if entry.get('observed') is True else u'Unknown',
                _join(entry.get('evidence'))])
        return rows, entries

    def _set_access_matrix(self, value=None, prepared=None):
        rows, entries = prepared if prepared is not None else self._format_access_matrix(value)
        self.access_model.set_rows(rows, entries)

    def _format_objects_fields(self, result):
        combined = result.get('object_field_catalog') or {}
        object_source = result.get('object_catalog') or (
            combined.get('objects') if isinstance(combined, dict) else combined)
        field_source = result.get('field_catalog') or (
            combined.get('fields') if isinstance(combined, dict) else [])
        objects = self._dict_rows(object_source, 'object_name', ('objects', 'rows', 'items'))
        fields = self._dict_rows(field_source, 'field_name', ('fields', 'rows', 'items'))
        if not fields:
            for obj in objects:
                object_name = obj.get('object_name') or obj.get('name')
                embedded = obj.get('fields')
                if isinstance(embedded, (list, tuple, dict)):
                    for field in self._dict_rows(embedded, 'field_name', ('fields', 'rows', 'items')):
                        field.setdefault('object_name', object_name)
                        fields.append(field)
        object_rows = []
        for index, entry in enumerate(objects):
            object_rows.append([
                _integer(index + 1), _text(entry.get('object_name') or entry.get('name')),
                _text(entry.get('object_kind') or entry.get('kind') or entry.get('type')),
                _join(entry.get('data_interactions')), _join(entry.get('crud_intents')),
                _join(entry.get('operation_ids') or entry.get('operations')),
                _integer(_count(entry.get('fields'))), _join(entry.get('groups')),
                _join(entry.get('auth_kinds')), _text(entry.get('confidence')),
                _packet_text(entry.get('packet_nos')), _join(entry.get('reasons'))])
        field_rows = []
        for index, entry in enumerate(fields):
            field_rows.append([
                _integer(index + 1), _text(entry.get('object_name') or entry.get('object')),
                _text(entry.get('field_name') or entry.get('name') or entry.get('path')),
                _text(entry.get('field_kind') or entry.get('field_type') or entry.get('type')),
                _text(entry.get('focus_type')), _join(entry.get('sources')),
                _join(entry.get('crud_intents')),
                _join(entry.get('operation_ids') or entry.get('operations')), _join(entry.get('groups')),
                _join(entry.get('auth_kinds')), _text(entry.get('confidence')),
                _packet_text(entry.get('packet_nos')), _join(entry.get('reasons'))])
        return object_rows, objects, field_rows, fields

    def _set_objects_fields(self, result=None, prepared=None):
        values = prepared if prepared is not None else self._format_objects_fields(result or {})
        object_rows, objects, field_rows, fields = values
        self.object_model.set_rows(object_rows, objects)
        self.field_model.set_rows(field_rows, fields)

    def _format_apps_endpoints(self, result):
        combined = result.get('app_endpoint_catalog') or {}
        app_source = result.get('application_catalog') or (
            combined.get('applications') if isinstance(combined, dict) else [])
        aura_endpoint_source = (combined.get('endpoints') if isinstance(combined, dict) else combined)
        # 全HTTP endpoint inventoryを優先する。従来のAura endpoint catalogは
        # Applications側の互換表示にだけ利用する。
        endpoint_source = result.get('endpoint_catalog') or result.get('endpoints') or (
            combined.get('endpoints') if isinstance(combined, dict) else combined)
        endpoints = self._dict_rows(endpoint_source, 'aura_endpoint', ('endpoints', 'rows', 'items'))
        aura_endpoints = self._dict_rows(
            aura_endpoint_source, 'aura_endpoint', ('endpoints', 'rows', 'items'))
        apps = self._dict_rows(app_source, 'app_id', ('applications', 'apps', 'rows', 'items'))
        if not apps:
            grouped = {}
            for endpoint in aura_endpoints:
                key = (_text(endpoint.get('app_id')), _text(endpoint.get('host')))
                app = grouped.setdefault(key, {
                    'app_id': endpoint.get('app_id'), 'host': endpoint.get('host'),
                    'is_default_app': endpoint.get('is_default_app'), 'features': [],
                    'default_app_confidence': endpoint.get('default_app_confidence'),
                    'default_app_reasons': [], 'endpoints': [], 'operation_ids': [],
                    'groups': [], 'session_fingerprints': [], 'packet_nos': []})
                for target, source in (('features', endpoint.get('features')),
                                       ('default_app_reasons', endpoint.get('default_app_reasons')),
                                       ('operation_ids', endpoint.get('operation_ids')),
                                       ('groups', endpoint.get('groups')),
                                       ('session_fingerprints', endpoint.get('session_fingerprints')),
                                       ('packet_nos', endpoint.get('packet_nos'))):
                    for item in source or []:
                        if item not in app[target]: app[target].append(item)
                endpoint_value = endpoint.get('aura_endpoint') or endpoint.get('endpoint') or endpoint.get('path')
                if endpoint_value and endpoint_value not in app['endpoints']:
                    app['endpoints'].append(endpoint_value)
            apps = list(grouped.values())
        app_rows = []
        for index, entry in enumerate(apps):
            app_rows.append([
                _integer(index + 1), _text(entry.get('app_id') or entry.get('application')),
                _text(entry.get('host')), _text(entry.get('is_default_app')),
                _text(entry.get('default_app_confidence')), _join(entry.get('default_app_reasons')),
                _join(entry.get('features') or entry.get('salesforce_features')),
                _integer(_count(entry.get('endpoints') or entry.get('aura_endpoints'))),
                _join(entry.get('operation_ids')), _join(entry.get('groups')),
                _join(entry.get('session_fingerprints') or entry.get('sessions')),
                _packet_text(entry.get('packet_nos'))])
        endpoint_rows = []
        for index, entry in enumerate(endpoints):
            endpoint_rows.append([
                _integer(index + 1), _text(entry.get('route_classification')),
                _text(entry.get('route_confidence')), _join(entry.get('route_evidence')),
                _text(entry.get('destination_label')), _text(entry.get('destination_confidence')),
                _text(entry.get('destination_source')), _text(entry.get('protocol_kind')),
                _text(entry.get('host')), _text(entry.get('method')),
                _text(entry.get('path') or entry.get('normalized_path') or entry.get('aura_endpoint')),
                _join(entry.get('data_interactions')), _join(entry.get('request_content_types')),
                _join(entry.get('response_content_types')), _join(entry.get('status_codes')),
                _join(entry.get('parameters')), _join(entry.get('operation_ids')),
                _join(entry.get('groups')), _join(entry.get('session_fingerprints') or entry.get('sessions')),
                _integer(entry.get('occurrences')), _packet_text(entry.get('packet_nos'))])
        return app_rows, apps, endpoint_rows, endpoints

    def _set_apps_endpoints(self, result=None, prepared=None):
        values = prepared if prepared is not None else self._format_apps_endpoints(result or {})
        app_rows, apps, endpoint_rows, endpoints = values
        self.app_model.set_rows(app_rows, apps)
        self.endpoint_model.set_rows(endpoint_rows, endpoints)

    def _format_packet_catalog(self, packets):
        entries = self._dict_rows(packets, 'packet_no', ('packets', 'rows', 'items'))
        rows = []
        for entry in entries:
            operation_ids = entry.get('operation_ids') or []
            rows.append([
                _integer(entry.get('packet_no')), _text(entry.get('route_classification')),
                _text(entry.get('destination_label')), _text(entry.get('protocol_kind')),
                _text(entry.get('host')), _text(entry.get('method')),
                _text(entry.get('path') or entry.get('normalized_path')),
                _text(entry.get('status')), _join(entry.get('groups')),
                _join(operation_ids), _integer(entry.get('operation_count', _count(operation_ids)))])
        return rows, entries

    def _set_packet_catalog(self, prepared=None):
        rows, entries = prepared if prepared is not None else ([], [])
        self.packet_model.set_rows(rows, entries)

    def _format_coverage(self, result):
        coverage = result.get('planning_coverage') or {}
        if isinstance(coverage, dict):
            summary = coverage.get('summary') or coverage.get('metrics') or {}
            rows_source = coverage.get('rows') or coverage.get('gaps') or []
        else:
            summary = {}
            rows_source = coverage
        if not summary:
            top_summary = result.get('summary') or {}
            summary = {}
            for key in ('planning_gaps', 'technical_gaps', 'sessions', 'session_fingerprints',
                        'unique_operations', 'objects', 'fields', 'apps', 'aura_endpoints'):
                if key in top_summary:
                    summary[key] = top_summary.get(key)
        entries = self._dict_rows(rows_source, row_keys=('rows', 'gaps', 'items'))
        entries.extend(self._dict_rows(result.get('planning_gaps') or [], row_keys=('rows', 'gaps', 'items')))
        unique_entries = []
        seen_gap_ids = set()
        for entry in entries:
            gap_id = _text(entry.get('gap_id'))
            if gap_id and gap_id in seen_gap_ids:
                continue
            if gap_id:
                seen_gap_ids.add(gap_id)
            unique_entries.append(entry)
        entries = unique_entries
        summary_rows = []
        if isinstance(summary, dict):
            for key in sorted(summary.keys(), key=lambda value: _text(value).lower()):
                summary_rows.append([_text(key).replace(u'_', u' ').title(), _join(summary.get(key))])
        summary_rows.append([u'Planning gaps', _text(len(entries))])
        rows = []
        for index, entry in enumerate(entries):
            state = _text(entry.get('state') or entry.get('status'))
            if state.lower() == u'denied':
                state = u'Unknown'
            if not state:
                state = u'Not observed'
            rows.append([
                _integer(index + 1), _text(entry.get('category')), _text(entry.get('severity')),
                _text(entry.get('scope')), _text(entry.get('operation') or entry.get('operation_id')),
                state, _text(entry.get('reason')), _text(entry.get('recommendation')),
                _join(entry.get('evidence'))])
        return summary_rows, rows, entries

    def _set_coverage(self, result=None, prepared=None):
        values = prepared if prepared is not None else self._format_coverage(result or {})
        summary_rows, rows, entries = values
        self.coverage_summary_model.set_rows(summary_rows)
        self.coverage_model.set_rows(rows, entries)

    def _show_selected_operation(self):
        view_row = self.operation_table.getSelectedRow()
        if view_row < 0:
            self._show_operation(None)
            return
        model_row = self.operation_table.convertRowIndexToModel(view_row)
        self._show_operation(self.operation_model.entry_at(model_row))

    def _show_operation(self, operation):
        parameters = (operation or {}).get('parameters') or []
        parameter_rows = []
        for index, entry in enumerate(parameters):
            parameter_rows.append([
                _integer(index + 1), _text(entry.get('region')), _text(entry.get('type')),
                _text(entry.get('nesting')), _text(entry.get('path') or entry.get('parameter_path')),
                _integer(entry.get('occurrences')),
                _packet_text(entry.get('packet_nos') or entry.get('packet_no')),
                _join(entry.get('sample_values') or entry.get('value_samples') or entry.get('values')),
                _classification(entry), _score_reasons(entry)])
        self.parameter_model.set_rows(parameter_rows, parameters)

        response_entries = self._response_entries(operation or {})
        response_rows = []
        for index, entry in enumerate(response_entries):
            response_rows.append([
                _integer(index + 1), _text(entry.get('path') or entry.get('name') or entry.get('field')),
                _text(entry.get('type')), _integer(entry.get('occurrences')),
                _packet_text(entry.get('packet_nos') or entry.get('packet_no')),
                _join(entry.get('sample_values') or entry.get('value_samples') or entry.get('values'))])
        self.response_model.set_rows(response_rows, response_entries)
        item = (operation or {}).get('representative_item')
        if item is None and operation:
            item = self._packet_items.get(_text(operation.get('representative_packet_no')))
        try:
            request = item.getRequest() if item is not None else None
            response = item.getResponse() if item is not None else None
            self.request_editor.setMessage(request if request is not None else self._empty_bytes, True)
            self.response_editor.setMessage(response if response is not None else self._empty_bytes, False)
        except Exception as error:
            if self.error_fn:
                self.error_fn(u'Authorization Planning',
                              u'Representative message preview failed: %s' % _text(error))

    def _response_entries(self, operation):
        entries = []
        seen = set()
        for values in (operation.get('response_fields') or [],
                       operation.get('response_schema_paths') or []):
            if isinstance(values, dict):
                iterable = []
                for path, detail in values.items():
                    entry = dict(detail) if isinstance(detail, dict) else {'type': detail}
                    entry.setdefault('path', path)
                    iterable.append(entry)
            elif isinstance(values, (list, tuple, set)):
                iterable = values
            else:
                iterable = [values]
            for value in iterable:
                entry = value if isinstance(value, dict) else {'path': value}
                path = _text(entry.get('path') or entry.get('name') or entry.get('field'))
                if path in seen:
                    continue
                seen.add(path)
                entries.append(entry)
        return entries

    def _queue_filter(self):
        self._filter_timer.restart()

    def _apply_sorter_filter(self, sorter):
        filters = []
        global_query = _text(self.find_field.getText())
        local_query = self._local_queries.get(sorter, u'')
        for query in (global_query, local_query):
            if query:
                filters.append(RowFilter.regexFilter(u'(?i)' + Pattern.quote(query)))
        if not filters:
            sorter.setRowFilter(None)
        elif len(filters) == 1:
            sorter.setRowFilter(filters[0])
        else:
            sorter.setRowFilter(RowFilter.andFilter(filters))

    def _apply_filter(self):
        for sorter in self._sorters:
            self._apply_sorter_filter(sorter)

    def _on_clear(self, event):
        if self._worker is not None:
            return
        for model in (self.summary_model, self.operation_model, self.parameter_model, self.response_model,
                      self.access_model, self.object_model, self.field_model, self.app_model,
                      self.endpoint_model, self.packet_model, self.coverage_summary_model, self.coverage_model,
                      self.plan_model, self.session_model, self.gap_model, self.resource_model):
            model.set_rows([])
        self._packet_items = {}
        self.find_field.setText(u'')
        for binding in self._local_filter_bindings:
            binding.field.setText(u'')
        self._local_queries.clear()
        self._show_operation(None)
        self.progress.setIndeterminate(False)
        self.progress.setValue(0)
        self.progress.setString(u'Idle')
        self.status_label.setText(u'Cleared. Range fields were preserved.')
