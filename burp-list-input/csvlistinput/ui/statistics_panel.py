# -*- coding: utf-8 -*-
"""Passive History statistics and Aura-aware aggregation UI."""

from threading import Thread

from java.awt import BorderLayout, FlowLayout
from java.lang import Integer, Runnable
from javax.swing import (JButton, JCheckBox, JComboBox, JLabel, JPanel, JScrollPane, JTable,
                          JTextField, SwingUtilities, JOptionPane, BoxLayout, BorderFactory)
from javax.swing.table import AbstractTableModel

from csvlistinput import statistics_engine


class _UiRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn
    def run(self):
        self.fn()


class _SummaryModel(AbstractTableModel):
    COLUMNS = ['Class', 'Packets (including aggregation)', 'Packets (excluding aggregation)', 'Definition']
    def __init__(self):
        AbstractTableModel.__init__(self)
        self.rows = []
    def set_rows(self, rows):
        self.rows = rows
        self.fireTableDataChanged()
    def getRowCount(self): return len(self.rows)
    def getColumnCount(self): return len(self.COLUMNS)
    def getColumnName(self, col): return self.COLUMNS[col]
    def getColumnClass(self, col): return Integer if col in (1, 2) else str
    def getValueAt(self, row, col):
        data = self.rows[row]
        return [data['class'], Integer(data['including_aggregated']),
                Integer(data['excluding_aggregated']), data['definition']][col]


class StatisticsPanel(JPanel):
    def __init__(self, callbacks, helpers, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.helpers = helpers
        self.log_fn = log_fn
        self.error_fn = error_fn
        self.records = []
        self._worker = None

        top = JPanel(); top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

        build_section = JPanel(FlowLayout(FlowLayout.LEFT))
        build_section.setBorder(BorderFactory.createTitledBorder('1. Build statistics'))
        build_section.add(JLabel('Packet No range:'))
        self.start_field = JTextField(6); build_section.add(self.start_field)
        build_section.add(JLabel('to'))
        self.end_field = JTextField(6); build_section.add(self.end_field)
        build_section.add(JButton('All', actionPerformed=self._on_all))
        self.build_button = JButton('Build statistics', actionPerformed=self._on_build); build_section.add(self.build_button)
        self._build_button_text = 'Build statistics'
        top.add(build_section)

        annotation_section = JPanel(); annotation_section.setLayout(BoxLayout(annotation_section, BoxLayout.Y_AXIS))
        annotation_section.setBorder(BorderFactory.createTitledBorder('2. Annotation options'))
        self.add_class = JCheckBox('Add class [tag] to comments', True); annotation_section.add(self.add_class)
        self.add_agg = JCheckBox('Add aggregation [tag] to comments', True); annotation_section.add(self.add_agg)
        color_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.color_targets = JCheckBox('Color aggregation targets', False); color_row.add(self.color_targets)
        color_row.add(JLabel('Color:'))
        self.color_combo = JComboBox(['gray', 'yellow', 'cyan', 'orange', 'magenta']); color_row.add(self.color_combo)
        annotation_section.add(color_row)
        top.add(annotation_section)

        apply_section = JPanel(FlowLayout(FlowLayout.LEFT))
        apply_section.setBorder(BorderFactory.createTitledBorder('3. Apply annotations to analyzed packets'))
        self.apply_button = JButton('Apply selected annotations', actionPerformed=self._on_apply); apply_section.add(self.apply_button)
        self._apply_button_text = 'Apply selected annotations'
        self.clear_annotations_button = JButton('Clear annotations', actionPerformed=self._on_clear_annotations)
        apply_section.add(self.clear_annotations_button)
        self._clear_annotations_button_text = 'Clear annotations'
        top.add(apply_section)
        self.add(top, BorderLayout.NORTH)

        self.model = _SummaryModel()
        self.table = JTable(self.model)
        center = JPanel(BorderLayout())
        center.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0))
        center.add(JScrollPane(self.table), BorderLayout.CENTER)
        definitions = JLabel('Definitions: Web screen = non-SPA HTML; web part = static asset; '
                             'SPA screen = SPA bootstrap HTML; SPA update = Aura message/context; API = other API-like traffic. '
                             'Aggregation groups adjacent Aura updates with the same key.')
        center.add(definitions, BorderLayout.SOUTH)
        self.add(center, BorderLayout.CENTER)
        self.status = JLabel('Build statistics for a Packet No range or All. Use Numbering & Grouping for comment annotations.')
        self.add(self.status, BorderLayout.SOUTH)

    def _range(self):
        def parse(value):
            value = str(value).strip()
            if not value: return None
            number = int(value)
            if number < 1: raise ValueError()
            return number
        try:
            start, end = parse(self.start_field.getText()), parse(self.end_field.getText())
            if start is not None and end is not None and start > end: raise ValueError()
            return start, end
        except ValueError:
            self.status.setText('Packet No must be a positive range with start no greater than end.')
            return None, 'error'

    def _on_all(self, event):
        self.start_field.setText(''); self.end_field.setText(''); self.status.setText('Range set to all HTTP History.')

    def _run(self, label, worker, finish=None):
        if self._worker is not None:
            self.status.setText('An operation is already running.')
            return
        self._worker = True
        self.build_button.setEnabled(False); self.apply_button.setEnabled(False)
        self.clear_annotations_button.setEnabled(False)
        self.build_button.setText('Building...' if label == 'Building statistics' else 'Build statistics')
        self.apply_button.setText('Applying...' if label == 'Applying annotations' else 'Apply selected annotations')
        self.clear_annotations_button.setText('Clearing...' if label == 'Clearing annotations' else 'Clear annotations')
        self.status.setText(label + ' (background)...')
        def run():
            try:
                result = worker()
                SwingUtilities.invokeLater(_UiRunnable(lambda: self._finished(label, result, finish)))
            except Exception as e:
                SwingUtilities.invokeLater(_UiRunnable(lambda error=e: self._failed(label, error)))
        thread = Thread(target=run); thread.setDaemon(True); thread.start()

    def _finished(self, label, result, finish):
        self._worker = None
        self._restore_operation_buttons()
        if finish: finish(result)
        else: self.status.setText('%s complete: %s.' % (label, result))
        if self.log_fn: self.log_fn('Statistics: %s complete: %s.' % (label, result))

    def _failed(self, label, error):
        self._worker = None; self._restore_operation_buttons(); self.status.setText('%s failed: %s' % (label, error))
        if self.error_fn: self.error_fn('Statistics', '%s failed: %s' % (label, error))

    def _restore_operation_buttons(self):
        self.build_button.setEnabled(True); self.build_button.setText(self._build_button_text)
        self.apply_button.setEnabled(True); self.apply_button.setText(self._apply_button_text)
        self.clear_annotations_button.setEnabled(True); self.clear_annotations_button.setText(self._clear_annotations_button_text)

    def _on_build(self, event):
        start, end = self._range()
        if end == 'error': return
        self._run('Building statistics', lambda: statistics_engine.analyze_history(self.callbacks, self.helpers, start, end),
                  lambda records: self._set_records(records, start, end))

    def _set_records(self, records, start, end):
        self.records = records; self.model.set_rows(statistics_engine.summary_rows(records))
        targets = len([record for record in records if record['agg_role'] == u'target'])
        scope = 'all HTTP History' if start is None and end is None else 'selected range'
        self.status.setText('%d packet(s) analyzed in %s; %d aggregation target(s).' % (len(records), scope, targets))

    def _on_apply(self, event):
        if not self.records:
            self.status.setText('Build statistics before applying annotations.')
            return
        self._run('Applying annotations', lambda: statistics_engine.annotate_analysis(
            self.records, self.add_class.isSelected(), self.add_agg.isSelected(), False,
            self.color_targets.isSelected(), str(self.color_combo.getSelectedItem())))

    def _on_clear_annotations(self, event):
        start, end = self._range()
        if end == 'error':
            return
        ret = JOptionPane.showConfirmDialog(
            self, 'Remove only Statistics-generated class and aggregation tags from the selected range? '
                 'Numbering, groups and unrelated tags will remain.',
            'Clear Statistics annotations', JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
        if ret != JOptionPane.YES_OPTION:
            return
        self._run('Clearing annotations', lambda: statistics_engine.clear_analysis_annotations(
            self.callbacks, start, end))
