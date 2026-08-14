# -*- coding: utf-8 -*-
"""History annotation tools kept separate from the Statistics view."""

from threading import Thread

from java.awt import BorderLayout, FlowLayout
from java.lang import Runnable
from javax.swing import (JButton, JLabel, JPanel, JTextField, SwingUtilities, JOptionPane,
                         BoxLayout, BorderFactory)

from csvlistinput import statistics_engine


class _UiRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


class AnnotationsPanel(JPanel):
    """Numbering, grouping and bracket-tag cleanup for Proxy HTTP History."""

    def __init__(self, callbacks, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.callbacks = callbacks
        self.log_fn = log_fn
        self.error_fn = error_fn
        self._worker = None
        self._active_button = None
        self._button_labels = {}

        controls = JPanel(); controls.setLayout(BoxLayout(controls, BoxLayout.Y_AXIS))

        range_section = JPanel(FlowLayout(FlowLayout.LEFT))
        range_section.setBorder(BorderFactory.createTitledBorder('1. Packet range'))
        range_section.add(JLabel('Packet No range:'))
        self.start_field = JTextField(6)
        self.end_field = JTextField(6)
        range_section.add(self.start_field)
        range_section.add(JLabel('to'))
        range_section.add(self.end_field)
        range_section.add(JButton('All', actionPerformed=self._on_all))
        controls.add(range_section)

        numbering_section = JPanel(FlowLayout(FlowLayout.LEFT))
        numbering_section.setBorder(BorderFactory.createTitledBorder('2. Numbering'))
        numbering_section.add(JLabel('Start:'))
        self.number_start = JTextField('1', 5)
        numbering_section.add(self.number_start)
        numbering_section.add(JLabel('Digits:'))
        self.number_digits = JTextField('4', 3)
        numbering_section.add(self.number_digits)
        self.number_button = JButton('Number all', actionPerformed=self._on_number)
        numbering_section.add(self.number_button)
        self.remove_number_button = JButton('Remove numbering', actionPerformed=self._on_remove_number)
        numbering_section.add(self.remove_number_button)
        controls.add(numbering_section)

        grouping_section = JPanel(FlowLayout(FlowLayout.LEFT))
        grouping_section.setBorder(BorderFactory.createTitledBorder('3. Group cleanup'))
        grouping_section.add(JLabel('Group name:'))
        self.group_name = JTextField(14)
        grouping_section.add(self.group_name)
        self.clear_group_button = JButton('Clear group in range', actionPerformed=self._on_clear_group)
        grouping_section.add(self.clear_group_button)
        controls.add(grouping_section)

        cleanup_section = JPanel(FlowLayout(FlowLayout.LEFT))
        cleanup_section.setBorder(BorderFactory.createTitledBorder('4. Comment tag cleanup'))
        self.clear_tags_button = JButton('Clear all [tags] in range', actionPerformed=self._on_clear_tags)
        cleanup_section.add(self.clear_tags_button)
        controls.add(cleanup_section)
        for button in (self.number_button, self.remove_number_button,
                       self.clear_group_button, self.clear_tags_button):
            self._button_labels[button] = button.getText()
        self.add(controls, BorderLayout.NORTH)

        help_text = ('Numbering adds [0001] at the start of each comment. '
                     'Grouping adds [group="name"]. The range fields are empty for all HTTP History. '
                     'Clear all [tags] removes bracket annotations, including numbering and groups.')
        self.status = JLabel(help_text)
        self.add(self.status, BorderLayout.SOUTH)

    def _range(self):
        def parse(value):
            value = str(value).strip()
            if not value:
                return None
            number = int(value)
            if number < 1:
                raise ValueError()
            return number
        try:
            start, end = parse(self.start_field.getText()), parse(self.end_field.getText())
            if start is not None and end is not None and start > end:
                raise ValueError()
            return start, end
        except ValueError:
            self.status.setText('Packet No must be a positive range with start no greater than end.')
            return None, 'error'

    def _on_all(self, event):
        self.start_field.setText('')
        self.end_field.setText('')
        self.status.setText('Range set to all HTTP History.')

    def _set_busy(self, busy, label=None):
        buttons = (self.number_button, self.remove_number_button,
                   self.clear_group_button, self.clear_tags_button)
        for button in buttons:
            # Explicitly release Swing's armed/pressed model before disabling
            # the button. Otherwise some Burp/Jython Look & Feel combinations
            # leave the clicked button painted as if it were still held down.
            model = button.getModel()
            model.setPressed(False)
            model.setArmed(False)
            button.setEnabled(not busy)
            if not busy:
                button.setText(self._button_labels[button])
        if busy and self._active_button is not None:
            self._active_button.setText('Working...')
            self._active_button.repaint()
        if label:
            self.status.setText(label + ' (background)...')
        self.revalidate()
        self.repaint()

    def _run(self, label, worker, button=None):
        if self._worker is not None:
            self.status.setText('An operation is already running.')
            return
        self._worker = True
        self._active_button = button
        self._set_busy(True, label)

        def run():
            try:
                result = worker()
                SwingUtilities.invokeLater(_UiRunnable(lambda: self._finished(label, result)))
            except Exception as error:
                SwingUtilities.invokeLater(_UiRunnable(lambda e=error: self._failed(label, e)))
        thread = Thread(target=run)
        thread.setDaemon(True)
        thread.start()

    def _finished(self, label, result):
        self._worker = None
        self._set_busy(False)
        self._active_button = None
        self.status.setText('%s complete: %s.' % (label, result))
        if self.log_fn:
            self.log_fn('Annotations: %s complete: %s.' % (label, result))

    def _failed(self, label, error):
        self._worker = None
        self._set_busy(False)
        self._active_button = None
        self.status.setText('%s failed: %s' % (label, error))
        if self.error_fn:
            self.error_fn('Annotations', '%s failed: %s' % (label, error))

    def _on_number(self, event):
        try:
            start = int(str(self.number_start.getText()).strip())
            digits = int(str(self.number_digits.getText()).strip())
            if start < 0 or digits < 1:
                raise ValueError()
        except ValueError:
            self.status.setText('Start must be 0 or greater and digits must be 1 or greater.')
            return
        self._run('Numbering all History', lambda: statistics_engine.number_all(
            self.callbacks, start, digits), self.number_button)

    def _on_remove_number(self, event):
        self._run('Removing numbering', lambda: statistics_engine.remove_numbering(self.callbacks),
                  self.remove_number_button)

    def _on_clear_group(self, event):
        start, end = self._range()
        if end == 'error':
            return
        self._run('Clearing group', lambda: statistics_engine.remove_group(
            self.callbacks, start, end, self.group_name.getText()), self.clear_group_button)

    def _on_clear_tags(self, event):
        start, end = self._range()
        if end == 'error':
            return
        ret = JOptionPane.showConfirmDialog(
            self, 'Remove every [tag] from comments in the selected range? '
                 'This also removes numbering and group tags.',
            'Clear all bracket tags', JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
        if ret != JOptionPane.YES_OPTION:
            return
        self._run('Clearing bracket tags', lambda: statistics_engine.clear_bracket_tags(
            self.callbacks, start, end), self.clear_tags_button)
