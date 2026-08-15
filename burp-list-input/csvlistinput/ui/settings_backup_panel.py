# -*- coding: utf-8 -*-
"""Backup/restore UI for portable MyTools Markdown settings files."""

import traceback
from threading import Thread

from java.awt import BorderLayout, FlowLayout
from java.lang import Runnable
from javax.swing import SwingUtilities
from javax.swing import JButton, JFileChooser, JLabel, JOptionPane, JPanel

from csvlistinput import settings_backup


class _UiRunnable(Runnable):
    def __init__(self, fn): self.fn = fn
    def run(self): self.fn()


class SettingsBackupPanel(JPanel):
    def __init__(self, word_store, color_store, comment_store, request_rule_store, response_rule_store, csv_store,
                 on_word_list_restored=None, on_rules_restored=None, on_csv_restored=None, log_fn=None, error_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.word_store = word_store
        self.color_store = color_store
        self.comment_store = comment_store
        self.request_rule_store = request_rule_store
        self.response_rule_store = response_rule_store
        self.csv_store = csv_store
        self.on_word_list_restored = on_word_list_restored
        self.on_rules_restored = on_rules_restored
        self.on_csv_restored = on_csv_restored
        self.log_fn = log_fn
        self.error_fn = error_fn
        self._worker = None
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        self.export_button = JButton('Export backup (.md)...', actionPerformed=self._on_export)
        self.restore_button = JButton('Restore backup (.md)...', actionPerformed=self._on_restore)
        top.add(self.export_button)
        top.add(self.restore_button)
        self.add(top, BorderLayout.NORTH)
        self.status = JLabel(
            'Exports/restores My Word List, Target & List Mapping CSV, and Match & Replace rules. '
            'Color Snapshots and Comment Snapshots are not included.')
        self.add(self.status, BorderLayout.CENTER)

    def _on_export(self, event):
        if self._worker is not None:
            return
        chooser = JFileChooser()
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith('.md'):
            path += '.md'
        self._set_busy('export')
        self._worker = Thread(target=self._export_worker, args=(path,))
        self._worker.setDaemon(True)
        self._worker.start()

    def _export_worker(self, path):
        try:
            content = settings_backup.export_markdown(
                self.word_store, self.color_store, self.comment_store,
                self.request_rule_store, self.response_rule_store, self.csv_store)
            handle = open(path, 'wb')
            try:
                handle.write(content.encode('utf-8'))
            finally:
                handle.close()
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._export_finished(path)))
        except Exception as error:
            detail = traceback.format_exc()
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._export_failed(error, detail)))

    def _export_finished(self, path):
        self._set_idle()
        self.status.setText('Backup exported: %s' % path)
        if self.log_fn:
            self.log_fn('Settings Backup: exported %s' % path)

    def _export_failed(self, error, detail):
        self._set_idle()
        self.status.setText('Backup export failed: %s' % error)
        if self.error_fn:
            self.error_fn('Settings Backup', 'Export failed: %s' % error, detail)

    def _on_restore(self, event):
        if self._worker is not None:
            return
        chooser = JFileChooser()
        if chooser.showOpenDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        answer = JOptionPane.showConfirmDialog(
            self, 'Restore this backup? This replaces the active My Word List, Target & List Mapping CSV, Match & Replace rules, '
            'but does not change Color Snapshots, Comment Snapshots, or the current Proxy History.',
            'Restore MyTools Backup',
            JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE)
        if answer != JOptionPane.YES_OPTION:
            return
        self._set_busy('restore')
        self._worker = Thread(target=self._restore_worker, args=(path,))
        self._worker.setDaemon(True)
        self._worker.start()

    def _restore_worker(self, path):
        try:
            handle = open(path, 'rb')
            try:
                content = handle.read().decode('utf-8-sig')
            finally:
                handle.close()
            result = settings_backup.restore_markdown(
                content, self.word_store, self.color_store, self.comment_store,
                self.request_rule_store, self.response_rule_store, self.csv_store)
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._restore_finished(result, path)))
        except Exception as error:
            detail = traceback.format_exc()
            SwingUtilities.invokeLater(_UiRunnable(lambda: self._restore_failed(error, detail)))

    def _restore_finished(self, result, path):
        words, _colors, _comments, request_rules, response_rules, mapping_rows = result
        self._set_idle()
        if self.on_word_list_restored:
            self.on_word_list_restored()
        if self.on_rules_restored:
            self.on_rules_restored()
        if self.on_csv_restored:
            self.on_csv_restored()
        rules_text = ('%d request / %d response rule(s)' % (request_rules, response_rules)
                      if request_rules is not None else 'Match & Replace rules unchanged (legacy backup)')
        mapping_text = '%d Target & List Mapping CSV row(s)' % mapping_rows if mapping_rows is not None else 'Target & List Mapping CSV unchanged (legacy backup)'
        self.status.setText('Restored: %d word(s), %s, %s.' % (words, rules_text, mapping_text))
        if self.log_fn:
            self.log_fn('Backup & Restore: restored %d words, %s, %s from %s' %
                        (words, rules_text, mapping_text, path))

    def _restore_failed(self, error, detail):
        self._set_idle()
        self.status.setText('Backup restore failed: %s' % error)
        if self.error_fn:
            self.error_fn('Settings Backup', 'Restore failed: %s' % error, detail)

    def _set_busy(self, operation):
        self.export_button.setEnabled(False)
        self.restore_button.setEnabled(False)
        if operation == 'export':
            self.export_button.setText('Exporting...')
            self.status.setText('Exporting backup in the background...')
        else:
            self.restore_button.setText('Restoring...')
            self.status.setText('Restoring backup in the background...')
        self.revalidate(); self.repaint()

    def _set_idle(self):
        self._worker = None
        self.export_button.setEnabled(True)
        self.restore_button.setEnabled(True)
        self.export_button.setText('Export backup (.md)...')
        self.restore_button.setText('Restore backup (.md)...')

    # Old synchronous implementations were intentionally replaced by the
    # worker methods above; do not perform snapshot conversion on the EDT.
    def _legacy_restore_removed(self):
        pass
