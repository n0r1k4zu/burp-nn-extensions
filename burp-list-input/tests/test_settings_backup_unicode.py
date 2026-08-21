# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from csvlistinput import settings_backup
from csvlistinput.replace_rule_store import ReplaceRule


class _WordStore(object):
    def __init__(self): self.rows = [{'word': u'日本語', 'is_regex': False, 'comment': u'コメント'}]
    def snapshot(self): return list(self.rows)
    def replace(self, rows): self.rows = list(rows)


class _RuleStore(object):
    def __init__(self): self.rules = [ReplaceRule(u'検索', u'置換')]
    def snapshot(self): return list(self.rules)
    def replace_rules(self, rules): self.rules = list(rules)


class _CsvStore(object):
    def __init__(self): self.payload = {'headers': [u'No', u'項目'], 'rows': [[u'1', u'値']], 'start_row': 1}
    def backup_snapshot(self): return dict(self.payload)
    def restore_snapshot(self, payload): self.payload = payload


class SettingsBackupUnicodeTest(unittest.TestCase):
    def test_export_and_restore_preserves_japanese_csv_cells(self):
        words, request_rules, response_rules, csv_store = _WordStore(), _RuleStore(), _RuleStore(), _CsvStore()
        markdown = settings_backup.export_markdown(words, object(), object(), request_rules, response_rules, csv_store)
        self.assertIn(u'日本語', markdown)
        self.assertIn(u'コメント', markdown)
        self.assertIn(u'項目', markdown)
        target_words, target_request, target_response, target_csv = _WordStore(), _RuleStore(), _RuleStore(), _CsvStore()
        target_words.rows = []
        result = settings_backup.restore_markdown(
            markdown, target_words, object(), object(), target_request, target_response, target_csv)
        self.assertEqual(u'日本語', target_words.rows[0]['word'])
        self.assertEqual(u'コメント', target_words.rows[0]['comment'])
        self.assertEqual(u'項目', target_csv.payload['headers'][1])
        self.assertEqual(1, result[0])


if __name__ == '__main__':
    unittest.main()
