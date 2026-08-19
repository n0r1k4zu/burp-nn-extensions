# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from csvlistinput import parameter_inventory_engine


class _Point(object):
    def __init__(self, path, value):
        self.path = path
        self.original_value = value
        self.type = 'JSON_LEAF'


class _Item(object):
    def getRequest(self): return 'request'
    def getHttpService(self): return None
    def getComment(self): return '注釈 [group="日本語"]'.encode('utf-8')


class _Callbacks(object):
    def getProxyHistory(self): return [_Item()]


class ParameterInventoryRiskTest(unittest.TestCase):
    def test_aggressive_focus_expands_candidates_without_changing_default(self):
        self.assertIsNone(parameter_inventory_engine.risk_level('profileName'))
        self.assertEqual('medium', parameter_inventory_engine.risk_level('profileName', True))
        self.assertIsNone(parameter_inventory_engine.risk_level('userPreferences'))
        self.assertEqual('high', parameter_inventory_engine.risk_level('userPreferences', True))

    def test_collect_normalizes_non_ascii_paths_values_and_comments(self):
        points = [_Point('$.日本語'.encode('utf-8'), '値'.encode('utf-8'))]
        rows = parameter_inventory_engine.collect(
            _Callbacks(), object(), detector=lambda helpers, request, service: points)
        self.assertEqual(u'$.日本語', rows[0]['path'])
        self.assertEqual([u'日本語'], rows[0]['groups'])
        self.assertEqual(u'値', parameter_inventory_engine.value_rows(rows[0])[0]['value'])


if __name__ == '__main__':
    unittest.main()
