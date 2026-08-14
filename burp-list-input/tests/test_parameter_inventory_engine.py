# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from csvlistinput import parameter_inventory_engine


class ParameterInventoryRiskTest(unittest.TestCase):
    def test_aggressive_focus_expands_candidates_without_changing_default(self):
        self.assertIsNone(parameter_inventory_engine.risk_level('profileName'))
        self.assertEqual('medium', parameter_inventory_engine.risk_level('profileName', True))
        self.assertIsNone(parameter_inventory_engine.risk_level('userPreferences'))
        self.assertEqual('high', parameter_inventory_engine.risk_level('userPreferences', True))


if __name__ == '__main__':
    unittest.main()
