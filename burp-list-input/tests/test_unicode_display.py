# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from csvlistinput.utils import to_display_text


class UnicodeDisplayTest(unittest.TestCase):
    def test_utf8_packet_bytes_are_safe_display_text(self):
        self.assertEqual(u'日本語', to_display_text(u'日本語'.encode('utf-8')))

    def test_non_utf8_bytes_fall_back_without_failure(self):
        self.assertEqual(u'\xff', to_display_text(b'\xff'))


if __name__ == '__main__':
    unittest.main()
