# -*- coding: utf-8 -*-
"""Regression tests for the bounded live-search path."""

import os
import sys
import unittest

THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(THIS_DIR))

from csvlistinput import word_search_engine
from csvlistinput.replace_engine import _apply_rules_to_text
from csvlistinput.replace_rule_store import ReplaceRule


class WordSearchEngineTest(unittest.TestCase):
    def test_history_search_limits_packet_number_range(self):
        class Item(object):
            def __init__(self, request):
                self.request = request

            def getRequest(self):
                return self.request

            def getResponse(self):
                return None

            def getHttpService(self):
                return None

        class Callbacks(object):
            def getProxyHistory(self):
                return [Item("first"), Item("match second"), Item("match third")]

        class Helpers(object):
            def bytesToString(self, value):
                return value

        hits = word_search_engine.search(Callbacks(), Helpers(), "match", 0, 0,
                                         start_packet_no=2, end_packet_no=2)

        self.assertEqual(1, len(hits))
        self.assertEqual(2, hits[0]["packet_no"])

    def test_and_query_matches_terms_across_one_packet_request_and_response(self):
        hits = word_search_engine.hits_in_packet_for_terms(
            "request has hoge", "response has piyo", ["hoge", "piyo"], "&", 0, 0)

        self.assertEqual([("Request", "", "hoge", ""), ("Response", "", "piyo", "")], hits)

    def test_or_query_returns_each_matching_term(self):
        hits = word_search_engine.hits_in_text("hoge ufu", "hoge | piyo | ufu", 0, 0)

        self.assertEqual([("", "hoge", ""), ("", "ufu", "")], hits)

    def test_query_operators_can_be_escaped(self):
        terms, operator = word_search_engine.parse_search_query(r"hoge\&piyo | ufu\|bar | slash\\value")

        self.assertEqual(["hoge&piyo", "ufu|bar", "slash\\value"], terms)
        self.assertEqual("|", operator)

    def test_japanese_mac_yen_sign_can_escape_operators(self):
        terms, operator = word_search_engine.parse_search_query(u"hoge¥&piyo | ufu¥|bar | slash¥¥value")

        self.assertEqual(["hoge&piyo", "ufu|bar", u"slash¥value"], terms)
        self.assertEqual("|", operator)

    def test_mixed_query_operators_are_rejected(self):
        with self.assertRaises(ValueError):
            word_search_engine.parse_search_query("hoge & piyo | ufu")

    def test_limited_multi_word_search_does_not_build_every_common_word_hit(self):
        hits = word_search_engine.hits_in_text("a" * 100000, "a | aa", 0, 0, max_hits=200)

        self.assertEqual(200, len(hits))

    def test_max_hits_stops_at_the_requested_limit(self):
        # A very large real response containing a common word used to build
        # every match before Live Word Watch sliced the list down to 200.
        hits = word_search_engine.hits_in_text("a" * 100000, "a", 0, 0, max_hits=200)

        self.assertEqual(200, len(hits))
        self.assertEqual(("", "a", ""), hits[0])

    def test_max_hits_keeps_left_to_right_context(self):
        hits = word_search_engine.hits_in_text("one two two", "two", 2, 2, max_hits=1)

        self.assertEqual([("e ", "two", " t")], hits)

    def test_no_limit_preserves_history_search_behavior(self):
        hits = word_search_engine.hits_in_text("two two", "two", 0, 0)

        self.assertEqual([("", "two", ""), ("", "two", "")], hits)

    def test_replace_handles_unicode_rule_against_non_ascii_bytes(self):
        source = u"before 日本 after".encode("utf-8")
        rule = ReplaceRule(before=u"日本", after=u"置換")

        replaced, count = _apply_rules_to_text(source, [rule])

        self.assertEqual(1, count)
        self.assertEqual(u"before 置換 after".encode("utf-8"), replaced)


if __name__ == "__main__":
    unittest.main()
