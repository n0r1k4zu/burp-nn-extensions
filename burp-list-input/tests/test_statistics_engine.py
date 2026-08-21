# -*- coding: utf-8 -*-

import os
import sys
import unittest

THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(THIS_DIR))

from csvlistinput import statistics_engine


class _Item(object):
    def __init__(self, request, response='', comment=''):
        self.request = request
        self.response = response
        self.comment = comment
        self.highlight = None
    def getRequest(self): return self.request
    def getResponse(self): return self.response
    def getComment(self): return self.comment
    def setComment(self, value): self.comment = value
    def setHighlight(self, value): self.highlight = value


class _Callbacks(object):
    def __init__(self, items): self.items = items
    def getProxyHistory(self): return self.items


class _Helpers(object):
    def bytesToString(self, value): return value


class StatisticsEngineTest(unittest.TestCase):
    def test_classification_definitions(self):
        self.assertEqual(statistics_engine.WEB_SCREEN,
                         statistics_engine.classify_packet('/', '', 'HTTP/1.1 200\r\nContent-Type: text/html\r\n\r\n<html>', 'text/html'))
        self.assertEqual(statistics_engine.WEB_PART,
                         statistics_engine.classify_packet('/app.js', '', '', 'application/javascript'))
        self.assertEqual(statistics_engine.SPA_SCREEN,
                         statistics_engine.classify_packet('/', '', '<html>lightning</html>', 'text/html'))
        self.assertEqual(statistics_engine.SPA_UPDATE,
                         statistics_engine.classify_packet('/sfsites/aura', 'message=x', '', ''))
        self.assertEqual(statistics_engine.API,
                         statistics_engine.classify_packet('/api/users', '', '{}', 'application/json'))

    def test_adjacent_aura_runs_only_mark_later_packets_as_targets(self):
        body = 'message=%7B%22actions%22%3A%5B%7B%22descriptor%22%3A%22aura%3A%2F%2FApexActionController%2FACTION%24execute%22%7D%5D%7D&aura.pageURI=%2Fhome'
        items = [_Item('POST /s/sfsites/aura HTTP/1.1\r\nCookie: x=1\r\n\r\n' + body, ''),
                 _Item('POST /s/sfsites/aura HTTP/1.1\r\nCookie: x=1\r\n\r\n' + body, ''),
                 _Item('GET /api/x HTTP/1.1\r\n\r\n', ''),
                 _Item('POST /s/sfsites/aura HTTP/1.1\r\nCookie: x=1\r\n\r\n' + body, '')]
        records = statistics_engine.analyze_history(_Callbacks(items), _Helpers())
        # As in SF Helper, non-Aura packets do not split an Aura run; a
        # different Aura aggregation key does.
        self.assertEqual([u'representative', u'target', u'single', u'target'],
                         [record['agg_role'] for record in records])
        rows = dict((row['class'], row) for row in statistics_engine.summary_rows(records))
        self.assertEqual(3, rows[statistics_engine.SPA_UPDATE]['including_aggregated'])
        self.assertEqual(1, rows[statistics_engine.SPA_UPDATE]['excluding_aggregated'])

    def test_annotations_numbering_grouping_and_clear(self):
        items = [_Item('GET / HTTP/1.1\r\n\r\n', 'HTTP/1.1 200\r\nContent-Type: text/html\r\n\r\n<html>', '[1992] note'),
                 _Item('GET /a.js HTTP/1.1\r\n\r\n', '', '')]
        callbacks = _Callbacks(items)
        self.assertEqual(2, statistics_engine.number_all(callbacks, 7, 4))
        self.assertTrue(items[0].comment.startswith('[0007]'))
        self.assertEqual(2, statistics_engine.add_group(items, 'login'))
        self.assertIn('[group="login"]', items[0].comment)
        self.assertEqual(2, statistics_engine.remove_group(callbacks, None, None, 'login'))
        self.assertEqual(2, statistics_engine.clear_bracket_tags(callbacks))
        self.assertNotIn('[', items[0].comment)

    def test_number_selected_numbers_only_selected_items_and_replaces_old_number(self):
        items = [_Item('GET / HTTP/1.1\r\n\r\n', '', '[0009] keep'),
                 _Item('GET / HTTP/1.1\r\n\r\n', '', 'untouched')]
        changed = statistics_engine.number_selected([items[0]], 1, 4)
        self.assertEqual(1, changed)
        self.assertEqual('[0001] keep', items[0].comment)
        self.assertEqual('untouched', items[1].comment)

    def test_group_names_accept_history_comment_variants(self):
        self.assertEqual(['alpha', 'beta', 'gamma'], statistics_engine.group_names(
            '[group="alpha"] note [ GROUP = \'beta\' ] [group=gamma]'))
        self.assertEqual([u'日本語'], statistics_engine.group_names(
            b'comment [group="\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e"]'))

    def test_clear_analysis_annotations_preserves_groups_and_numbering(self):
        items = [_Item('GET / HTTP/1.1\r\n\r\n', '',
                       '[0001] [group="user1"] [Web画面] [集約対象] note')]
        changed = statistics_engine.clear_analysis_annotations(_Callbacks(items))
        self.assertEqual(1, changed)
        self.assertEqual('[0001] [group="user1"] note', items[0].comment)

    def test_clear_analysis_annotations_handles_non_ascii_bytes_and_legacy_forms(self):
        items = [_Item('GET / HTTP/1.1\r\n\r\n', '',
                       b'\xe3\x83\xa1\xe3\x83\xa2 [SPA(\xe7\x94\xbb\xe9\x9d\xa2\xe6\x9b\xb4\xe6\x96\xb0)] [\xe9\x9b\x86\xe7\xb4\x84\xe5\xaf\xbe\xe8\xb1\xa1_\xe9\x9b\x86\xe7\xb4\x84\xe5\x85\x88No1992]'),
                 _Item('GET / HTTP/1.1\r\n\r\n', '', '[Web Screen] [Aggregation Target] note')]
        changed = statistics_engine.clear_analysis_annotations(_Callbacks(items))
        self.assertEqual(2, changed)
        self.assertEqual(u'メモ', items[0].comment)
        self.assertEqual(u'note', items[1].comment)

    def test_clear_analysis_annotations_removes_current_spa_and_aggregation_tags(self):
        items = [_Item('GET / HTTP/1.1\r\n\r\n', '', u'[SPA（画面更新）]'),
                 _Item('GET / HTTP/1.1\r\n\r\n', '', u'[SPA（画面更新）] [集約対象]'),
                 _Item('GET / HTTP/1.1\r\n\r\n', '', u'[0107] [集約対象_集約先No0092]')]
        changed = statistics_engine.clear_analysis_annotations(_Callbacks(items))
        self.assertEqual(3, changed)
        self.assertEqual(u'', items[0].comment)
        self.assertEqual(u'', items[1].comment)
        self.assertEqual(u'[0107]', items[2].comment)

    def test_aggregation_annotation_uses_representative_leading_number(self):
        body = 'message=%7B%22actions%22%3A%5B%7B%22descriptor%22%3A%22aura%3A%2F%2FApexActionController%2FACTION%24execute%22%7D%5D%7D'
        items = [_Item('POST /aura HTTP/1.1\r\n\r\n' + body, '', '[1992] representative'),
                 _Item('POST /aura HTTP/1.1\r\n\r\n' + body, '', '')]
        records = statistics_engine.analyze_history(_Callbacks(items), _Helpers())
        changed, colored = statistics_engine.annotate_analysis(records, add_aggregation_tags=True,
                                                                 color_targets=True)
        self.assertEqual(1, changed)
        self.assertEqual(1, colored)
        self.assertIn(u'[集約対象_集約先No1992]', items[1].comment)
        self.assertEqual('gray', items[1].highlight)

    def test_aggregation_annotation_falls_back_to_representative_packet_number(self):
        body = 'message=%7B%22actions%22%3A%5B%7B%22descriptor%22%3A%22aura%3A%2F%2FApexActionController%2FACTION%24execute%22%7D%5D%7D'
        items = [_Item('POST /aura HTTP/1.1\r\n\r\n' + body, '', ''),
                 _Item('POST /aura HTTP/1.1\r\n\r\n' + body, '', '')]
        records = statistics_engine.analyze_history(_Callbacks(items), _Helpers())
        changed, _colored = statistics_engine.annotate_analysis(records, add_aggregation_tags=True)
        self.assertEqual(1, changed)
        self.assertIn(u'[集約対象_集約先PacketNo1]', items[1].comment)

    def test_aura_aggregation_accepts_japanese_json_keys_and_values(self):
        body = ('message=%7B%22actions%22%3A%5B%7B%22descriptor%22%3A%22aura%3A%2F%2F'
                'ApexActionController%2FACTION%24execute%22%2C%22params%22%3A%7B%22objectName%22%3A'
                '%22%E9%A1%A7%E5%AE%A2%22%2C%22%E5%90%8D%E5%89%8D%22%3A%22%E5%B1%B1%E7%94%B0%22%7D%7D%5D%7D')
        items = [_Item('POST /aura HTTP/1.1\r\n\r\n' + body, '', ''),
                 _Item('POST /aura HTTP/1.1\r\n\r\n' + body, '', '')]
        records = statistics_engine.analyze_history(_Callbacks(items), _Helpers())
        self.assertEqual(u'target', records[1]['agg_role'])
