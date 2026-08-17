# -*- coding: utf-8 -*-
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csvlistinput import detection_engine
from csvlistinput.constants import BurpParamType
from csvlistinput.models import InsertionPoint


class FakeParam(object):
    def __init__(self, name, type_, start, end):
        self._name = name
        self._type = type_
        self._start = start
        self._end = end

    def getName(self):
        return self._name

    def getType(self):
        return self._type

    def getValueStart(self):
        return self._start

    def getValueEnd(self):
        return self._end


class FakeRequestInfo(object):
    def __init__(self, headers, body_offset, parameters):
        self._headers = headers
        self._body_offset = body_offset
        self._parameters = parameters

    def getHeaders(self):
        return self._headers

    def getBodyOffset(self):
        return self._body_offset

    def getParameters(self):
        return self._parameters


class FakeHelpers(object):
    def __init__(self, request_info):
        self.request_info = request_info
        self.analyze_calls = 0

    def bytesToString(self, raw):
        return raw

    def analyzeRequest(self, *args):
        self.analyze_calls += 1
        return self.request_info


def request_info(raw, parameters=None):
    head, _body = raw.split('\r\n\r\n', 1)
    return FakeRequestInfo(head.split('\r\n'), len(head) + 4, parameters or [])


class DetectionEngineTest(unittest.TestCase):
    def setUp(self):
        # Production runs on Jython 2 where the byte-preserving buffer is a
        # ``str``.  The Python 3 regression runner's compatibility helper
        # returns ``bytes``; keep this suite focused on the Jython pipeline.
        self._original_bytes_to_bytestring = detection_engine.bytes_to_bytestring
        detection_engine.bytes_to_bytestring = lambda helpers, raw: raw

    def tearDown(self):
        detection_engine.bytes_to_bytestring = self._original_bytes_to_bytestring

    def test_nested_json_body_keeps_exact_byte_offsets(self):
        raw = ('POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n'
               '{"outer":{"id":"42"},"items":[{"amount":7}]}')
        helpers = FakeHelpers(request_info(raw))
        engine = detection_engine.DetectionEngine(cache_size=0)
        points = engine.detect(helpers, raw)
        by_path = dict((point.path, point) for point in points)
        self.assertIn('$.outer.id', by_path)
        self.assertIn('$.items[0].amount', by_path)
        id_point = by_path['$.outer.id']
        self.assertEqual('42', raw[id_point.start:id_point.end])
        self.assertEqual('42', id_point.original_value)

    def test_json_string_containing_array_of_objects_expands_to_nested_leaves(self):
        """A common API/Aura shape: JSON text is itself held in a JSON string.

        The outer value remains a valid replacement point, while each array
        object's leaf is also independently mappable.
        """
        raw = ('POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n'
               '{"payload":"[{\\"hoge\\":\\"1\\",\\"piyo\\":\\"2\\"}]"}')
        helpers = FakeHelpers(request_info(raw))
        points = detection_engine.DetectionEngine(cache_size=0).detect(helpers, raw)
        by_path = dict((point.path, point) for point in points)
        self.assertIn('$.payload', by_path)
        self.assertIn('$.payload{json}[0].hoge', by_path)
        self.assertIn('$.payload{json}[0].piyo', by_path)
        self.assertEqual('JSON_LEAF_NESTED', by_path['$.payload{json}[0].hoge'].type)
        self.assertEqual('1', by_path['$.payload{json}[0].hoge'].original_value)
        self.assertEqual('2', by_path['$.payload{json}[0].piyo'].original_value)

    def test_ndjson_body_detects_each_document_with_independent_path(self):
        raw = ('POST /batch HTTP/1.1\r\nContent-Type: application/x-ndjson\r\n\r\n'
               '{"id":"A1","record":{"owner":"u1"}}\n'
               '{"id":"A2","record":{"owner":"u2"}}\n')
        helpers = FakeHelpers(request_info(raw))
        points = detection_engine.DetectionEngine(cache_size=0).detect(helpers, raw)
        paths = [point.path for point in points]
        self.assertIn('ndjson[0]$.record.owner', paths)
        self.assertIn('ndjson[1]$.record.owner', paths)

    def test_form_value_expands_url_encoded_nested_json(self):
        encoded = '%7B%22record%22%3A%7B%22id%22%3A%22A1%22%7D%7D'
        raw = ('POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n'
               'message=' + encoded)
        start = raw.index(encoded)
        params = [FakeParam('message', BurpParamType.BODY, start, start + len(encoded))]
        helpers = FakeHelpers(request_info(raw, params))
        points = detection_engine.DetectionEngine(cache_size=0).detect(helpers, raw)
        paths = [point.path for point in points]
        self.assertIn('body[message]', paths)
        self.assertIn('body[message]{json}.record.id', paths)
        nested = [point for point in points if point.path.endswith('.record.id')][0]
        self.assertEqual('A1', nested.original_value)
        self.assertTrue(start <= nested.start < nested.end <= start + len(encoded))
        self.assertEqual('A1', raw[nested.start:nested.end])

    def test_query_value_expands_double_percent_encoded_nested_json(self):
        encoded = '%257B%2522record%2522%253A%257B%2522id%2522%253A%2522A1%2522%257D%257D'
        raw = 'GET /?payload=' + encoded + ' HTTP/1.1\r\nHost: target\r\n\r\n'
        start = raw.index(encoded)
        params = [FakeParam('payload', BurpParamType.URL, start, start + len(encoded))]
        helpers = FakeHelpers(request_info(raw, params))
        points = detection_engine.DetectionEngine(cache_size=0).detect(helpers, raw)
        nested = [point for point in points if point.path.endswith('.record.id')][0]
        self.assertEqual('A1', nested.original_value)
        self.assertTrue(start <= nested.start < nested.end <= start + len(encoded))

    def test_multipart_json_uses_same_pipeline(self):
        body = ('--abc\r\nContent-Disposition: form-data; name="payload"\r\n'
                'Content-Type: application/json\r\n\r\n'
                '{"record":{"id":"7"}}\r\n--abc--\r\n')
        raw = ('POST /upload HTTP/1.1\r\n'
               'Content-Type: multipart/form-data; boundary=abc\r\n\r\n' + body)
        helpers = FakeHelpers(request_info(raw))
        points = detection_engine.DetectionEngine(cache_size=0).detect(helpers, raw)
        point = [item for item in points if item.path == 'multipart[payload]$.record.id'][0]
        self.assertEqual('7', raw[point.start:point.end])
        self.assertEqual(0, point.multipart_part_index)

    def test_cache_avoids_reanalysis_and_returns_independent_points(self):
        raw = 'GET /?id=1 HTTP/1.1\r\nHost: target\r\n\r\n'
        start = raw.index('1')
        info = request_info(raw, [FakeParam('id', BurpParamType.URL, start, start + 1)])
        helpers = FakeHelpers(info)
        engine = detection_engine.DetectionEngine(cache_size=4)
        first = engine.detect(helpers, raw)
        first[0].path = 'changed-by-a-consumer'
        second = engine.detect(helpers, raw)
        self.assertEqual(1, helpers.analyze_calls)
        self.assertEqual('url[id]', second[0].path)
        self.assertEqual({'hits': 1, 'misses': 1, 'entries': 1}, engine.cache_stats())

    def test_body_limit_preserves_independent_transport_points(self):
        raw = ('POST /?id=1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n'
               '{"large":"0123456789"}')
        start = raw.index('1')
        info = request_info(raw, [FakeParam('id', BurpParamType.URL, start, start + 1)])
        helpers = FakeHelpers(info)
        errors = []
        engine = detection_engine.DetectionEngine(cache_size=0, max_body_bytes=4)
        points = engine.detect(helpers, raw, on_error=errors.append)
        paths = [point.path for point in points]
        self.assertIn('url[id]', paths)
        self.assertIn('header[Content-Type]', paths)
        self.assertNotIn('$.large', paths)
        self.assertTrue(any('exceeds the configured' in message for message in errors))

    def test_json_depth_limit_is_string_aware_and_reports_skip(self):
        deep_raw = ('POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n'
                    '{"a":{"b":{"c":1}}}')
        helpers = FakeHelpers(request_info(deep_raw))
        errors = []
        engine = detection_engine.DetectionEngine(
            cache_size=0, max_json_structure_depth=2)
        points = engine.detect(helpers, deep_raw, on_error=errors.append)
        self.assertNotIn('$.a.b.c', [point.path for point in points])
        self.assertTrue(any('depth limit' in message for message in errors))

        quoted_braces = ('POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n'
                         '{"text":"{{{{"}')
        helpers = FakeHelpers(request_info(quoted_braces))
        points = engine.detect(helpers, quoted_braces)
        self.assertIn('$.text', [point.path for point in points])

    def test_exact_duplicate_suppression_keeps_distinct_offsets(self):
        a = InsertionPoint('url[id]', 'URL', 10, 11, '1')
        duplicate = InsertionPoint('url[id]', 'URL', 10, 11, '1')
        other_offset = InsertionPoint('url[id]', 'URL', 20, 21, '2')
        result = detection_engine._deduplicate_points([a, duplicate, other_offset])
        self.assertEqual([a, other_offset], result)

    def test_body_exception_does_not_discard_url_or_header_points(self):
        raw = 'POST /?id=1 HTTP/1.1\r\nX-Test: yes\r\n\r\nbody'
        start = raw.index('1')
        info = request_info(raw, [FakeParam('id', BurpParamType.URL, start, start + 1)])
        helpers = FakeHelpers(info)
        errors = []
        original = detection_engine._process_body

        def fail_body(*args, **kwargs):
            raise RuntimeError('synthetic body failure')

        detection_engine._process_body = fail_body
        try:
            points = detection_engine.DetectionEngine(cache_size=0).detect(
                helpers, raw, on_error=errors.append)
        finally:
            detection_engine._process_body = original
        paths = [point.path for point in points]
        self.assertIn('url[id]', paths)
        self.assertIn('header[X-Test]', paths)
        self.assertTrue(any('synthetic body failure' in message for message in errors))


if __name__ == '__main__':
    unittest.main()
