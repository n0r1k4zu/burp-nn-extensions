# -*- coding: utf-8 -*-
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csvlistinput import authorization_planning_engine
from csvlistinput.models import InsertionPoint

try:
    _TEXT_TYPE = unicode
except NameError:
    _TEXT_TYPE = str


def _raw(text):
    return text.encode('utf-8') if isinstance(text, str) else text


class _Service(object):
    def __init__(self, host=u'example.my.site.com'):
        self.host = host

    def getHost(self):
        return self.host


class _Item(object):
    def __init__(self, request, response=None, comment=u'', highlight=None,
                 host=u'example.my.site.com', url=None):
        self.request = _raw(request)
        self.response = _raw(response) if response is not None else None
        self.comment = comment
        self.highlight = highlight
        self.service = _Service(host)
        self.url = url

    def getRequest(self): return self.request
    def getResponse(self): return self.response
    def getComment(self): return self.comment
    def setComment(self, value): self.comment = value
    def getHighlight(self): return self.highlight
    def getHttpService(self): return self.service
    def getUrl(self): return self.url


class _Callbacks(object):
    def __init__(self, items, scope_fn=None):
        self.items = items
        self.scope_fn = scope_fn
    def getProxyHistory(self): return self.items
    def isInScope(self, url):
        if self.scope_fn is None:
            return True
        return self.scope_fn(url)


class _Helpers(object):
    def bytesToString(self, value):
        # Burp bytesToString相当: byteをLatin-1の同一code pointへ写す。
        return value.decode('latin-1') if isinstance(value, bytes) else value


class _Point(object):
    def __init__(self, path, value, type_=u'JSON_LEAF', nesting=0, recovered=False):
        self.path = path
        self.original_value = value
        self.type = type_
        self.nesting_depth = nesting
        self.recovered = recovered


def _detector(points_by_request=None, errors=None):
    points_by_request = points_by_request or {}
    errors = errors or {}

    def detect(helpers, request, service, on_error=None):
        text = helpers.bytesToString(request)
        for marker, message in errors.items():
            if marker in text and on_error:
                on_error(message)
        for marker, points in points_by_request.items():
            if marker in text:
                return points
        return []
    return detect


def _request(method, path, body=u'', headers=None):
    headers = list(headers or [])
    return (method + u' ' + path + u' HTTP/1.1\r\nHost: example.my.site.com\r\n' +
            u'\r\n'.join(headers) + (u'\r\n' if headers else u'') + u'\r\n' + body)


def _response(status=200, body=u'', content_type=u'application/json'):
    return (u'HTTP/1.1 %d OK\r\nContent-Type: %s\r\n\r\n%s' %
            (status, content_type, body))


def _aura_body(actions, context=None, page_uri=None):
    # json.dumpsのASCII出力なので簡易percent encodingで十分。
    message = json.dumps({'actions': actions}, ensure_ascii=True, separators=(',', ':'))
    try:
        from urllib import quote_plus
    except ImportError:
        from urllib.parse import quote_plus
    context_json = json.dumps(context or {'fwuid': 'FW-SECRET'}, ensure_ascii=True,
                              separators=(',', ':'))
    body = (u'message=' + quote_plus(message) + u'&aura.context=' +
            quote_plus(context_json) + u'&aura.token=undefined')
    if page_uri is not None:
        body += u'&aura.pageURI=' + quote_plus(page_uri)
    return body


class AuthorizationPlanningEngineTest(unittest.TestCase):
    def _analyze(self, items, **kwargs):
        kwargs.setdefault('detector', _detector())
        return authorization_planning_engine.analyze_history(
            _Callbacks(items), _Helpers(), **kwargs)

    def test_all_range_progress_missing_response_and_cancel(self):
        items = [
            _Item(_request(u'GET', u'/api/1'), _response(body=u'{"id":"001000000000001"}')),
            _Item(_request(u'GET', u'/api/2'), None),
            _Item(_request(u'GET', u'/api/3'), _response(body=u'{}')),
        ]
        progress = []
        ranged = self._analyze(items, start_packet_no=2, end_packet_no=3,
                               progress_fn=lambda processed, total: progress.append((processed, total)))
        self.assertEqual(2, ranged['summary']['packets_analyzed'])
        self.assertEqual([2, 3], [packet['packet_no'] for packet in ranged['packets']])
        self.assertEqual([(1, 2), (2, 2)], progress)
        self.assertTrue(any(gap['reason'] == u'missing response' for gap in ranged['gaps']))

        calls = []
        cancelled = self._analyze(
            items, cancel_check=lambda: calls.append(1) or len(calls) > 1)
        self.assertTrue(cancelled['summary']['cancelled'])
        self.assertEqual(1, cancelled['summary']['packets_analyzed'])

    def test_operation_representative_prefers_packet_with_response(self):
        """集約行のViewerがRequestだけになる代表Packetを選ばない。"""
        items = [
            _Item(_request(u'GET', u'/api/orders'), None),
            _Item(_request(u'GET', u'/api/orders'), _response(body=u'{"id":"1"}')),
        ]
        result = self._analyze(items)
        operation = result['operations'][0]
        self.assertEqual(2, operation['representative_packet_no'])
        self.assertIsNotNone(operation['representative_item'].getResponse())

    def test_aura_batch_creates_distinct_actions_and_classifies_origins(self):
        actions = [
            {'id': '1;a', 'descriptor': 'aura://RecordUiController/ACTION$getRecord',
             'callingDescriptor': 'markup://c:Caller', 'params': {'recordId': '001000000000001'}},
            {'id': '2;a', 'descriptor': 'apex://MyController/ACTION$getAccount',
             'params': {'accountId': '001000000000002'}},
            {'id': '3;a', 'descriptor': 'apex://pkg.MyController/ACTION$saveOrder',
             'params': {'orderId': '801000000000001'}},
            {'id': '4;a', 'descriptor': 'mystery://Controller/ACTION$read', 'params': {}},
        ]
        item = _Item(
            _request(u'POST', u'/s/sfsites/aura', _aura_body(actions),
                     [u'Content-Type: application/x-www-form-urlencoded']),
            _response(body=json.dumps({'actions': []})))
        result = self._analyze([item])
        self.assertEqual(4, result['summary']['aura_actions'])
        self.assertEqual(4, result['summary']['unique_operations'])
        origins = dict((row['operation_name'], row['origin']) for row in result['operations'])
        self.assertEqual(u'Salesforce Standard', origins[u'getRecord'])
        self.assertEqual(u'Org Custom Apex', origins[u'getAccount'])
        self.assertEqual(u'Managed or Namespaced Apex', origins[u'saveOrder'])
        self.assertEqual(u'Unknown', origins[u'read'])
        standard = next(row for row in result['operations'] if row['operation_name'] == u'getRecord')
        self.assertEqual(u'markup://c:Caller', standard['calling_descriptor'])
        self.assertTrue(standard['origin_reason'])
        self.assertEqual(set([0, 1, 2, 3]), set(
            row['representative_action_index'] for row in result['operations']))
        self.assertEqual(set([u'1;a', u'2;a', u'3;a', u'4;a']), set(
            row['representative_action_id'] for row in result['operations']))
        self.assertIn(standard['origin_confidence'], (u'low', u'medium', u'high'))
        categories = dict((row['operation_name'], row['origin_category'])
                          for row in result['operations'])
        self.assertEqual(u'Salesforce標準', categories[u'getRecord'])
        self.assertEqual(u'Apexカスタム', categories[u'getAccount'])
        self.assertEqual(u'Apexカスタム', categories[u'saveOrder'])

    def test_origin_category_distinguishes_apex_rest_salesforce_rest_and_unknown(self):
        result = self._analyze([
            _Item(_request(u'GET', u'/services/apexrest/orders'), _response(body=u'{}')),
            _Item(_request(u'GET', u'/services/data/v60.0/sobjects/Account'), _response(body=u'{}')),
            _Item(_request(u'GET', u'/custom/route'), _response(body=u'<html></html>', content_type=u'text/html')),
        ])
        categories = dict((row['path'], row['origin_category']) for row in result['operations'])
        self.assertEqual(u'ApexREST', categories[u'/services/apexrest/orders'])
        self.assertEqual(u'SalesforceREST', categories[u'/services/data/v60.0/sobjects/Account'])
        self.assertEqual(u'Unknown', categories[u'/custom/route'])

    def test_aura_cmp_def_query_is_retained_in_operation_catalog_path(self):
        """GET auraCmpDefはqueryの_defを捨てず、定義ごとにCatalogへ出す。"""
        item = _Item(
            _request(u'GET',
                     u'/cst/s/sfsites/auraCmpDef?aura.app=markup%3A%2F%2Fsiteforce%3AcommunityApp'
                     u'&_def=markup%3A%2F%2Fc%3AloanWizard'),
            _response(body=u'$A.componentService.addComponent({})', content_type=u'text/javascript'))
        result = self._analyze([item])
        operation = result['operations'][0]
        expected_path = u'/cst/s/sfsites/auraCmpDef?_def=markup://c:loanWizard'
        self.assertEqual(expected_path, operation['path'])
        self.assertEqual(u'Aura component definition: markup://c:loanWizard',
                         operation['operation_name'])
        self.assertIn(u'markup://siteforce:communityApp', operation['app_ids'])
        self.assertEqual(u'/cst/s/sfsites/auraCmpDef', result['packets'][0]['path'])

    def test_aura_cmp_def_literal_markup_url_in_query_is_not_absolute_request_target(self):
        """_def内の`://`をabsolute-form URLと誤認しない。"""
        item = _Item(
            _request(u'GET',
                     u'/cst/s/sfsites/auraCmpDef?aura.app=markup://siteforce:communityApp'
                     u'&_def=markup://runtime_feature_usage_sdk:feature'),
            _response(body=u'{}'))
        result = self._analyze([item])
        operation = result['operations'][0]
        self.assertEqual(
            u'/cst/s/sfsites/auraCmpDef?_def=markup://runtime_feature_usage_sdk:feature',
            operation['path'])
        self.assertEqual(u'/cst/s/sfsites/auraCmpDef', result['packets'][0]['path'])

    def test_exact_duplicate_aura_actions_are_linked_to_a_representative_packet(self):
        """Aura action IDだけが異なる同じ画面更新は重複候補として見える。"""
        first = {'id': '1;a', 'descriptor': 'apex://OrderController/ACTION$getOrder',
                 'params': {'recordId': '801000000000001'}}
        second = {'id': '99;a', 'descriptor': 'apex://OrderController/ACTION$getOrder',
                  'params': {'recordId': '801000000000001'}}
        items = [
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([first]),
                           [u'Content-Type: application/x-www-form-urlencoded']),
                  _response(body=u'{"actions":[]}')),
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([second]),
                           [u'Content-Type: application/x-www-form-urlencoded']),
                  _response(body=u'{"actions":[]}')),
        ]
        result = self._analyze(items)
        operation = result['operations'][0]
        self.assertEqual([2], operation['exact_duplicate_packet_nos'])
        self.assertEqual(1, operation['test_variants'])
        self.assertEqual(1, operation['deduplication_groups'][0]['representative_packet_no'])
        self.assertEqual(u'Exact duplicate', result['packets'][1]['deduplication'][0]['status'])

    def test_different_aura_resource_values_remain_separate_test_variants(self):
        """別recordIdは同一Operationでも重複として省略しない。"""
        first = {'id': '1;a', 'descriptor': 'apex://OrderController/ACTION$getOrder',
                 'params': {'recordId': '801000000000001'}}
        second = {'id': '2;a', 'descriptor': 'apex://OrderController/ACTION$getOrder',
                  'params': {'recordId': '801000000000002'}}
        items = [
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([first]),
                           [u'Content-Type: application/x-www-form-urlencoded']), _response(body=u'{}')),
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([second]),
                           [u'Content-Type: application/x-www-form-urlencoded']), _response(body=u'{}')),
        ]
        operation = self._analyze(items)['operations'][0]
        self.assertEqual([], operation['exact_duplicate_packet_nos'])
        self.assertEqual(2, operation['test_variants'])

    def test_packet_comment_annotations_and_export_rows_include_deduplication(self):
        action = {'id': '1;a', 'descriptor': 'apex://OrderController/ACTION$getOrder',
                  'params': {'recordId': '801000000000001'}}
        items = [
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([action]),
                           [u'Content-Type: application/x-www-form-urlencoded']), _response(body=u'{}'),
                  comment=u'[group="user1"] keep this'),
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([dict(action, id='2;a')]),
                           [u'Content-Type: application/x-www-form-urlencoded']), _response(body=u'{}')),
        ]
        result = self._analyze(items)
        updated, skipped = authorization_planning_engine.apply_packet_comment_annotations(result)
        self.assertEqual(2, updated)
        self.assertEqual(0, skipped)
        self.assertTrue(items[0].getComment().startswith(u'[AP:Protocol=Aura]'))
        self.assertIn(u'[group="user1"] keep this', items[0].getComment())
        self.assertIn(u'[AP:Protocol=Aura]', items[0].getComment())
        self.assertIn(u'[AP:Duplicate=Yes;RepresentativePacketNo=1]', items[1].getComment())
        rows = authorization_planning_engine.export_rows(result)
        self.assertEqual(set([u'Operation', u'Packet']), set(row['Record Type'] for row in rows))
        self.assertTrue(all(row['Origin'] in (u'Salesforce標準', u'Apexカスタム', u'ApexREST',
                                              u'SalesforceREST', u'Unknown') for row in rows))
        self.assertTrue(any(row['Record Type'] == u'Packet' and
                            row['Deduplication'] == u'Yes;RepresentativePacketNo=1'
                            for row in rows))

    def test_generic_apex_controller_uses_class_namespace_and_method(self):
        actions = [
            {'id': '1;a', 'descriptor': 'aura://ApexActionController/ACTION$execute',
             'params': {'classname': 'OrderController', 'methodName': 'getOrders'}},
            {'id': '2;a', 'descriptor': 'aura://ApexActionController/ACTION$execute',
             'params': {'namespace': 'pkg', 'apexClass': 'OrderController', 'method': 'saveOrder'}},
        ]
        item = _Item(_request(u'POST', u'/aura', _aura_body(actions)), _response(body=u'{"actions":[]}'))
        rows = self._analyze([item])['operations']
        by_name = dict((row['operation_name'], row) for row in rows)
        self.assertEqual(u'Org Custom Apex', by_name[u'OrderController.getOrders']['origin'])
        self.assertEqual(u'Managed or Namespaced Apex', by_name[u'pkg.OrderController.saveOrder']['origin'])

    def test_same_aura_shape_aggregates_across_packets_without_action_index(self):
        actions1 = [{'id': '1;a', 'descriptor': 'apex://MyController/ACTION$get',
                     'params': {'accountId': '001000000000001'}}]
        actions2 = [{'id': '99;a', 'descriptor': 'apex://MyController/ACTION$get',
                     'params': {'accountId': '001000000000002'}}]
        items = [
            _Item(_request(u'POST', u'/aura', _aura_body(actions1)), _response(body=u'{"actions":[]}')),
            _Item(_request(u'POST', u'/aura', _aura_body(actions2)), _response(body=u'{"actions":[]}')),
        ]
        result = self._analyze(items)
        self.assertEqual(1, result['summary']['unique_operations'])
        self.assertEqual(2, result['operations'][0]['occurrences'])
        self.assertEqual([1, 2], result['operations'][0]['packet_nos'])

    def test_rest_graphql_nested_parameters_and_framework_controls(self):
        rest = _Item(
            _request(u'GET', u'/services/data/v60.0/sobjects/Account/001000000000001?ownerId=005000000000001',
                     headers=[u'Cookie: sid=COOKIE-SECRET', u'X-CSRF-Token: CSRF-SECRET']),
            _response(body=u'{"OwnerId":"005000000000001","Email":"user@example.test"}'))
        graphql_body = json.dumps({
            'operationName': 'AccountLookup',
            'query': 'query AccountLookup($filter: AccountFilter){account(filter:$filter){id}}',
            'variables': {'filter': {'ownerId': '005000000000002'}},
        })
        graphql = _Item(
            _request(u'POST', u'/graphql', graphql_body,
                     [u'Content-Type: application/json', u'Authorization: Bearer BEARER-SECRET']),
            _response(body=u'{"data":{"account":{"id":"001000000000009"}}}'))
        points = {
            'ownerId=005': [_Point(u'url[ownerId]', u'005000000000001', u'URL_PARAM')],
            'AccountLookup': [
                _Point(u'$.variables.filter.ownerId', u'005000000000002', nesting=3),
                _Point(u'header[Authorization]', u'Bearer BEARER-SECRET', u'HEADER'),
                _Point(u'header[X-CSRF-Token]', u'CSRF-SECRET', u'HEADER'),
            ],
        }
        result = authorization_planning_engine.analyze_history(
            _Callbacks([rest, graphql]), _Helpers(), detector=_detector(points))
        protocols = set(row['protocol_kind'] for row in result['operations'])
        self.assertIn(u'REST', protocols)
        self.assertIn(u'GraphQL', protocols)
        graph_row = next(row for row in result['operations'] if row['protocol_kind'] == u'GraphQL')
        self.assertEqual(u'AccountLookup', graph_row['operation_name'])
        owner = next(row for row in graph_row['parameters'] if row['path'].endswith(u'ownerId'))
        self.assertEqual(3, owner['nesting'])
        self.assertIn(u'identifier', owner['candidate_classification'].lower())
        self.assertGreater(owner['score'], 0)
        self.assertTrue(owner['reasons'])
        controls = [row for row in graph_row['parameters']
                    if u'authorization' in row['path'].lower() or u'csrf' in row['path'].lower()]
        self.assertTrue(controls)
        self.assertTrue(all(row['candidate_classification'] == u'Framework/session control'
                            for row in controls))
        candidate_paths = [row['path'] for row in graph_row['resource_candidates']]
        self.assertTrue(any(path.endswith(u'ownerId') for path in candidate_paths))
        self.assertFalse(any(u'csrf' in path.lower() or u'authorization' in path.lower()
                             for path in candidate_paths))
        serialized = json.dumps(result, default=lambda _value: '<item>', ensure_ascii=False)
        self.assertNotIn('COOKIE-SECRET', serialized)
        self.assertNotIn('BEARER-SECRET', serialized)
        self.assertNotIn('CSRF-SECRET', serialized)
        self.assertTrue(all(session['fingerprint'].startswith(u'sha256:') for session in result['sessions']))

    def test_rotating_csrf_does_not_split_cookie_session(self):
        items = [
            _Item(_request(u'GET', u'/api/one', headers=[
                u'Cookie: sid=SAME-SESSION', u'X-CSRF-Token: TOKEN-ONE']), _response(body=u'{}')),
            _Item(_request(u'GET', u'/api/two', headers=[
                u'Cookie: sid=SAME-SESSION', u'X-CSRF-Token: TOKEN-TWO']), _response(body=u'{}')),
        ]
        result = self._analyze(items)
        self.assertEqual(1, result['summary']['session_fingerprints'])
        self.assertEqual(2, result['sessions'][0]['occurrences'])
        serialized = json.dumps(result, default=lambda _value: '<item>', ensure_ascii=False)
        self.assertNotIn('SAME-SESSION', serialized)
        self.assertNotIn('TOKEN-ONE', serialized)
        self.assertNotIn('TOKEN-TWO', serialized)

    def test_aura_response_matches_action_id_and_builds_resource_corpus(self):
        actions = [
            {'id': 'read;a', 'descriptor': 'apex://AccountController/ACTION$getAccount',
             'params': {'accountId': '001000000000001'}},
            {'id': 'write;a', 'descriptor': 'apex://OrderController/ACTION$saveOrder',
             'params': {'orderId': '801000000000001'}},
        ]
        response_body = json.dumps({'actions': [
            {'id': 'write;a', 'state': 'SUCCESS', 'returnValue': {
                'OrderId': '801000000000001', 'Status': 'Approved'}},
            {'id': 'read;a', 'state': 'SUCCESS', 'returnValue': {
                'AccountId': '001000000000001', 'OwnerId': '005000000000001'}},
        ]})
        item = _Item(_request(u'POST', u'/aura', _aura_body(actions)), _response(body=response_body))
        result = self._analyze([item])
        account = next(row for row in result['operations'] if row['operation_name'] == u'getAccount')
        order = next(row for row in result['operations'] if row['operation_name'] == u'saveOrder')
        self.assertIn(u'returnValue.OwnerId', account['response_schema_paths'])
        self.assertNotIn(u'returnValue.OwnerId', order['response_schema_paths'])
        self.assertTrue(account['response_resource_candidates'])
        owner_field = next(field for field in account['response_fields']
                           if field['path'] == u'returnValue.OwnerId')
        self.assertEqual(u'string', owner_field['type'])
        self.assertTrue(any(resource['source'] in (u'Response', u'Both') for resource in result['resources']))
        self.assertGreater(result['summary']['response_fields'], 0)
        self.assertGreater(result['summary']['resources'], 0)

    def test_non_aura_response_japanese_group_and_unicode_bytes_are_visible(self):
        request = _request(u'GET', u'/api/顧客/001000000000001').replace(
            u'Host: example.my.site.com', u'Host: 日本語.example')
        response = _response(body=u'{"顧客":{"所有者ID":"005000000000001","氏名":"山田太郎"}}')
        item = _Item(request, response,
                     comment=u'メモ [group="一般ユーザー"]'.encode('utf-8'),
                     highlight=u'青'.encode('utf-8'), host=u'日本語.example')
        points = [_Point(u'$.検索.所有者ID'.encode('utf-8'),
                         u'005000000000001'.encode('utf-8'), nesting=2)]
        result = authorization_planning_engine.analyze_history(
            _Callbacks([item]), _Helpers(), detector=lambda helpers, request, service: points)
        packet = result['packets'][0]
        self.assertEqual(u'/api/顧客/001000000000001', packet['path'])
        self.assertEqual([u'一般ユーザー'], packet['groups'])
        self.assertIn(u'メモ', packet['comment'])
        operation = result['operations'][0]
        self.assertEqual([u'一般ユーザー'], operation['observed_groups'])
        self.assertTrue(any(u'所有者ID' in field['path'] for field in operation['response_fields']))
        self.assertTrue(any(resource['groups'] == [u'一般ユーザー'] for resource in result['resources']))
        self.assertEqual([u'一般ユーザー'], result['sessions'][0]['observed_groups'])
        # 返却中の表示文字列にUTF-8 byte-stringが残らないことを代表値で確認。
        self.assertIsInstance(operation['parameters'][0]['path'], _TEXT_TYPE)
        self.assertIn(u'日本語', packet['host'])

    def test_malformed_aura_detector_error_and_binary_gap_are_not_silent(self):
        malformed = _Item(
            _request(u'POST', u'/aura', u'message=%7Bbroken',
                     [u'Content-Type: application/x-www-form-urlencoded']),
            _response(body=u'{broken'))
        binary = _Item(_request(u'GET', u'/image.png'),
                       _response(body=u'PNGDATA', content_type=u'image/png'))
        result = authorization_planning_engine.analyze_history(
            _Callbacks([malformed, binary]), _Helpers(),
            detector=_detector(errors={'%7Bbroken': u'検出器エラー'.encode('utf-8')}))
        reasons = [gap['reason'] for gap in result['gaps']]
        self.assertTrue(any(u'malformed Aura message' in reason for reason in reasons))
        self.assertTrue(any(u'検出器エラー' in reason for reason in reasons))
        self.assertTrue(any(u'binary response' in reason for reason in reasons))
        self.assertEqual(len(result['gaps']), result['summary']['parse_gaps'])

    def test_plan_rows_explain_priority_without_claiming_vulnerability(self):
        item = _Item(
            _request(u'PATCH', u'/api/orders/801000000000001', u'{"ownerId":"005000000000001"}',
                     [u'Content-Type: application/json']),
            _response(body=u'{"orderId":"801000000000001","status":"Approved"}'))
        points = [_Point(u'$.ownerId', u'005000000000001')]
        result = authorization_planning_engine.analyze_history(
            _Callbacks([item]), _Helpers(), detector=lambda helpers, request, service: points)
        self.assertTrue(result['plan_rows'])
        row = result['plan_rows'][0]
        self.assertIn(row['priority'], (u'P0', u'P1', u'P2', u'P3'))
        self.assertIsInstance(row['score'], int)
        self.assertTrue(row['reasons'])
        self.assertIn(u'same-role cross-user substitution/replay', row['recommended_tests'])
        self.assertNotIn(u'vulnerable', u' '.join(row['reasons']).lower())

    def test_origin_is_not_used_as_a_risk_score(self):
        actions = [
            {'id': '1;a', 'descriptor': 'aura://RecordUiController/ACTION$getAccount',
             'params': {'accountId': '001000000000001'}},
            {'id': '2;a', 'descriptor': 'apex://AccountController/ACTION$getAccount',
             'params': {'accountId': '001000000000001'}},
        ]
        item = _Item(_request(u'POST', u'/aura', _aura_body(actions)),
                     _response(body=u'{"actions":[]}'))
        result = self._analyze([item])
        rows = [row for row in result['plan_rows'] if row['candidate_path'] == u'params.accountId']
        self.assertEqual(2, len(rows))
        self.assertEqual(rows[0]['score'], rows[1]['score'])
        self.assertFalse(any(u'custom/namespaced' in u' '.join(row['reasons']).lower()
                             for row in rows))

    def test_aura_execute_graphql_decodes_nested_percent_and_builds_catalog(self):
        try:
            from urllib import quote_plus
        except ImportError:
            from urllib.parse import quote_plus
        query = (u'query AccountPlan($where:Account_Filter){uiapi{query{'
                 u'Account(where:$where,first:25){edges{node{Id Name OwnerId}}'
                 u'pageInfo{endCursor hasNextPage}}}}}')
        twice_encoded = quote_plus(quote_plus(query))
        actions = [{
            'id': '1;a',
            'descriptor': 'aura://RecordUiController/ACTION$executeGraphQL',
            'params': {'queryInput': {'query': twice_encoded,
                                      'variables': {'where': {'Name': {'like': 'テスト%'}}}}},
        }]
        item = _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body(actions),
                             [u'Content-Type: application/x-www-form-urlencoded']),
                     _response(body=u'{"actions":[]}'))
        result = self._analyze([item])
        operation = result['operations'][0]
        graphql = operation['graphql']
        self.assertEqual(u'query', graphql['kind'])
        self.assertEqual([u'Account'], graphql['objects'])
        self.assertEqual([u'Id', u'Name', u'OwnerId'], graphql['fields'])
        self.assertTrue(graphql['has_filter'])
        self.assertTrue(graphql['has_pagination'])
        self.assertEqual([u'List/Search'], graphql['crud_intents'])
        self.assertEqual(u'Record List/Search', operation['data_interaction'])
        self.assertIn(u'GraphQL Pagination', operation['salesforce_features'])
        objects = result['object_field_catalog']['objects']
        account = next(row for row in objects if row['object_name'] == u'Account')
        self.assertEqual([u'Id', u'Name', u'OwnerId'], account['fields'])
        self.assertNotIn(u'endCursor', account['fields'])
        self.assertNotIn(u'hasNextPage', account['fields'])

    def test_graphql_mutation_extracts_update_without_copying_inline_literal(self):
        query = (u'mutation AccountEdit($input:AccountUpdateInput!){uiapi{'
                 u'AccountUpdate(input:$input,note:"秘密のメモ",retry:123){'
                 u'Record{Id Name Amount__c} errors{message}}}}')
        actions = [{
            'id': '1;a',
            'descriptor': 'aura://RecordUiController/ACTION$executeGraphQL',
            'params': {'queryInput': {'query': query, 'variables': {'input': {'Id': '001000000000001'}}}},
        }]
        item = _Item(_request(u'POST', u'/aura', _aura_body(actions)),
                     _response(body=u'{"actions":[]}'))
        result = self._analyze([item])
        operation = result['operations'][0]
        graphql = operation['graphql']
        self.assertEqual(u'mutation', graphql['kind'])
        self.assertEqual([u'Update'], graphql['crud_intents'])
        self.assertEqual(u'Record Update', operation['data_interaction'])
        self.assertNotIn(u'秘密のメモ', graphql['query_preview'])
        self.assertNotIn(u'123', graphql['query_preview'])
        self.assertNotIn(u'AccountUpdate', graphql['fields'])
        self.assertNotIn(u'message', graphql['fields'])
        account = next(row for row in result['object_field_catalog']['objects']
                       if row['object_name'] == u'Account')
        self.assertIn(u'Amount__c', account['fields'])
        serialized = json.dumps(result, default=lambda _value: '<item>', ensure_ascii=False)
        self.assertNotIn(u'秘密のメモ', serialized)

    def test_getitems_entity_name_populates_object_catalog(self):
        actions = [{
            'id': '1;a', 'descriptor': 'aura://ListUiController/ACTION$getItems',
            'params': {'entityNameOrId': 'Account', 'scope': 'RecentlyViewed',
                       'pageSize': 50},
        }]
        item = _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body(actions)),
                     _response(body=u'{"actions":[]}'))
        result = self._analyze([item])
        self.assertEqual(u'Record List/Search', result['operations'][0]['data_interaction'])
        account = next(row for row in result['object_field_catalog']['objects']
                       if row['object_name'] == u'Account')
        self.assertTrue(any(u'entityNameOrId' in reason for reason in account['reasons']))
        features = [row['feature'] for row in result['salesforce_features']]
        self.assertIn(u'getItems', features)

    def test_sparse_access_matrix_app_catalog_and_planning_gaps_are_separate(self):
        action = {'id': '1;a', 'descriptor': 'apex://AccountController/ACTION$getAccount',
                  'params': {'accountId': '001000000000001'}}
        context = {'fwuid': 'FW', 'app': 'markup://siteforce:communityApp'}
        items = [
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([action], context, u'/s/'),
                           [u'Cookie: sid=SESSION-A']), _response(body=u'{"actions":[]}'),
                  comment=u'[group="user1"]'),
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([action], context, u'/s/'),
                           [u'Cookie: sid=SESSION-B']), _response(body=u'{"actions":[]}'),
                  comment=u'[group="user2"]'),
            _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body([action], context, u'/s/')),
                  _response(body=u'{"actions":[]}')),
        ]
        result = self._analyze(items)
        self.assertEqual(0, result['summary']['technical_gaps'])
        self.assertGreater(result['summary']['planning_gaps'], 0)
        self.assertEqual(3, len(result['access_matrix']))
        self.assertTrue(all(row['observed'] for row in result['access_matrix']))
        self.assertTrue(all(u'not an Allow/Deny' in row['evidence']
                            for row in result['access_matrix']))
        self.assertTrue(result['app_endpoint_catalog'][0]['is_default_app'])
        gap_ids = set(row['gap_id'] for row in result['planning_gaps'])
        self.assertNotIn(u'subject-guest-not-observed', gap_ids)
        self.assertNotIn(u'subject-authenticated-not-observed', gap_ids)
        self.assertNotIn(u'subject-fewer-than-two-labeled-groups', gap_ids)
        self.assertIn(u'subject-relation-not-defined', gap_ids)
        self.assertIn(u'policy-ownership-relation-not-defined', gap_ids)
        serialized = json.dumps(result, default=lambda _value: '<item>', ensure_ascii=False)
        self.assertNotIn('SESSION-A', serialized)
        self.assertNotIn('SESSION-B', serialized)

    def test_data_interaction_taxonomy_covers_planning_categories(self):
        classify = authorization_planning_engine._data_interaction
        cases = [
            (u'GET', u'getRecord', u'/aura', u'Record Read'),
            (u'POST', u'getItems', u'/aura', u'Record List/Search'),
            (u'POST', u'createAccount', u'/aura', u'Record Create'),
            (u'PATCH', u'updateAccount', u'/aura', u'Record Update'),
            (u'DELETE', u'deleteAccount', u'/aura', u'Record Delete'),
            (u'POST', u'getConfigData', u'/aura', u'Metadata/Schema'),
            (u'POST', u'selfRegister', u'/aura', u'Authentication/Self-registration'),
            (u'GET', u'getHomeUrl', u'/home', u'Navigation/Admin Surface'),
            (u'POST', u'getComponentDef', u'/aura', u'UI Definition'),
            (u'POST', u'doThing', u'/aura', u'Unknown'),
        ]
        for method, operation, path, expected in cases:
            category, confidence, reasons, _intents = classify(method, operation, path, {})
            self.assertEqual(expected, category)
            self.assertIn(confidence, (u'low', u'medium', u'high'))
            self.assertTrue(reasons)

    def test_scope_only_filters_history_and_reports_url_failures(self):
        items = [
            _Item(_request(u'GET', u'/in'), _response(body=u'{}'),
                  url=u'https://example.my.site.com/in'),
            _Item(_request(u'GET', u'/out'), _response(body=u'{}'),
                  url=u'https://outside.example/out'),
            _Item(_request(u'GET', u'/unknown'), _response(body=u'{}'), url=None),
        ]
        callbacks = _Callbacks(items, scope_fn=lambda url: u'my.site.com' in url)
        progress = []
        result = authorization_planning_engine.analyze_history(
            callbacks, _Helpers(), scope_only=True, detector=_detector(),
            progress_fn=lambda current, total: progress.append((current, total)))
        self.assertEqual(3, result['summary']['packets_selected_by_range'])
        self.assertEqual(3, result['summary']['packets_considered'])
        self.assertEqual(1, result['summary']['packets_analyzed'])
        self.assertEqual(1, result['summary']['packets_excluded_out_of_scope'])
        self.assertEqual(1, result['summary']['scope_lookup_failures'])
        self.assertTrue(result['summary']['scope_only'])
        self.assertEqual([1], [packet['packet_no'] for packet in result['packets']])
        self.assertEqual([(1, 3), (2, 3), (3, 3)], progress)
        scope_gaps = [gap for gap in result['gaps'] if gap['stage'] == u'scope']
        self.assertEqual(1, len(scope_gaps))
        self.assertEqual(len(result['gaps']), result['summary']['technical_gaps'])

        unfiltered = authorization_planning_engine.analyze_history(
            callbacks, _Helpers(), scope_only=False, detector=_detector())
        self.assertEqual(3, unfiltered['summary']['packets_analyzed'])

    def test_non_aura_web11_routes_reach_operation_and_endpoint_catalogs(self):
        paths = [
            u'/web11/abc/app/customer/Message',
            u'/web11/abc/app/customer/Login',
            u'/web11/abc/app/customer/Entry',
        ]
        items = []
        for path in paths:
            items.append(_Item(
                _request(u'POST', path, u'customerId=123&text=日本語', [
                    u'Content-Type: application/x-www-form-urlencoded',
                    u'Origin: https://example.my.site.com',
                ]),
                _response(body=u'{"ok":true}', content_type=u'application/json'),
                url=u'https://example.my.site.com' + path))
        result = authorization_planning_engine.analyze_history(
            _Callbacks(items), _Helpers(), detector=_detector(),
            destination_rules=(
                u'On-prem | ^example\\.my\\.site\\.com$ | '
                u'^/web11/.+/(Login|Entry|Message)$'))

        operations = dict((row['path'], row) for row in result['operations'])
        self.assertEqual(set(paths), set(operations.keys()))
        self.assertEqual(u'Authentication/Self-registration',
                         operations[u'/web11/abc/app/customer/Login']['data_interaction'])
        for operation in operations.values():
            self.assertEqual(u'Custom same-origin/backend route',
                             operation['route_classification'])
            self.assertEqual(u'On-prem', operation['destination_label'])
            self.assertTrue(operation['parameters'])

        endpoints = dict((row['path'], row) for row in result['endpoint_catalog'])
        self.assertEqual(set(paths), set(endpoints.keys()))
        self.assertTrue(all(row['destination_label'] == u'On-prem'
                            for row in endpoints.values()))
        self.assertEqual(3, len(result['packet_catalog']))
        self.assertTrue(all(row['operation_count'] >= 1 for row in result['packet_catalog']))
        self.assertEqual(0, result['summary']['packets_without_operation'])
        self.assertFalse(any(gap['stage'] == u'operation_catalog' for gap in result['gaps']))

    def test_non_aura_absolute_form_and_missing_response_still_reach_catalog(self):
        path = u'/web11/abc/app/customer/Message'
        request = (u'POST https://example.my.site.com%s?customerId=123 HTTP/1.1\r\n'
                   u'Host: example.my.site.com:443\r\n'
                   u'Content-Type: application/json\r\n\r\n'
                   u'{"requestId":"REQ-1","message":"日本語"}') % path
        result = authorization_planning_engine.analyze_history(
            _Callbacks([_Item(request, None, url=u'https://example.my.site.com' + path)]),
            _Helpers(), detector=_detector(),
            destination_rules=u'On-prem | ^example\\.my\\.site\\.com$ | ^/web11/')
        self.assertEqual(1, len(result['operations']))
        self.assertEqual(path, result['operations'][0]['path'])
        self.assertEqual(u'On-prem', result['operations'][0]['destination_label'])
        self.assertEqual(1, result['packet_catalog'][0]['operation_count'])
        self.assertTrue(any(row['stage'] == u'response' and row['reason'] == u'missing response'
                            for row in result['gaps']))

    def test_invalid_destination_rule_is_a_technical_gap_not_a_build_failure(self):
        item = _Item(_request(u'GET', u'/web11/abc/app/customer/Entry'), _response(body=u'{}'))
        result = self._analyze([item], destination_rules=u'On-prem | [ | ^/web11/')
        self.assertEqual(1, len(result['operations']))
        self.assertEqual(u'', result['operations'][0]['destination_label'])
        self.assertTrue(any(row['stage'] == u'destination_rule' for row in result['gaps']))

    def test_non_aura_route_scope_filtering_is_explicit(self):
        inside = u'/web11/abc/app/customer/Login'
        outside = u'/web11/abc/app/customer/Entry'
        items = [
            _Item(_request(u'POST', inside, u'x=1'), _response(body=u'{}'),
                  url=u'https://inside.example' + inside),
            _Item(_request(u'POST', outside, u'x=2'), _response(body=u'{}'),
                  url=u'https://outside.example' + outside),
        ]
        result = authorization_planning_engine.analyze_history(
            _Callbacks(items, scope_fn=lambda url: u'inside.example' in url),
            _Helpers(), detector=_detector(), scope_only=True)
        self.assertEqual([inside], [row['path'] for row in result['operations']])
        self.assertEqual(1, result['summary']['packets_excluded_out_of_scope'])
        self.assertEqual([1], [row['packet_no'] for row in result['packet_catalog']])

    def test_non_record_surfaces_remain_visible_in_test_plan_without_resource_ids(self):
        actions = [
            {'id': '1;a', 'descriptor': 'aura://ConfigController/ACTION$getConfigData',
             'params': {}},
            {'id': '2;a', 'descriptor': 'aura://CommunityController/ACTION$selfRegister',
             'params': {}},
        ]
        item = _Item(_request(u'POST', u'/s/sfsites/aura', _aura_body(actions)),
                     _response(body=u'{"actions":[]}'))
        result = self._analyze([item])
        planned = dict((row['data_interaction'], row) for row in result['plan_rows'])
        self.assertIn(u'Metadata/Schema', planned)
        self.assertIn(u'Authentication/Self-registration', planned)
        self.assertEqual(u'(operation-level)', planned[u'Metadata/Schema']['candidate_path'])
        self.assertTrue(planned[u'Authentication/Self-registration']['reasons'])


if __name__ == '__main__':
    unittest.main()
