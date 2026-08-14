# -*- coding: utf-8 -*-
import os, sys, unittest
THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(THIS_DIR))
from csvlistinput import aura_audit_engine as engine

class AuraAuditEngineTest(unittest.TestCase):
    def test_captured_session_and_post_body_are_independent_of_sf_helper(self):
        context = engine.build_context('FW', 'site.app')
        request = 'POST /s/sfsites/aura HTTP/1.1\r\nCookie: sid=x\r\n\r\n' + engine.build_post_body([], context, 'token', '/home')
        session = engine.extract_session_from_request(request)
        self.assertEqual('/s/sfsites/aura', session['endpoint_path'])
        self.assertEqual('FW', session['fwuid'])
        self.assertEqual('sid=x', session['cookie'])
        self.assertTrue(engine.parse_response('{"actions":[{"id":"1;a","state":"SUCCESS"}]}'))

    def test_recon_and_record_parsers(self):
        config = {'Account': '001', 'Contact': '003'}
        self.assertEqual(config, engine.parse_config_result({'state': 'SUCCESS', 'returnValue': {'apiNamesToKeyPrefixes': config}}))
        action = {'state': 'SUCCESS', 'returnValue': {'data': {'uiapi': {'query': {'Account': {
            'edges': [{'node': {'Name': {'value': 'Acme'}}}], 'totalCount': 1,
            'pageInfo': {'endCursor': 'x', 'hasNextPage': False}}}}}}}
        rows, cursor, more, total = engine.parse_graphql_rows_result(action, 'Account', ['Name'])
        self.assertEqual([{'Name': 'Acme'}], rows); self.assertEqual(('x', False, 1), (cursor, more, total))
        self.assertEqual(set(['apex://Demo/ACTION$run']), engine.parse_apex_controller_names('x apex://Demo/ACTION$run y'))
