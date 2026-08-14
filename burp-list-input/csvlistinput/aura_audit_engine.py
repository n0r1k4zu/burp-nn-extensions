# -*- coding: utf-8 -*-
"""Independent Salesforce Aura diagnostic protocol primitives for MyTools.

This module intentionally has no dependency on burp-sf-aura.  Swing and
Burp transport are kept outside it so its request construction and response
parsing can be tested independently.
"""

import json
import re

try:
    from urllib import quote_plus, unquote_plus
except ImportError:
    from urllib.parse import quote_plus, unquote_plus


def build_action(action_id, descriptor, params=None, calling_descriptor=u'UNKNOWN'):
    return {'id': action_id, 'descriptor': descriptor,
            'callingDescriptor': calling_descriptor, 'params': params or {}}


def build_context(fwuid, app_name, mode=u'PROD'):
    key = u'APPLICATION@markup://%s' % app_name
    return json.dumps({'mode': mode, 'fwuid': fwuid, 'app': app_name,
                       'loaded': {key: app_name}, 'dn': [], 'globals': {}, 'uad': False})


def build_post_body(actions, aura_context, aura_token, page_uri=u'unknown'):
    message = json.dumps({'actions': actions})
    return u'&'.join([u'message=' + quote_plus(message),
                      u'aura.context=' + quote_plus(aura_context),
                      u'aura.pageURI=' + quote_plus(page_uri or u'unknown'),
                      u'aura.token=' + quote_plus(aura_token or u'undefined')])


def parse_response(text):
    try:
        return json.loads(text) if text else None
    except Exception:
        return None


def responses_by_id(response):
    return dict((action.get('id'), action) for action in (response or {}).get('actions', [])
                if action.get('id') is not None)


def action_success(response):
    return bool(response) and response.get('state') == u'SUCCESS'


def extract_session_from_request(request_text):
    """Extract a captured Aura session without sending any request."""
    body = request_text.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in request_text else u''
    values = {}
    for pair in body.split('&'):
        key, sep, value = pair.partition('=')
        if sep:
            values[key] = unquote_plus(value)
    context = values.get('aura.context')
    if not context:
        return None
    try:
        parsed = json.loads(context)
    except Exception:
        return None
    first = request_text.splitlines()[0].split() if request_text else []
    path = first[1].split('?', 1)[0] if len(first) > 1 else u''
    headers = request_text.split('\r\n\r\n', 1)[0].splitlines()[1:]
    cookie = next((line.split(':', 1)[1].strip() for line in headers if line.lower().startswith('cookie:')), u'')
    return {'endpoint_path': path, 'context': context, 'token': values.get('aura.token', u'undefined'),
            'page_uri': values.get('aura.pageURI', u'unknown'), 'fwuid': parsed.get('fwuid', u''),
            'app': parsed.get('app', u''), 'cookie': cookie}


def recon_actions(enabled):
    """Build selected low-volume reconnaissance actions; no transport occurs here."""
    actions = []
    if enabled.get('objects') or enabled.get('counts') or enabled.get('list_ui'):
        actions.append(build_action('1;a', u'aura://HostConfigController/ACTION$getConfigData'))
    if enabled.get('self_registration'):
        actions.extend(build_self_registration_actions())
    if enabled.get('graphql'):
        params = {'queryInput': {'operationName': 'getUsersCount',
                  'query': 'query getUsersCount{uiapi{query{User{totalCount}}}}', 'variables': {}}}
        actions.append(build_action('4;a', u'aura://RecordUiController/ACTION$executeGraphQL', params))
    if enabled.get('home_urls'):
        actions.append(build_home_bootstrap_action('5;a'))
    return actions


def build_object_count_action(action_id, object_name):
    return build_action(action_id,
        u'serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems',
        {'entityNameOrId': object_name, 'layoutType': 'COMPACT', 'pageSize': 1,
         'currentPage': 1, 'useTimeout': False, 'getCount': True, 'enableRowActions': False})


def build_list_views_action(action_id, object_name):
    return build_action(action_id,
        u'serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews',
        {'scope': object_name, 'maxMruResults': 10, 'maxAllResults': 20})


def build_list_items_action(action_id, object_name, filter_name):
    return build_action(action_id,
        u'serviceComponent://ui.force.components.controllers.lists.listViewDataManager.ListViewDataManagerController/ACTION$getItems',
        {'filterName': filter_name, 'entityName': object_name, 'pageSize': 50,
         'layoutType': 'LIST', 'getCount': True, 'enableRowActions': False, 'offset': 0})


def parse_config_result(action):
    if not action_success(action): return {}
    return (action.get('returnValue') or {}).get('apiNamesToKeyPrefixes') or {}


def parse_count_result(action):
    if not action_success(action): return None
    return (action.get('returnValue') or {}).get('totalCount')


def parse_list_views_result(action):
    if not action_success(action): return []
    return [item.get('name') for item in (action.get('returnValue') or {}).get('listViews', []) if item.get('name')]


def build_self_registration_actions():
    return [build_action('selfreg;enabled', u'apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled'),
            build_action('selfreg;url', u'apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl')]


def parse_self_registration_result(enabled_action, url_action):
    enabled = action_success(enabled_action) and bool(enabled_action.get('returnValue'))
    url = url_action.get('returnValue') if enabled and action_success(url_action) else None
    return enabled, url


def parse_list_items_result(action):
    if not action_success(action): return False
    return bool((action.get('returnValue') or {}).get('recordIdActionsList'))


def build_graphql_fields_action(action_id, object_names):
    names = json.dumps(list(object_names), separators=(',', ':'))
    query = u'query getFields{uiapi{objectInfos(apiNames:%s){ApiName,fields{ApiName,dataType}}}}' % names
    return build_action(action_id, u'aura://RecordUiController/ACTION$executeGraphQL',
                        {'queryInput': {'operationName': 'getFields', 'query': query, 'variables': {}}})


def parse_graphql_fields_result(action):
    if not action_success(action): return {}
    try: infos = action['returnValue']['data']['uiapi']['objectInfos']
    except Exception: return {}
    banned = set(['ADDRESS', 'ANYTYPE', 'COMPLEXVALUE'])
    result = {}
    for info in infos or []:
        name = info.get('ApiName')
        if not name: continue
        result[name] = [field.get('ApiName') for field in info.get('fields', [])
                        if field.get('ApiName') and field.get('dataType') not in banned
                        and field.get('ApiName') != 'CloneSourceId']
    return result


def build_graphql_rows_action(action_id, object_name, field_names, page_size=2000, after_cursor=None):
    fields = u','.join(u'%s{value}' % field for field in field_names)
    paging = u'first:%d' % page_size
    if after_cursor: paging += u', after:"%s"' % after_cursor
    query = u'query getRows{uiapi{query{%s(%s){edges{node{%s}}totalCount pageInfo{endCursor hasNextPage}}}}}' % (
        object_name, paging, fields)
    return build_action(action_id, u'aura://RecordUiController/ACTION$executeGraphQL',
                        {'queryInput': {'operationName': 'getRows', 'query': query, 'variables': {}}})


def parse_graphql_rows_result(action, object_name, field_names):
    if not action_success(action): return [], None, False, None
    try: result = action['returnValue']['data']['uiapi']['query'][object_name]
    except Exception: return [], None, False, None
    rows = []
    for edge in result.get('edges', []):
        node = edge.get('node') or {}
        rows.append(dict((field, (node.get(field) or {}).get('value')) for field in field_names))
    page = result.get('pageInfo') or {}
    return rows, page.get('endCursor'), bool(page.get('hasNextPage')), result.get('totalCount')


def build_getitems_records_action(action_id, object_name, page_size=2000, current_page=1, sort_by=None):
    params = {'entityNameOrId': object_name, 'layoutType': 'FULL', 'pageSize': page_size,
              'currentPage': current_page, 'useTimeout': False, 'getCount': False,
              'enableRowActions': False}
    if sort_by: params['sortBy'] = sort_by
    return build_action(action_id,
        u'serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems', params)


def parse_getitems_records_result(action):
    if not action_success(action): return []
    return (action.get('returnValue') or {}).get('records') or []


def build_home_bootstrap_action(action_id):
    return build_action(action_id,
        u'serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData')


def parse_home_urls_result(action):
    if not action_success(action): return {}
    try:
        components = action.get('components') or []
        return (components[0].get('model') or {}).get('apiNameToObjectHomeUrls') or {} if components else {}
    except Exception:
        return {}


def parse_apex_controller_names(text):
    return set(re.findall(r'apex://[A-Za-z0-9_-]+/ACTION\$[A-Za-z0-9_-]+', text or ''))


def parse_resource_urls(text):
    if not text: return []
    return re.findall(r'src="([^"]+)"', text) + re.findall(r'/auraCmdDef\?[^"\']+', text)


def endpoint_response_looks_valid(text):
    return bool(text) and u'markup://' in text


_TOKEN_RE = re.compile(r'eyJub[^";]+')
def token_from_text(text):
    match = _TOKEN_RE.search(text or u'')
    return match.group(0) if match else None
