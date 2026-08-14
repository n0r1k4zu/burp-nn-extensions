# -*- coding: utf-8 -*-
"""Build a de-duplicated request-parameter inventory from Proxy History.

The inventory deliberately delegates extraction to ``detection_engine`` so
it has the same JSON/XML/nested-value coverage as Target & List Mapping.
Structural paths are aggregated for the main table; per-value aggregates are
retained only in memory so the UI can reveal them for a user-selected path.
"""

import re

from csvlistinput import detection_engine, statistics_engine

try:
    _UNICODE_TYPE = unicode
except NameError:  # CPython test runtime
    _UNICODE_TYPE = str


def _display_value(value):
    """Safely make a parser's byte-string value suitable for a Swing cell."""
    if value is None:
        return u""
    if isinstance(value, _UNICODE_TYPE):
        return value
    try:
        return value.decode('utf-8')
    except UnicodeDecodeError:
        return value.decode('latin-1')


# These names are useful leads during authorized testing, not vulnerability
# findings.  The tiers merely make high-impact authorization, money movement,
# authentication, and PII-bearing fields easier to spot in a large inventory.
_HIGH_RISK = set([
    'userid', 'user_id', 'accountid', 'account_id', 'customerid', 'customer_id',
    'ownerid', 'owner_id', 'tenantid', 'tenant_id', 'organizationid', 'orgid',
    'role', 'roleid', 'permission', 'permissions', 'isadmin', 'admin',
    'amount', 'price', 'total', 'balance', 'currency', 'paymentid', 'transactionid',
    'transferid', 'walletid', 'bankaccount', 'cardnumber', 'creditcard',
])
_MEDIUM_RISK = set([
    'id', 'requestid', 'orderid', 'invoiceid', 'profileid', 'addressid', 'documentid',
    'token', 'accesstoken', 'refreshtoken', 'sessionid', 'apikey', 'api_key',
    'email', 'phone', 'mobile', 'address', 'birthdate', 'dob', 'ssn', 'passport',
])
_AGGRESSIVE_HIGH_HINTS = (
    'user', 'account', 'owner', 'tenant', 'org', 'role', 'permission', 'privilege',
    'auth', 'admin', 'amount', 'price', 'total', 'balance', 'cost', 'payment',
    'invoice', 'order', 'transaction', 'transfer', 'wallet', 'bank', 'card',
    'salary', 'quota', 'limit', 'credit', 'refund', 'discount')
_AGGRESSIVE_MEDIUM_HINTS = (
    'password', 'passwd', 'pwd', 'secret', 'token', 'session', 'csrf', 'nonce',
    'email', 'phone', 'mobile', 'address', 'birth', 'dob', 'ssn', 'passport',
    'name', 'key', 'identifier', 'request', 'redirect', 'return', 'url', 'query',
    'filter', 'sort', 'page', 'file', 'path', 'content', 'message')
_TOKEN_RE = re.compile(r'[a-z0-9]+')


def risk_level(path, aggressive=False):
    """Return ``high``, ``medium`` or ``None`` for a structural path."""
    lowered = (path or '').lower()
    normalized = lowered.replace('-', '_')
    compact = re.sub(r'[^a-z0-9]', '', lowered)
    tokens = set(_TOKEN_RE.findall(normalized))
    candidates = tokens | set([compact])
    if candidates & _HIGH_RISK:
        return 'high'
    if candidates & _MEDIUM_RISK:
        return 'medium'
    # Helpful variants such as ``userId`` become ``userid`` in compact.
    if any(word in compact for word in _HIGH_RISK if len(word) >= 5):
        return 'high'
    if any(word in compact for word in _MEDIUM_RISK if len(word) >= 5):
        return 'medium'
    if aggressive:
        if any(word in compact for word in _AGGRESSIVE_HIGH_HINTS):
            return 'high'
        if any(word in compact for word in _AGGRESSIVE_MEDIUM_HINTS):
            return 'medium'
    return None


def collect(callbacks, helpers, start_packet_no=None, end_packet_no=None, detector=None,
            cancel_check=None, aggressive_focus=False):
    """Return inventory rows for inclusive 1-based Proxy History bounds.

    Each row is ``{'path', 'count', 'packet_nos', 'risk', 'values'}``, sorted
    by path. ``values`` is an internal mapping used by ``value_rows()``.
    ``count`` is the number of appearances and ``packet_nos`` is the unique
    packet-number set in which that structural path appeared.
    """
    detector = detector or detection_engine.detect
    rows = {}
    packet_no = 0
    for item in callbacks.getProxyHistory():
        packet_no += 1
        if cancel_check and cancel_check():
            break
        if start_packet_no is not None and packet_no < start_packet_no:
            continue
        if end_packet_no is not None and packet_no > end_packet_no:
            break
        request_bytes = item.getRequest()
        if request_bytes is None:
            continue
        try:
            points = detector(helpers, request_bytes, item.getHttpService())
        except Exception:
            # One malformed/unusual packet must not prevent the rest of the
            # selected history from being inventoried.
            continue
        groups = statistics_engine.group_names(item.getComment() if hasattr(item, 'getComment') else u'')
        for point in points:
            path = point.path
            row = rows.get(path)
            if row is None:
                row = {'path': path, 'count': 0, 'packet_nos': set(), 'groups': set(),
                       'risk': risk_level(path, aggressive_focus), 'values': {}}
                rows[path] = row
            row['count'] += 1
            row['packet_nos'].add(packet_no)
            row['groups'].update(groups)
            value = _display_value(getattr(point, 'original_value', None))
            value_row = row['values'].get(value)
            if value_row is None:
                value_row = {'value': value, 'count': 0, 'packet_nos': set(), 'groups': set()}
                row['values'][value] = value_row
            value_row['count'] += 1
            value_row['packet_nos'].add(packet_no)
            value_row['groups'].update(groups)
    result = list(rows.values())
    for row in result:
        row['packet_nos'] = sorted(row['packet_nos'])
        row['groups'] = sorted(row['groups'])
    result.sort(key=lambda row: row['path'].lower())
    return result


def value_rows(parameter_row):
    """Return selected parameter's unique values, sorted for stable display."""
    if not parameter_row:
        return []
    result = []
    for row in parameter_row.get('values', {}).values():
        result.append({'value': row['value'], 'count': row['count'],
                       'packet_nos': sorted(row['packet_nos']), 'groups': sorted(row.get('groups', set()))})
    result.sort(key=lambda row: row['value'])
    return result
