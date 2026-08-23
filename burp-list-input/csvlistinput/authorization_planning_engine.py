# -*- coding: utf-8 -*-
"""Proxy Historyから認可テスト計画の材料を受動的に抽出する。

このモジュールはHistoryを読み取るだけで、送信・再送・History注釈の変更を
一切行わない。返却値はSwingでそのまま扱えるUnicode文字列へ正規化し、Cookie、
Authorization、CSRF、token等の秘密値を解析テーブル用フィールドへ複製せず、
Session識別にはfingerprintだけを使う。代表通信は既存History itemへの参照であり、
Burpのmessage viewerには元の通信がそのまま表示される。
"""

import hashlib
import json
import re

from csvlistinput import detection_engine, parameter_inventory_engine, statistics_engine
from csvlistinput.utils import to_display_text


_SF_ID_RE = re.compile(r'^[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?$')
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_LONG_HEX_RE = re.compile(r'^[0-9a-fA-F]{16,}$')
_GRAPHQL_OPERATION_RE = re.compile(r'\b(query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)')
_GRAPHQL_TOKEN_RE = re.compile(r'\.\.\.|[_A-Za-z][_0-9A-Za-z]*|[{}():!$@\[\],]')
_GRAPHQL_STRING_RE = re.compile(r'"""(?:.|\n)*?"""|"(?:\\.|[^"\\])*"', re.DOTALL)
_GRAPHQL_NUMBER_RE = re.compile(r'(?<![_A-Za-z0-9])[-+]?(?:\d+\.\d+|\d+)(?:[eE][-+]?\d+)?')
_ACTION_INDEX_RE = re.compile(r'actions\[(\d+)\]')
_STATIC_EXTENSIONS = set([
    u'js', u'css', u'map', u'png', u'jpg', u'jpeg', u'gif', u'svg', u'ico',
    u'webp', u'woff', u'woff2', u'ttf', u'eot', u'mp4', u'webm', u'mp3', u'pdf',
])
_BINARY_MIME_PREFIXES = (u'image/', u'audio/', u'video/', u'font/')
_BINARY_MIMES = set([u'application/octet-stream', u'application/pdf', u'application/zip'])
_MAX_RESPONSE_JSON_BYTES = 4 * 1024 * 1024
_MAX_VISIBLE_VALUE = 512

# Salesforceが提供するApex namespaceの代表例。完全な公式一覧ではないため、
# この集合によるStandard判定のconfidenceはmedium以下に留める。
_KNOWN_SALESFORCE_NAMESPACES = set([
    u'applauncher', u'communities', u'community', u'force', u'lightning',
    u'salesforce', u'sfdc', u'siteforce', u'ui', u'visualforce',
])

_READ_WORDS = (u'get', u'find', u'fetch', u'load', u'list', u'query', u'search',
               u'read', u'describe', u'count', u'view', u'bootstrap', u'initial')
_WRITE_WORDS = (u'create', u'insert', u'update', u'upsert', u'delete', u'remove',
                u'save', u'submit', u'approve', u'reject', u'change', u'set',
                u'assign', u'transfer', u'pay', u'refund', u'upload')

_GRAPHQL_SCAFFOLD_FIELDS = set([
    u'uiapi', u'query', u'mutation', u'edges', u'node', u'nodes', u'record',
    u'records', u'pageinfo', u'totalcount', u'count', u'errors', u'success',
    u'endcursor', u'startcursor', u'hasnextpage', u'haspreviouspage',
    u'eq', u'ne', u'lt', u'lte', u'gt', u'gte', u'like', u'in', u'nin',
    u'and', u'or', u'not', u'order', u'orderby', u'direction',
    u'returnvalue', u'state', u'message', u'attributes', u'pagesize', u'offset',
    u'limit', u'scope',
])

_OBJECT_PARAMETER_NAMES = set([
    u'objectapiname', u'objectname', u'entityapiname', u'sobjecttype',
    u'sobjectname', u'apiname', u'entitynameorid', u'scope', u'recordid',
])

# 通信ごとに変わっても業務上の操作を表さないAura値。重複候補の照合では除外する。
# recordId等の業務パラメータは除外しないため、別レコードへの操作を誤って重複扱いにしない。
_DEDUP_VOLATILE_FORM_KEYS = set([u'aura.context', u'aura.token'])


def parse_destination_rules(text):
    """利用者が指定する宛先ラベル規則を解析する。

    1行を ``Label | Host regular expression | Path regular expression`` とする。
    HostまたはPathは空欄にできるが、両方を空欄にはできない。物理的な宛先は
    HTTP通信だけでは断定しないため、ここでのLabelは仕様書等に基づく利用者の
    注釈であり、engineが推測した値ではない。
    """
    rules = []
    errors = []
    for line_no, raw_line in enumerate((_display(text) or u'').splitlines(), 1):
        line = _display(raw_line).strip()
        if not line or line.startswith(u'#'):
            continue
        # 空白付きの区切りを優先し、Path regex内の
        # ``(Login|Entry|Message)`` を列区切りと誤認しない。
        parts = ([part.strip() for part in line.split(u' | ', 2)]
                 if u' | ' in line else
                 [part.strip() for part in line.split(u'|', 2)])
        if len(parts) != 3:
            errors.append(u'line %d: use Label | Host regex | Path regex' % line_no)
            continue
        label, host_pattern, path_pattern = parts
        if not label or (not host_pattern and not path_pattern):
            errors.append(u'line %d: label and either Host or Path regex are required' % line_no)
            continue
        try:
            host_re = re.compile(host_pattern, re.I) if host_pattern else None
            path_re = re.compile(path_pattern) if path_pattern else None
        except Exception as exc:
            errors.append(u'line %d: invalid regular expression: %s' %
                          (line_no, _exception_text(exc)))
            continue
        rules.append({'label': label, 'host_regex': host_pattern,
                      'path_regex': path_pattern, 'host_re': host_re,
                      'path_re': path_re,
                      'source': u'User destination rule line %d' % line_no})
    return rules, errors

_FRAMEWORK_NAMES = set([
    u'message', u'aura.context', u'aura.pageuri', u'aura.token', u'fwuid',
    u'context', u'callingdescriptor', u'descriptor', u'actionid', u'action_id',
    u'content-length', u'host', u'origin', u'referer', u'user-agent',
])
_SECRET_FRAGMENTS = (
    u'authorization', u'proxy-authorization', u'cookie', u'password', u'passwd',
    u'secret', u'accesstoken', u'refreshtoken', u'access_token', u'refresh_token',
    u'aura.token', u'token', u'csrf', u'xsrf', u'sessionid', u'session_id',
    u'session', u'apikey', u'api_key',
)

_RESOURCE_HINTS = (
    ((u'owner', u'所有者'), u'Ownership / subject', 6),
    ((u'tenant', u'organization', u'orgid', u'テナント', u'組織'), u'Tenant / organization', 6),
    ((u'account', u'contact', u'user', u'parent', u'取引先', u'連絡先', u'ユーザー', u'親'), u'Record / subject identifier', 5),
    ((u'payment', u'order', u'invoice', u'transaction', u'支払', u'注文', u'請求', u'取引'), u'Business object identifier', 5),
    ((u'file', u'content', u'document', u'attachment', u'ファイル', u'コンテンツ', u'文書', u'添付'), u'File / content', 5),
    ((u'amount', u'price', u'total', u'balance', u'currency', u'refund', u'金額', u'価格', u'残高', u'通貨', u'返金'), u'Money', 6),
    ((u'role', u'permission', u'privilege', u'isadmin', u'admin', u'ロール', u'権限', u'管理者'), u'Authorization / role', 7),
    ((u'status', u'approval', u'approver', u'state', u'ステータス', u'状態', u'承認'), u'Workflow / status', 5),
    ((u'object', u'field', u'filter', u'query', u'sort', u'オブジェクト', u'項目', u'フィルタ', u'検索'), u'Object / field selector', 3),
    ((u'email', u'phone', u'mobile', u'address', u'birth', u'dob', u'ssn',
      u'passport', u'fullname', u'firstname', u'lastname', u'メール', u'電話',
      u'住所', u'生年月日', u'氏名', u'名前'), u'PII field', 5),
)


def _display(value):
    """任意のJava/Python文字列・UTF-8 byte-stringをUnicodeへ揃える。"""
    return to_display_text(value)


def _exception_text(exc):
    try:
        return _display(exc)
    except Exception:
        return u'unknown error'


def _utf8_bytes(value):
    """hashlibへ渡す境界を明示する（Jythonの暗黙ASCII変換を防ぐ）。"""
    return _display(value).encode('utf-8')


def _sha256(value):
    return u'sha256:' + _display(hashlib.sha256(_utf8_bytes(value)).hexdigest())


def _operation_id(parts):
    normalized = u'\x1f'.join([_display(part) for part in parts])
    return u'op-' + _display(hashlib.sha256(_utf8_bytes(normalized)).hexdigest()[:16])


def _http_text(helpers, raw):
    if raw is None:
        return u''
    try:
        text = _display(helpers.bytesToString(raw))
    except Exception:
        text = _display(raw)
    # BurpのbytesToStringはHTTP byteをLatin-1同値のJava Stringとして返す。
    # Java String proxyをto_display_textした場合、Jython ``str``のような
    # 型情報が残らずUTF-8 decodeの機会を失うため、可逆な場合だけ明示的に
    # Latin-1 bytesへ戻してUTF-8を試す。元から日本語UnicodeならLatin-1へ
    # encodeできないのでそのまま保持される。
    try:
        decoded = text.encode('latin-1').decode('utf-8')
        return decoded
    except (UnicodeEncodeError, UnicodeDecodeError, LookupError):
        return text


def _split_head_body(text):
    if u'\r\n\r\n' in text:
        return text.split(u'\r\n\r\n', 1)
    if u'\n\n' in text:
        return text.split(u'\n\n', 1)
    return text, u''


def _parse_headers(head):
    lines = head.replace(u'\r\n', u'\n').split(u'\n') if head else []
    headers = []
    by_name = {}
    for line in lines[1:]:
        name, separator, value = line.partition(u':')
        if not separator:
            continue
        normalized_name = _display(name).strip()
        normalized_value = _display(value).strip()
        headers.append((normalized_name, normalized_value))
        lowered = normalized_name.lower()
        if lowered not in by_name:
            by_name[lowered] = normalized_value
    return lines, headers, by_name


def _header_value(headers, name):
    return headers.get(_display(name).lower(), u'')


def _percent_decode(value, plus_as_space=True):
    """URL form値をbyte列として復元後、UTF-8優先でUnicode化する。"""
    value = _display(value)
    out = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == u'%' and index + 2 < len(value):
            token = value[index + 1:index + 3]
            try:
                out.append(int(token, 16))
                index += 3
                continue
            except (TypeError, ValueError):
                pass
        if char == u'+' and plus_as_space:
            out.append(32)
        else:
            encoded = char.encode('utf-8')
            for octet in bytearray(encoded):
                out.append(octet)
        index += 1
    try:
        return bytes(out).decode('utf-8')
    except Exception:
        try:
            return bytes(out).decode('latin-1')
        except Exception:
            # Jython環境でbytes(bytearray)の挙動が異なる場合の安全側fallback。
            return value.replace(u'+', u' ') if plus_as_space else value


def _parse_form(text):
    result = {}
    for pair in (_display(text) or u'').split(u'&'):
        key, separator, value = pair.partition(u'=')
        if not separator:
            continue
        decoded_key = _percent_decode(key)
        decoded_value = _percent_decode(value)
        result.setdefault(decoded_key, []).append(decoded_value)
    return result


def _merge_request_values(parsed_request):
    """Queryとform本文の値を、Aura判定用にひとつへまとめる。

    auraCmpDef/auraResourcesはGET queryにaura.appや_defを載せるため、本文だけを
    見るとAura文脈と対象コンポーネントを取り落とす。両方に同名の値がある場合も
    観測値として保持する。
    """
    merged = {}
    query_values = _parse_form(parsed_request.get('query'))
    body_values = _parse_form(parsed_request.get('body'))
    for source in (query_values, body_values):
        for key, values in source.items():
            merged.setdefault(key, []).extend(values)
    return merged


def _canonical_aura_message(value):
    """Aura action IDだけを除いて、同じ画面操作を比較可能な形にする。"""
    message = _safe_json(value)
    if not isinstance(message, dict):
        return _display(value)
    actions = message.get('actions')
    if isinstance(actions, list):
        normalized_actions = []
        for action in actions:
            if isinstance(action, dict):
                copied = dict(action)
                # idは一送信内のresponse対応番号であり、操作対象そのものではない。
                copied.pop('id', None)
                normalized_actions.append(copied)
            else:
                normalized_actions.append(action)
        message = dict(message)
        message['actions'] = normalized_actions
    try:
        return _display(json.dumps(message, ensure_ascii=True, sort_keys=True,
                                   separators=(u',', u':')))
    except Exception:
        return _display(value)


def _dedup_signature(parsed_request, request_values):
    """秘密値を保存せず、完全一致候補だけを保守的に判定するfingerprint。"""
    parts = [_display(parsed_request.get('method')).upper(),
             _display(parsed_request.get('path'))]
    for key in sorted(request_values.keys(), key=lambda value: _display(value).lower()):
        lowered = _display(key).lower()
        if lowered in _DEDUP_VOLATILE_FORM_KEYS:
            continue
        values = request_values.get(key) or []
        canonical_values = []
        for value in values:
            canonical_values.append(_canonical_aura_message(value) if lowered == u'message'
                                    else _display(value))
        parts.append(_display(key) + u'=' + u'|'.join(sorted(canonical_values)))
    return _sha256(u'\n'.join(parts))


def _parse_request(text):
    head, body = _split_head_body(text)
    lines, header_rows, headers = _parse_headers(head)
    first = lines[0].split() if lines else []
    method = _display(first[0]).upper() if first else u''
    target = _display(first[1]) if len(first) > 1 else u'/'
    # absolute-form request-targetにも対応する。ただし、auraCmpDefの
    # `_def=markup://namespace:component`のようなquery値にも`://`が現れる。
    # target全体に含まれるだけでabsolute-formと誤認すると、query値後半が
    # Path（例: //runtime_feature_usage_sdk:...）になってしまう。
    if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', target):
        remainder = target.split(u'://', 1)[1]
        slash = remainder.find(u'/')
        target = remainder[slash:] if slash >= 0 else u'/'
    raw_path, separator, query = target.partition(u'?')
    path = _percent_decode(raw_path, plus_as_space=False) or u'/'
    return {
        'method': method, 'target': target, 'path': path,
        'query': query if separator else u'', 'body': body,
        'headers': headers, 'header_rows': header_rows,
    }


def _parse_response(text):
    head, body = _split_head_body(text)
    lines, header_rows, headers = _parse_headers(head)
    status = None
    if lines:
        parts = lines[0].split()
        if len(parts) > 1:
            try:
                status = int(parts[1])
            except (TypeError, ValueError):
                status = None
    return {'status': status, 'body': body, 'headers': headers, 'header_rows': header_rows}


def _service_host(item):
    try:
        service = item.getHttpService()
        if service is not None:
            return _display(service.getHost())
    except Exception:
        pass
    return u''


def _history_item_url(helpers, item, request_bytes):
    """BurpのURL objectを値の文字列化なしでScope APIへ渡す。"""
    if hasattr(item, 'getUrl'):
        url = item.getUrl()
        if url is not None:
            return url
    if hasattr(helpers, 'analyzeRequest'):
        try:
            info = helpers.analyzeRequest(item)
        except Exception:
            service = item.getHttpService() if hasattr(item, 'getHttpService') else None
            info = helpers.analyzeRequest(service, request_bytes)
        if info is not None and hasattr(info, 'getUrl'):
            url = info.getUrl()
            if url is not None:
                return url
    raise ValueError(u'HTTP request URL could not be resolved for Target scope filtering')


def _content_type(headers):
    value = _header_value(headers, u'content-type')
    return value.split(u';', 1)[0].strip().lower()


def _normalized_path(path):
    path = _display(path) or u'/'
    if not path.startswith(u'/'):
        path = u'/' + path
    parts = path.split(u'/')
    normalized = []
    for part in parts:
        if _UUID_RE.match(part):
            normalized.append(u':uuid')
        elif _SF_ID_RE.match(part):
            normalized.append(u':sfid')
        elif _LONG_HEX_RE.match(part):
            normalized.append(u':hex')
        elif part.isdigit() and part:
            normalized.append(u':id')
        else:
            normalized.append(part)
    value = u'/'.join(normalized)
    if value != u'/' and value.endswith(u'/'):
        value = value[:-1]
    return value or u'/'


def _aura_component_definition_path(normalized_path, request_values):
    """auraCmpDef系をコンポーネント単位でCatalogへ残す表示用Pathを返す。

    通常のCatalog Pathはqueryを除くため、`auraCmpDef?_def=...`がすべて一行へ
    集約され、どのコンポーネント定義を取得した通信か分からなくなる。`_def`は
    その定義を特定する非秘密の識別子なので、Aura component definitionに限り
    canonical queryとして保持する。ルール照合用の正規化Pathは変更しない。
    """
    lowered = (_display(normalized_path) or u'').lower()
    if u'auracmpdef' not in lowered and u'auraresources' not in lowered:
        return normalized_path
    definition = (request_values.get(u'_def') or
                  request_values.get(u'def') or
                  request_values.get(u'aura.def') or [u''])[0]
    definition = _display(definition).strip()
    if not definition:
        return normalized_path
    return normalized_path + u'?_def=' + definition


def _aura_component_operation_name(normalized_path, request_values):
    """descriptorを持たないAura定義取得にも識別可能なOperation名を付ける。"""
    lowered = (_display(normalized_path) or u'').lower()
    definition = (request_values.get(u'_def') or
                  request_values.get(u'def') or
                  request_values.get(u'aura.def') or [u''])[0]
    definition = _display(definition).strip()
    if u'auracmpdef' in lowered:
        return u'Aura component definition' + (u': ' + definition if definition else u'')
    if u'auraresources' in lowered:
        return u'Aura resources' + (u': ' + definition if definition else u'')
    return u'Aura endpoint'


def _is_binary_content_type(content_type):
    content_type = (_display(content_type) or u'').lower()
    return content_type in _BINARY_MIMES or any(
        content_type.startswith(prefix) for prefix in _BINARY_MIME_PREFIXES)


def _safe_json(text):
    try:
        return json.loads(_display(text))
    except Exception:
        return None


def _secret_or_framework(path, region=None):
    lowered = (_display(path) or u'').lower().replace(u' ', u'')
    leaf = re.split(r'[\.\[\]/]', lowered)[-1]
    if lowered in _FRAMEWORK_NAMES or leaf in _FRAMEWORK_NAMES:
        return True
    if u'actions[' in lowered and (leaf == u'id' or lowered.endswith(u'].id')):
        return True
    if any(fragment in lowered for fragment in _SECRET_FRAGMENTS):
        return True
    if (_display(region) or u'').lower() == u'cookie':
        return True
    return False


def _redacted_value(path, region, value):
    if _secret_or_framework(path, region):
        return u'[redacted]'
    visible = _display(value)
    leaf = re.split(r'[.\[\]/]', _display(path).lower())[-1]
    if leaf in (u'query', u'graphql', u'querytext'):
        decoded = _decode_graphql_text(visible)
        if _graphql_candidate_score(decoded) >= 8:
            return u'[GraphQL query omitted; ' + _sha256(_sanitize_graphql_query(decoded)) + u']'
    if len(visible) > _MAX_VISIBLE_VALUE:
        return visible[:_MAX_VISIBLE_VALUE] + u'\u2026'
    return visible


def _flatten_scalars(value, prefix=u'', out=None):
    """JSON-like値を(path, scalar)へ再帰展開する。"""
    if out is None:
        out = []
    if isinstance(value, dict):
        for raw_key in sorted(value.keys(), key=lambda item: _display(item).lower()):
            key = _display(raw_key)
            path = key if not prefix else prefix + u'.' + key
            _flatten_scalars(value.get(raw_key), path, out)
    elif isinstance(value, list):
        path = prefix + u'[]'
        for child in value:
            _flatten_scalars(child, path, out)
    else:
        out.append((prefix or u'$', _display(value)))
    return out


def _json_type(value):
    if value is None:
        return u'null'
    if isinstance(value, bool):
        return u'boolean'
    if isinstance(value, (int, float)):
        return u'number'
    if isinstance(value, dict):
        return u'object'
    if isinstance(value, list):
        return u'array'
    return u'string'


def _schema_path(path):
    return re.sub(r'\[\d+\]', u'[]', _display(path))


def _resource_hint(path, value):
    """候補種別、基礎score、説明を返す。Noneは候補外。"""
    path_text = _display(path)
    value_text = _display(value)
    if _secret_or_framework(path_text):
        return None
    compact = re.sub(r'[^a-z0-9]', u'', path_text.lower())
    best = None
    for fragments, candidate_type, score in _RESOURCE_HINTS:
        if any(fragment in compact for fragment in fragments):
            if best is None or score > best[1]:
                best = (candidate_type, score, u'field/path name suggests ' + candidate_type)
    leaf = re.split(r'[\.\[\]/]', path_text.lower())[-1]
    if leaf == u'id' or leaf.endswith(u'id'):
        identifier = (u'Record identifier', 5, u'field/path name ends with id')
        if best is None or identifier[1] > best[1]:
            best = identifier
    if _SF_ID_RE.match(value_text):
        identifier = (u'Salesforce record identifier', 8,
                      u'value resembles a Salesforce 15/18-character ID')
        if best is None or identifier[1] > best[1]:
            best = identifier
    elif _UUID_RE.match(value_text) or _LONG_HEX_RE.match(value_text):
        identifier = (u'Record identifier', 6, u'value resembles an opaque identifier')
        if best is None or identifier[1] > best[1]:
            best = identifier
    return best


def _behavior(method, operation_name, graphql_kind=None):
    if graphql_kind == u'query':
        return u'Read'
    if graphql_kind in (u'mutation', u'subscription'):
        return u'Write' if graphql_kind == u'mutation' else u'Read'
    lowered = (_display(operation_name) or u'').lower()
    if any(word in lowered for word in _WRITE_WORDS):
        return u'Write'
    if any(word in lowered for word in _READ_WORDS):
        return u'Read'
    method = (_display(method) or u'').upper()
    if method in (u'GET', u'HEAD', u'OPTIONS'):
        return u'Read'
    if method in (u'PUT', u'PATCH', u'DELETE'):
        return u'Write'
    return u'Unknown'


def _crud_intents(operation_name, method=u'', graphql_details=None):
    if graphql_details and graphql_details.get('crud_intents'):
        return list(graphql_details.get('crud_intents'))
    lowered = (_display(operation_name) or u'').lower()
    intents = []
    if any(word in lowered for word in (u'delete', u'remove', u'destroy')) or _display(method).upper() == u'DELETE':
        intents.append(u'Delete')
    if any(word in lowered for word in (u'create', u'insert', u'new')) or _display(method).upper() == u'POST':
        if any(word in lowered for word in (u'create', u'insert', u'new')):
            intents.append(u'Create')
    if any(word in lowered for word in (u'update', u'upsert', u'save', u'change', u'set')) or _display(method).upper() in (u'PUT', u'PATCH'):
        intents.append(u'Update')
    if not intents:
        if any(word in lowered for word in (u'list', u'search', u'query', u'find', u'items', u'count')):
            intents.append(u'List/Search')
        elif any(word in lowered for word in _READ_WORDS) or _display(method).upper() in (u'GET', u'HEAD'):
            intents.append(u'Read')
    return sorted(set(intents))


def _data_interaction(method, operation_name, path=u'', params=None, graphql_details=None):
    """データとの関わりをOriginとは独立に分類する。"""
    params = params if isinstance(params, dict) else {}
    text = u' '.join([
        _display(operation_name), _display(path),
        u' '.join([_display(key) for key in params.keys()]),
    ]).lower()
    reasons = []
    if graphql_details:
        text += u' ' + _display(graphql_details.get('query_preview')).lower()
    if any(word in text for word in (
            u'selfregister', u'self-register', u'self_registration', u'selfregistration',
            u'registration', u'signup', u'sign-up', u'login', u'logout', u'authenticate')):
        return (u'Authentication/Self-registration', u'high',
                [u'operation/path contains an authentication or registration indicator'], [])
    if any(word in text for word in (
            u'getcomponentdef', u'componentdef', u'getapplication', u'applicationdef',
            u'component definition', u'uidescription')):
        return (u'UI Definition', u'high',
                [u'operation identifies application/component definition retrieval'], [])
    if any(word in text for word in (
            u'getconfigdata', u'describe', u'metadata', u'objectinfo', u'picklistvalues',
            u'schema', u'layoutinfo')):
        return (u'Metadata/Schema', u'high',
                [u'operation identifies configuration, metadata, schema, or layout retrieval'], [])
    if any(word in text for word in (
            u'homeurl', u'recordlist', u'listview', u'navigation', u'navmenu',
            u'admin', u'setup', u'management')):
        return (u'Navigation/Admin Surface', u'medium',
                [u'operation/path suggests navigation, record-list, home, or administration surface'], [])
    intents = _crud_intents(operation_name, method, graphql_details)
    if u'Delete' in intents:
        reasons.append(u'delete intent inferred from GraphQL/method/operation name')
        return u'Record Delete', u'high' if graphql_details else u'medium', reasons, intents
    if u'Create' in intents:
        reasons.append(u'create intent inferred from GraphQL/method/operation name')
        return u'Record Create', u'high' if graphql_details else u'medium', reasons, intents
    if u'Update' in intents or u'Mutation' in intents:
        reasons.append(u'update or mutation intent inferred from GraphQL/method/operation name')
        return u'Record Update', u'high' if graphql_details else u'medium', reasons, intents
    if u'List/Search' in intents:
        reasons.append(u'list/search intent inferred from GraphQL/method/operation name')
        return u'Record List/Search', u'high' if graphql_details else u'medium', reasons, intents
    if u'Read' in intents:
        reasons.append(u'read intent inferred from GraphQL/method/operation name')
        return u'Record Read', u'medium', reasons, intents
    if any(_display(key).lower().replace(u'_', u'') in _OBJECT_PARAMETER_NAMES
           for key in params.keys()):
        return (u'Record Read', u'low',
                [u'object API name parameter was observed, but operation intent is ambiguous'], [u'Read'])
    return (u'Unknown', u'low',
            [u'no reliable data-interaction indicator was observed in passive traffic'], [])


def _salesforce_features(operation_name, descriptor=u'', path=u'', page_uri=u'',
                         graphql_details=None):
    text = u' '.join([_display(operation_name), _display(descriptor),
                      _display(path), _display(page_uri)]).lower()
    features = set()
    if u'aura' in text:
        features.add(u'Aura Endpoint')
    if u'sfsites/aura' in text:
        features.add(u'Experience Cloud Aura')
    if u'getconfigdata' in text:
        features.add(u'getConfigData')
    if u'getitems' in text:
        features.add(u'getItems')
        features.add(u'Record List')
    if u'recordlist' in text or u'listview' in text:
        features.add(u'Record List')
    if u'homeurl' in text or re.search(r'(^|[/ ])home([/? ]|$)', text):
        features.add(u'Home URL')
    if any(word in text for word in (u'selfregister', u'self-registration', u'selfregistration', u'signup')):
        features.add(u'Self-registration')
    if u'getcomponentdef' in text:
        features.add(u'getComponentDef')
    if u'getapplication' in text:
        features.add(u'getApplication')
    if graphql_details:
        features.add(u'GraphQL')
        if graphql_details.get('kind') == u'mutation':
            features.add(u'GraphQL Mutation')
        elif graphql_details.get('kind') == u'query':
            features.add(u'GraphQL Query')
        if graphql_details.get('has_pagination'):
            features.add(u'GraphQL Pagination')
        if graphql_details.get('has_filter'):
            features.add(u'GraphQL Filter')
    return sorted(features)


def _descriptor_parts(descriptor):
    descriptor = _display(descriptor)
    scheme, separator, rest = descriptor.partition(u'://')
    controller = rest
    action = u''
    if u'/ACTION$' in rest:
        controller, action = rest.split(u'/ACTION$', 1)
    return scheme.lower() if separator else u'', controller, action


def _origin_for_apex_class(class_name, namespace=u''):
    class_name = _display(class_name).strip()
    namespace = _display(namespace).strip()
    if not namespace and u'.' in class_name:
        namespace, class_name = class_name.split(u'.', 1)
    if namespace:
        if namespace.lower() in _KNOWN_SALESFORCE_NAMESPACES:
            return (u'Salesforce Standard', u'medium',
                    u'known Salesforce namespace: ' + namespace)
        return (u'Managed or Namespaced Apex', u'medium',
                u'explicit Apex namespace: ' + namespace)
    if class_name:
        return (u'Org Custom Apex', u'medium', u'Apex class has no explicit namespace')
    return (u'Unknown', u'low', u'Apex class/namespace was not available')


def _origin(descriptor, params=None):
    descriptor = _display(descriptor).strip()
    params = params if isinstance(params, dict) else {}
    scheme, controller, _action = _descriptor_parts(descriptor)
    if scheme == u'aura' and controller.lower().endswith(u'apexactioncontroller'):
        class_name = params.get('classname') or params.get('apexClass') or params.get('className') or u''
        namespace = params.get('namespace') or u''
        return _origin_for_apex_class(class_name, namespace)
    if scheme in (u'aura', u'servicecomponent'):
        return (u'Salesforce Standard', u'high',
                u'descriptor uses Salesforce framework scheme ' + scheme + u'://')
    if scheme == u'apex':
        return _origin_for_apex_class(controller)
    return (u'Unknown', u'low', u'descriptor scheme is missing or not recognized')


def _generic_apex_operation(params, fallback):
    if not isinstance(params, dict):
        return fallback
    class_name = _display(params.get('classname') or params.get('apexClass') or params.get('className') or u'')
    namespace = _display(params.get('namespace') or u'')
    method = _display(params.get('method') or params.get('methodName') or u'')
    if namespace and class_name and not class_name.startswith(namespace + u'.'):
        class_name = namespace + u'.' + class_name
    if class_name and method:
        return class_name + u'.' + method
    return class_name or method or fallback


def _graphql_metadata(parsed_request):
    body_json = _safe_json(parsed_request.get('body'))
    operation_name = u''
    query = u''
    if isinstance(body_json, dict):
        operation_name = _display(body_json.get('operationName'))
        query = _display(body_json.get('query'))
    if not query:
        form = _parse_form(parsed_request.get('body'))
        query = (form.get(u'query') or [u''])[0]
        operation_name = operation_name or (form.get(u'operationName') or [u''])[0]
    if not query:
        query_form = _parse_form(parsed_request.get('query'))
        query = (query_form.get(u'query') or [u''])[0]
        operation_name = operation_name or (query_form.get(u'operationName') or [u''])[0]
    match = _GRAPHQL_OPERATION_RE.search(query or u'')
    kind = _display(match.group(1)).lower() if match else u''
    if not operation_name and match:
        operation_name = _display(match.group(2))
    return operation_name, kind, body_json


def _graphql_candidate_score(text):
    lowered = (_display(text) or u'').lower()
    score = 0
    if re.search(r'\b(query|mutation|subscription)\b', lowered):
        score += 8
    if u'{' in lowered and u'}' in lowered:
        score += 4
    if u'uiapi' in lowered:
        score += 3
    if u'%7b' not in lowered and u'%20' not in lowered:
        score += 1
    return score


def _decode_graphql_text(value):
    """percent/plus encodingが重なったGraphQL文字列を最大4層まで復元する。"""
    initial = _display(value).strip()
    candidates = [initial]
    seen = set([initial])
    frontier = [initial]
    for _depth in range(4):
        next_frontier = []
        for current in frontier:
            for plus_as_space in (True, False):
                decoded = _percent_decode(current, plus_as_space=plus_as_space)
                if decoded not in seen:
                    seen.add(decoded)
                    candidates.append(decoded)
                    next_frontier.append(decoded)
            parsed = _safe_json(current)
            if isinstance(parsed, (str, unicode if 'unicode' in globals() else str)):
                parsed_text = _display(parsed)
                if parsed_text not in seen:
                    seen.add(parsed_text)
                    candidates.append(parsed_text)
                    next_frontier.append(parsed_text)
        frontier = next_frontier
        if not frontier:
            break
    candidates.sort(key=lambda text: (_graphql_candidate_score(text), len(text)), reverse=True)
    return candidates[0] if candidates else initial


def _sanitize_graphql_query(query):
    """inline literalを除去し、画面に出して安全な構造previewを作る。"""
    text = re.sub(r'#[^\r\n]*', u' ', _display(query))
    text = _GRAPHQL_STRING_RE.sub(u'"?"', text)
    text = _GRAPHQL_NUMBER_RE.sub(u'?', text)
    text = re.sub(
        r'(?i)\b(authorization|password|passwd|secret|token|session|csrf|xsrf)\b\s*:\s*[$_A-Za-z][_0-9A-Za-z]*',
        lambda match: _display(match.group(1)) + u':?', text)
    text = re.sub(r'\s+', u' ', text).strip()
    if len(text) > 1024:
        text = text[:1024] + u'\u2026'
    return text


def _skip_graphql_balanced(tokens, index, opening, closing):
    if index >= len(tokens) or tokens[index] != opening:
        return index
    depth = 0
    while index < len(tokens):
        token = tokens[index]
        if token == opening:
            depth += 1
        elif token == closing:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return index


def _graphql_selection_paths(tokens):
    """小さなselection-set parser。外部GraphQLライブラリなしでpathを復元する。"""
    paths = []
    type_conditions = []

    def parse_set(index, prefix):
        if index >= len(tokens) or tokens[index] != u'{':
            return index
        index += 1
        while index < len(tokens) and tokens[index] != u'}':
            token = tokens[index]
            if token == u'...':
                index += 1
                if index < len(tokens) and tokens[index].lower() == u'on':
                    index += 1
                    if index < len(tokens):
                        type_conditions.append(tokens[index])
                        index += 1
                elif index < len(tokens):
                    index += 1
                while index < len(tokens) and tokens[index] == u'@':
                    index += 1
                    if index < len(tokens):
                        index += 1
                    if index < len(tokens) and tokens[index] == u'(':
                        index = _skip_graphql_balanced(tokens, index, u'(', u')')
                if index < len(tokens) and tokens[index] == u'{':
                    index = parse_set(index, prefix)
                continue
            if not re.match(r'^[_A-Za-z]', token):
                index += 1
                continue
            field = token
            index += 1
            if index < len(tokens) and tokens[index] == u':':
                index += 1
                if index < len(tokens) and re.match(r'^[_A-Za-z]', tokens[index]):
                    field = tokens[index]
                    index += 1
            if index < len(tokens) and tokens[index] == u'(':
                index = _skip_graphql_balanced(tokens, index, u'(', u')')
            while index < len(tokens) and tokens[index] == u'@':
                index += 1
                if index < len(tokens):
                    index += 1
                if index < len(tokens) and tokens[index] == u'(':
                    index = _skip_graphql_balanced(tokens, index, u'(', u')')
            path = prefix + [field]
            paths.append(u'.'.join(path))
            if index < len(tokens) and tokens[index] == u'{':
                index = parse_set(index, path)
        return index + 1 if index < len(tokens) else index

    try:
        start = tokens.index(u'{')
    except ValueError:
        return [], []
    parse_set(start, [])
    return paths, type_conditions


def _graphql_crud_intents(kind, query_preview, field_paths):
    lowered = (u' '.join(field_paths) + u' ' + _display(query_preview)).lower()
    intents = []
    if kind == u'mutation':
        if any(word in lowered for word in (u'delete', u'remove', u'destroy')):
            intents.append(u'Delete')
        if any(word in lowered for word in (u'create', u'insert')):
            intents.append(u'Create')
        if any(word in lowered for word in (u'update', u'upsert', u'save')):
            intents.append(u'Update')
        if not intents:
            intents.append(u'Mutation')
    elif kind in (u'query', u'subscription'):
        if re.search(r'\b(list|search|items|edges|nodes)\b', lowered):
            intents.append(u'List/Search')
        else:
            intents.append(u'Read')
    return intents


def _graphql_details(query, operation_name=u'', variables_present=False):
    decoded = _decode_graphql_text(query)
    sanitized = _sanitize_graphql_query(decoded)
    tokens = [_display(token) for token in _GRAPHQL_TOKEN_RE.findall(sanitized)]
    match = _GRAPHQL_OPERATION_RE.search(decoded)
    kind = _display(match.group(1)).lower() if match else u''
    if not operation_name and match:
        operation_name = _display(match.group(2))
    if not kind and sanitized.lstrip().startswith(u'{'):
        kind = u'query'
    field_paths, type_conditions = _graphql_selection_paths(tokens)
    objects = set()
    object_fields = {}
    for type_name in type_conditions:
        if type_name and type_name.lower() not in _GRAPHQL_SCAFFOLD_FIELDS:
            objects.add(type_name)
    for path in field_paths:
        segments = path.split(u'.')
        lowered = [segment.lower() for segment in segments]
        object_name = u''
        if u'query' in lowered:
            query_index = lowered.index(u'query')
            if query_index + 1 < len(segments):
                object_name = segments[query_index + 1]
        elif u'uiapi' in lowered and len(segments) > lowered.index(u'uiapi') + 1:
            object_name = segments[lowered.index(u'uiapi') + 1]
        elif segments and (segments[0].endswith(u'__c') or
                           (segments[0][:1].isupper() and segments[0].lower() not in _GRAPHQL_SCAFFOLD_FIELDS)):
            object_name = segments[0]
        if kind == u'mutation':
            for segment in segments:
                candidate = re.sub(r'(Create|Update|Delete|Upsert|Input|Payload)$', u'', segment)
                if candidate != segment and candidate:
                    object_name = candidate
                    break
        if object_name and object_name.lower() not in _GRAPHQL_SCAFFOLD_FIELDS:
            objects.add(object_name)
            leaf = segments[-1] if segments else u''
            mutation_root = bool(re.search(r'(Create|Update|Delete|Upsert|Input|Payload)$', leaf))
            structural_branch = any(segment.lower() in (u'errors', u'pageinfo')
                                    for segment in segments[:-1])
            if (leaf and leaf.lower() not in _GRAPHQL_SCAFFOLD_FIELDS and
                    leaf != object_name and not mutation_root and not structural_branch):
                object_fields.setdefault(object_name, set()).add(leaf)
    fields = set()
    for path in field_paths:
        leaf = path.rsplit(u'.', 1)[-1]
        mutation_root = bool(re.search(r'(Create|Update|Delete|Upsert|Input|Payload)$', leaf))
        structural_branch = any(segment.lower() in (u'errors', u'pageinfo')
                                for segment in path.split(u'.')[:-1])
        if (leaf.lower() not in _GRAPHQL_SCAFFOLD_FIELDS and leaf not in objects and
                not mutation_root and not structural_branch):
            fields.add(leaf)
    has_filter = bool(re.search(r'\b(where|filter|filters)\b|\$filter\b', sanitized, re.I))
    has_pagination = bool(re.search(
        r'\b(first|last|after|before|cursor|pageInfo|edges|offset|limit)\b', sanitized, re.I))
    reasons = []
    confidence = u'low'
    if kind:
        reasons.append(u'GraphQL operation kind parsed from query text')
        confidence = u'medium'
    if field_paths:
        reasons.append(u'GraphQL selection-set paths parsed')
        confidence = u'high' if kind else u'medium'
    if objects:
        reasons.append(u'object names inferred from UI API query/mutation structure')
    return {
        'kind': kind or u'unknown', 'operation_name': _display(operation_name),
        'query_fingerprint': _sha256(sanitized), 'query_preview': sanitized,
        'objects': sorted(objects), 'fields': sorted(fields),
        'field_paths': sorted(set(field_paths)),
        'object_fields': dict((name, sorted(values)) for name, values in object_fields.items()),
        'has_filter': has_filter, 'has_pagination': has_pagination,
        'variables_present': bool(variables_present or u'$' in sanitized),
        'crud_intents': _graphql_crud_intents(kind, sanitized, field_paths),
        'parse_confidence': confidence, 'reasons': reasons,
    }


def _graphql_details_from_params(params):
    candidates = []
    variables_present = [False]

    def visit(value, path=u'params', depth=0):
        if depth > 12:
            return
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = _display(raw_key)
                lowered = key.lower()
                child_path = path + u'.' + key
                if lowered in (u'variables', u'variablevalues', u'queryvariables') and child:
                    variables_present[0] = True
                if lowered in (u'query', u'graphql', u'querytext') and not isinstance(child, (dict, list)):
                    candidates.append(_display(child))
                visit(child, child_path, depth + 1)
        elif isinstance(value, list):
            for child in value:
                visit(child, path + u'[]', depth + 1)
        else:
            text = _display(value).strip()
            if text.startswith((u'{', u'"{')) or u'%7b' in text.lower():
                parsed = _safe_json(_decode_graphql_text(text))
                if isinstance(parsed, (dict, list)):
                    visit(parsed, path, depth + 1)

    visit(params)
    if not candidates:
        return None
    candidates.sort(key=lambda text: (_graphql_candidate_score(_decode_graphql_text(text)), len(text)),
                    reverse=True)
    details = _graphql_details(candidates[0], variables_present=variables_present[0])
    return details if details.get('kind') != u'unknown' or details.get('field_paths') else None


def _graphql_details_from_request(parsed_request):
    operation_name, _kind, body_json = _graphql_metadata(parsed_request)
    query = u''
    variables_present = False
    if isinstance(body_json, dict):
        query = _display(body_json.get('query'))
        variables_present = bool(body_json.get('variables'))
    if not query:
        form = _parse_form(parsed_request.get('body'))
        query = (form.get(u'query') or [u''])[0]
        variables_present = bool((form.get(u'variables') or [u''])[0])
    if not query:
        form = _parse_form(parsed_request.get('query'))
        query = (form.get(u'query') or [u''])[0]
        variables_present = bool((form.get(u'variables') or [u''])[0])
    return _graphql_details(query, operation_name, variables_present) if query else None


def _protocol_kind(path, method, request_content_type, response_content_type,
                   parsed_request, aura_present):
    lowered = (_display(path) or u'').lower()
    if aura_present:
        return u'Aura'
    operation_name, graphql_kind, body_json = _graphql_metadata(parsed_request)
    if (u'graphql' in lowered or operation_name or graphql_kind or
            (isinstance(body_json, dict) and u'query' in body_json)):
        return u'GraphQL'
    if u'/ui-api/' in lowered or u'/uiapi/' in lowered:
        return u'UI API'
    if lowered.startswith(u'/services/data/') or lowered.startswith(u'/api/') or u'/rest/' in lowered:
        return u'REST'
    filename = lowered.rsplit(u'/', 1)[-1]
    extension = filename.rsplit(u'.', 1)[-1] if u'.' in filename else u''
    if (extension in _STATIC_EXTENSIONS or _is_binary_content_type(response_content_type) or
            _is_binary_content_type(request_content_type)):
        return u'File'
    if u'html' in response_content_type or u'html' in request_content_type:
        return u'Web'
    if u'json' in request_content_type or u'json' in response_content_type:
        return u'REST'
    if _display(method).upper() in (u'GET', u'HEAD'):
        return u'Web'
    return u'Other'


def _url_host(value):
    """Origin/Referer等から比較用hostを安全に取り出す（DNS等は行わない）。"""
    value = (_display(value) or u'').strip()
    if not value:
        return u''
    match = re.match(r'^[a-z][a-z0-9+.-]*://([^/?#]+)', value, re.I)
    if not match:
        return u''
    authority = match.group(1).rsplit(u'@', 1)[-1]
    if authority.startswith(u'['):
        closing = authority.find(u']')
        return authority[:closing + 1].lower() if closing >= 0 else authority.lower()
    return authority.split(u':', 1)[0].lower()


def _host_without_port(host):
    value = (_display(host) or u'').strip().lower()
    if value.startswith(u'['):
        closing = value.find(u']')
        return value[:closing + 1] if closing >= 0 else value
    return value.split(u':', 1)[0]


def _route_classification(protocol_kind, parsed_request, host):
    """HTTP上で分かる経路種別だけを返す。オンプレ等の物理配置は推測しない。"""
    if protocol_kind == u'Aura':
        return u'Salesforce Aura', u'high', [u'Aura message/actions or Aura request marker was observed']
    if protocol_kind == u'GraphQL':
        return u'GraphQL', u'high', [u'GraphQL request shape or endpoint marker was observed']
    if protocol_kind == u'UI API':
        return u'Salesforce UI API', u'high', [u'UI API path marker was observed']
    path = _display(parsed_request.get('path')).lower()
    if path.startswith(u'/services/data/'):
        return u'Salesforce REST API', u'high', [u'Salesforce services/data path marker was observed']

    headers = parsed_request.get('headers') or {}
    observed_origin = _url_host(_header_value(headers, u'origin'))
    observed_referer = _url_host(_header_value(headers, u'referer'))
    route_host = _host_without_port(host)
    for source, source_host in ((u'Origin', observed_origin), (u'Referer', observed_referer)):
        if source_host and route_host and source_host != route_host:
            return (u'External/cross-host route', u'medium',
                    [source + u' host differs from request Host'])
    if observed_origin or observed_referer:
        return (u'Custom same-origin/backend route', u'medium',
                [u'Origin/Referer host matches request Host or no cross-host difference was observed'])
    return (u'Custom same-origin/backend route', u'low',
            [u'No Origin/Referer evidence was available; same-origin/backend is not proven'])


def _destination_for_route(host, path, rules):
    """明示設定された規則だけで宛先ラベルを付ける。物理的宛先を推測しない。"""
    for rule in rules or []:
        host_re = rule.get('host_re')
        path_re = rule.get('path_re')
        if host_re is not None:
            raw_host = _display(host)
            if not host_re.search(raw_host) and not host_re.search(_host_without_port(raw_host)):
                continue
        if path_re is not None and not path_re.search(_display(path)):
            continue
        return (rule.get('label', u''), u'medium', rule.get('source', u'User destination rule'),
                [u'Matched user-configured host/path route rule'])
    return (u'', u'low', u'No user destination rule matched',
            [u'HTTP evidence alone does not establish physical destination infrastructure'])


def _call_detector(detector, helpers, request_bytes, service, on_error):
    target = detector or detection_engine.detect
    if hasattr(target, 'detect'):
        target = target.detect
    # 既存テスト/利用側の3引数detectorも許容する。TypeErrorがdetector内部で
    # 発生した場合も次の呼び出しが失敗し、packet単位のgapとして回収される。
    try:
        return target(helpers, request_bytes, service, on_error=on_error)
    except TypeError:
        return target(helpers, request_bytes, service)


def _point_record(point, path_override=None):
    path = _display(path_override if path_override is not None else getattr(point, 'path', u''))
    point_type = _display(getattr(point, 'type', u'Unknown'))
    region = _display(parameter_inventory_engine.region_for_point(point) or u'Unknown')
    nesting = getattr(point, 'nesting_depth', 0)
    try:
        nesting = int(nesting or 0)
    except (TypeError, ValueError):
        nesting = 0
    value = _redacted_value(path, region, getattr(point, 'original_value', u''))
    return {'path': _schema_path(path), 'type': point_type, 'region': region,
            'nesting': nesting, 'nesting_depth': nesting, 'value': value,
            'recovered': bool(getattr(point, 'recovered', False))}


def _new_operation(operation_id, protocol_kind, origin, confidence, reason,
                   host, method, path, descriptor, calling_descriptor,
                   operation_name, behavior, item, packet_no):
    return {
        'operation_id': operation_id, 'protocol_kind': protocol_kind,
        'origin': origin, 'origin_confidence': confidence, 'origin_reason': reason,
        'host': host, 'method': method, 'path': path, 'descriptor': descriptor,
        'calling_descriptor': calling_descriptor, 'operation_name': operation_name,
        'behavior': behavior, 'occurrences': 0, '_packet_nos': set(),
        '_status_codes': set(), '_request_content_types': set(),
        '_response_content_types': set(), '_parameters': {},
        '_resource_candidates': {}, '_response_fields': {},
        '_response_schema_paths': set(), '_response_resource_keys': set(),
        '_observed_groups': set(), '_traffic_classes': set(),
        '_session_contexts': {}, '_app_ids': set(), '_aura_endpoints': set(),
        '_salesforce_features': set(), 'graphql': None,
        'data_interaction': u'Unknown', 'data_interaction_confidence': u'low',
        'data_interaction_reasons': [], 'crud_intents': [],
        'route_classification': u'', 'route_confidence': u'low', 'route_evidence': [],
        'destination_label': u'', 'destination_confidence': u'low',
        'destination_source': u'', 'destination_evidence': [],
        # Aura batch内の別actionが同じ生HTTP Packetを共有することをUIへ伝える。
        'representative_action_id': u'', 'representative_action_index': None,
        'representative_item': item, 'representative_packet_no': packet_no,
    }


def _set_route_metadata(operation, packet_context):
    operation['route_classification'] = packet_context.get('route_classification', u'')
    operation['route_confidence'] = packet_context.get('route_confidence', u'low')
    operation['route_evidence'] = list(packet_context.get('route_evidence', []))
    operation['destination_label'] = packet_context.get('destination_label', u'')
    operation['destination_confidence'] = packet_context.get('destination_confidence', u'low')
    operation['destination_source'] = packet_context.get('destination_source', u'')
    operation['destination_evidence'] = list(packet_context.get('destination_evidence', []))


def _merge_parameter(operation, record, packet_no):
    key = (record['path'], record['type'], record['region'], record['nesting'])
    current = operation['_parameters'].get(key)
    if current is None:
        current = dict(record)
        current['occurrences'] = 0
        current['_values'] = set()
        current['_packet_nos'] = set()
        operation['_parameters'][key] = current
    current['occurrences'] += 1
    current['_packet_nos'].add(packet_no)
    current['recovered'] = bool(current.get('recovered') or record.get('recovered'))
    value = _display(record.get('value'))
    if value and value != u'[redacted]':
        current['_values'].add(value)


def _merge_explicit_parameter(operation, path, value, packet_no, nesting=0):
    record = {'path': _schema_path(path), 'type': u'JSON', 'region': u'Body',
              'nesting': nesting, 'nesting_depth': nesting,
              'value': _redacted_value(path, u'Body', value), 'recovered': False}
    _merge_parameter(operation, record, packet_no)


def _merge_candidate(operation, path, candidate_type, value, packet_no, score, reason, source=u'Request'):
    if _secret_or_framework(path):
        return
    visible = _redacted_value(path, u'', value)
    if not visible or visible == u'[redacted]':
        return
    key = (_schema_path(path), candidate_type, source)
    current = operation['_resource_candidates'].get(key)
    if current is None:
        current = {'path': key[0], 'candidate_type': candidate_type,
                   'source': source, '_sample_values': set(), '_packet_nos': set(),
                   '_reasons': set(), '_seen': set(),
                   'score': int(score), 'occurrences': 0}
        operation['_resource_candidates'][key] = current
    seen_marker = (packet_no, visible)
    if seen_marker in current['_seen']:
        return
    current['_seen'].add(seen_marker)
    current['_sample_values'].add(visible)
    current['_packet_nos'].add(packet_no)
    current['_reasons'].add(_display(reason))
    current['score'] = max(current['score'], int(score))
    current['occurrences'] += 1


def _add_path_candidates(operation, raw_path, packet_no, resource_map=None, groups=None):
    for index, segment in enumerate((_display(raw_path) or u'').split(u'/')):
        if not segment:
            continue
        if _SF_ID_RE.match(segment):
            path = u'path.segment[%d]' % index
            hint = (u'Salesforce record identifier', 8,
                    u'path segment resembles a Salesforce 15/18-character ID')
            _merge_candidate(operation, path, hint[0], segment, packet_no, hint[1], hint[2])
            if resource_map is not None:
                _record_resource(resource_map, operation, path, segment, packet_no,
                                 groups or [], u'Request', hint)
        elif _UUID_RE.match(segment) or _LONG_HEX_RE.match(segment):
            path = u'path.segment[%d]' % index
            hint = (u'Record identifier', 6,
                    u'path segment resembles an opaque identifier')
            _merge_candidate(operation, path, hint[0], segment, packet_no, hint[1], hint[2])
            if resource_map is not None:
                _record_resource(resource_map, operation, path, segment, packet_no,
                                 groups or [], u'Request', hint)


def _operation_for_action(operations, action, action_index, packet_context,
                          resource_map=None, groups=None):
    descriptor = _display(action.get('descriptor')) if isinstance(action, dict) else u''
    calling = _display(action.get('callingDescriptor')) if isinstance(action, dict) else u''
    params = action.get('params') if isinstance(action, dict) else {}
    params = params if isinstance(params, dict) else {}
    _scheme, _controller, action_name = _descriptor_parts(descriptor)
    operation_name = action_name or descriptor or u'Aura endpoint'
    if u'ApexActionController/ACTION$execute' in descriptor:
        operation_name = _generic_apex_operation(params, operation_name)
    graphql_details = None
    if (u'executegraphql' in operation_name.lower() or
            u'executegraphql' in descriptor.lower() or u'queryinput' in [
                _display(key).lower() for key in params.keys()]):
        graphql_details = _graphql_details_from_params(params)
        if graphql_details and graphql_details.get('operation_name'):
            operation_name = operation_name + u' / ' + graphql_details.get('operation_name')
    origin, confidence, reason = _origin(descriptor, params)
    schema = sorted([_schema_path(path) for path, _value in _flatten_scalars(params, u'params')])
    key_parts = [u'Aura', packet_context['host'], packet_context['method'],
                 packet_context['normalized_path'], descriptor, calling,
                 operation_name, u'|'.join(schema),
                 graphql_details.get('query_fingerprint') if graphql_details else u'']
    operation_id = _operation_id(key_parts)
    operation = operations.get(operation_id)
    if operation is None:
        operation = _new_operation(
            operation_id, u'Aura', origin, confidence, reason,
            packet_context['host'], packet_context['method'], packet_context['normalized_path'],
            descriptor, calling, operation_name,
            _behavior(packet_context['method'], operation_name),
            packet_context['item'], packet_context['packet_no'])
        operation['representative_action_id'] = _display(action.get('id'))
        operation['representative_action_index'] = action_index
        operations[operation_id] = operation
    _set_route_metadata(operation, packet_context)
    if graphql_details:
        operation['graphql'] = graphql_details
        operation['behavior'] = _behavior(packet_context['method'], operation_name,
                                          graphql_details.get('kind'))
    interaction, interaction_confidence, interaction_reasons, crud_intents = _data_interaction(
        packet_context['method'], operation_name, packet_context['normalized_path'],
        params, graphql_details)
    operation['data_interaction'] = interaction
    operation['data_interaction_confidence'] = interaction_confidence
    operation['data_interaction_reasons'] = interaction_reasons
    operation['crud_intents'] = crud_intents
    operation['_salesforce_features'].update(_salesforce_features(
        operation_name, descriptor, packet_context['normalized_path'],
        packet_context.get('page_uri', u''), graphql_details))
    for path, value in _flatten_scalars(params, u'params'):
        _merge_explicit_parameter(operation, path, value, packet_context['packet_no'],
                                  max(0, path.count(u'.') + path.count(u'[]')))
        hint = _resource_hint(path, value)
        if hint:
            candidate_type, score, candidate_reason = hint
            _merge_candidate(operation, path, candidate_type, value,
                             packet_context['packet_no'], score, candidate_reason, u'Request')
            if resource_map is not None:
                _record_resource(resource_map, operation, path, value,
                                 packet_context['packet_no'], groups or [], u'Request', hint)
    return operation_id, operation


def _operation_for_non_aura(operations, packet_context, parsed_request,
                            request_content_type, response_content_type):
    protocol = _protocol_kind(
        parsed_request['path'], parsed_request['method'], request_content_type,
        response_content_type, parsed_request, False)
    operation_name = u''
    graphql_kind = u''
    graphql_details = None
    if protocol == u'GraphQL':
        operation_name, graphql_kind, _body_json = _graphql_metadata(parsed_request)
        graphql_details = _graphql_details_from_request(parsed_request)
        if graphql_details:
            operation_name = graphql_details.get('operation_name') or operation_name
            graphql_kind = graphql_details.get('kind') or graphql_kind
    if not operation_name:
        operation_name = parsed_request['method'] + u' ' + packet_context['normalized_path']
    operation_id = _operation_id([
        protocol, packet_context['host'], packet_context['method'],
        packet_context['normalized_path'], operation_name,
        graphql_details.get('query_fingerprint') if graphql_details else u'',
    ])
    operation = operations.get(operation_id)
    if operation is None:
        operation = _new_operation(
            operation_id, protocol, u'Unknown', u'low',
            u'non-Aura traffic has no Aura/Apex descriptor', packet_context['host'],
            packet_context['method'], packet_context['normalized_path'], u'', u'',
            operation_name, _behavior(packet_context['method'], operation_name, graphql_kind),
            packet_context['item'], packet_context['packet_no'])
        operations[operation_id] = operation
    _set_route_metadata(operation, packet_context)
    if graphql_details:
        operation['graphql'] = graphql_details
    interaction, interaction_confidence, interaction_reasons, crud_intents = _data_interaction(
        parsed_request['method'], operation_name, packet_context['normalized_path'],
        _safe_json(parsed_request.get('body')), graphql_details)
    operation['data_interaction'] = interaction
    operation['data_interaction_confidence'] = interaction_confidence
    operation['data_interaction_reasons'] = interaction_reasons
    operation['crud_intents'] = crud_intents
    operation['_salesforce_features'].update(_salesforce_features(
        operation_name, u'', packet_context['normalized_path'],
        packet_context.get('page_uri', u''), graphql_details))
    return operation_id, operation


def _add_non_aura_request_parameters(operation, parsed_request, packet_no,
                                     resource_map=None, groups=None):
    """検出器の成否に依存せず、通常HTTPのquery/form/JSONを最小限列挙する。"""
    scalar_rows = []
    for key, values in _parse_form(parsed_request.get('query')).items():
        for value in values:
            scalar_rows.append((u'query.' + _display(key), _display(value)))
    body = parsed_request.get('body') or u''
    body_json = _safe_json(body)
    if body_json is not None:
        scalar_rows.extend([(u'body.' + path, value)
                            for path, value in _flatten_scalars(body_json, u'')])
    else:
        for key, values in _parse_form(body).items():
            for value in values:
                scalar_rows.append((u'body.' + _display(key), _display(value)))
    for path, value in scalar_rows:
        nesting = max(0, path.count(u'.') + path.count(u'[]'))
        _merge_explicit_parameter(operation, path, value, packet_no, nesting)
        hint = _resource_hint(path, value)
        if hint:
            _merge_candidate(operation, path, hint[0], value, packet_no, hint[1], hint[2], u'Request')
            if resource_map is not None:
                _record_resource(resource_map, operation, path, value, packet_no,
                                 groups or [], u'Request', hint)


def _add_operation_occurrence(operation, packet_context, status, request_content_type,
                              response_content_type, groups, traffic_class):
    # Operation Catalogは同じ操作を複数Packetから集約する。最初に観測した
    # Packetがレスポンス未取得でも、後続にレスポンス付きPacketがあれば、画面の
    # Request / Response Viewerには同じ完全な一組を代表として表示させる。
    # これを行わないと、Requestだけ見えてResponseが空に見えることがある。
    if packet_context.get('has_response') and not operation.get('_representative_has_response'):
        operation['representative_item'] = packet_context.get('item')
        operation['representative_packet_no'] = packet_context.get('packet_no')
        operation['_representative_has_response'] = True
    operation['occurrences'] += 1
    operation['_packet_nos'].add(packet_context['packet_no'])
    if status is not None:
        operation['_status_codes'].add(int(status))
    if request_content_type:
        operation['_request_content_types'].add(request_content_type)
    if response_content_type:
        operation['_response_content_types'].add(response_content_type)
    operation['_observed_groups'].update(groups)
    if traffic_class:
        operation['_traffic_classes'].add(traffic_class)
    fingerprint = packet_context.get('session_fingerprint', u'')
    if fingerprint:
        current = operation['_session_contexts'].get(fingerprint)
        if current is None:
            current = {'session_fingerprint': fingerprint,
                       'auth_kind': packet_context.get('auth_kind', u'Unknown'),
                       '_groups': set(), '_packet_nos': set(), 'occurrences': 0}
            operation['_session_contexts'][fingerprint] = current
        current['_groups'].update(groups)
        current['_packet_nos'].add(packet_context['packet_no'])
        current['occurrences'] += 1
    operation['_app_ids'].update(packet_context.get('app_ids', []))
    endpoint = packet_context.get('aura_endpoint', u'')
    if endpoint:
        operation['_aura_endpoints'].add(endpoint)


def _parameter_action_index(path):
    match = _ACTION_INDEX_RE.search(_display(path))
    return int(match.group(1)) if match else None


def _relative_action_parameter_path(path):
    text = _display(path)
    match = _ACTION_INDEX_RE.search(text)
    if not match:
        return _schema_path(text)
    suffix = text[match.end():]
    return _schema_path(suffix.lstrip(u'.') or u'action')


def _encoded_json(value):
    current = _display(value).strip()
    for _depth in range(5):
        parsed = _safe_json(current)
        if isinstance(parsed, (dict, list)):
            return parsed
        decoded = _percent_decode(current, plus_as_space=True)
        if decoded == current:
            break
        current = decoded
    return None


def _aura_context_info(form, parsed_request):
    """Aura contextからapp/pageURIを受動抽出する。認証値は返さない。"""
    context_value = (form.get(u'aura.context') or [u''])[0]
    context = _encoded_json(context_value)
    context = context if isinstance(context, dict) else {}
    app_ids = set()
    for key in (u'app', u'application', u'appDescriptor', u'applicationDescriptor'):
        value = context.get(key)
        if value:
            app_ids.add(_display(value))
    # auraCmpDef/auraResources GETではJSON contextではなくqueryのaura.appに
    # アプリ識別子が載る。
    for key in (u'aura.app', u'aura.application', u'app'):
        for value in form.get(key, []):
            if value:
                app_ids.add(_display(value))
    loaded = context.get('loaded')
    if isinstance(loaded, dict):
        for raw_key in loaded.keys():
            key = _display(raw_key)
            if u'application@' in key.lower():
                app_ids.add(key)
    page_uri = (form.get(u'aura.pageURI') or form.get(u'aura.pageuri') or [u''])[0]
    if not page_uri:
        page_uri = context.get('pageURI') or context.get('pageUri') or u''
    page_uri = _display(page_uri)
    default_app = False
    default_reason = u'default application was not identifiable from passive Aura context'
    default_confidence = u'low'
    for app_id in app_ids:
        lowered = app_id.lower().replace(u' ', u'')
        if u'siteforce:communityapp' in lowered:
            default_app = True
            default_reason = u'Aura context identifies siteforce:communityApp'
            default_confidence = u'high'
            break
    # pageURIだけからdefault app利用を断定しない。候補根拠としてmedium以下にする。
    if not default_app and page_uri in (u'/', u'/s/', u'/s'):
        default_app = True
        default_reason = u'pageURI is the site root; default-app use is heuristic'
        default_confidence = u'low'
    return {
        'app_ids': sorted(app_ids), 'page_uri': page_uri,
        'is_default_app': default_app,
        'default_app_reason': default_reason,
        'default_app_confidence': default_confidence,
    }


def _session_for_request(parsed_request, host):
    headers = parsed_request['headers']
    authorization = _header_value(headers, u'authorization')
    cookie = _header_value(headers, u'cookie')
    auxiliary = []
    for name in (u'x-csrf-token', u'x-xsrf-token'):
        value = _header_value(headers, name)
        if value:
            auxiliary.append(name + u'=' + value)
    form = _parse_form(parsed_request.get('body'))
    aura_token = (form.get(u'aura.token') or [u''])[0]
    if aura_token.lower() not in (u'', u'undefined', u'null'):
        auxiliary.append(u'aura.token=' + aura_token)
    # Cookie/Authorization が得られる場合は、それだけを安定したセッション識別子にする。
    # CSRF/Aura token はリクエストごとに更新される実装があり、常に混ぜると同じ
    # ユーザーの通信を多数のセッションへ誤分割するため、主認証情報がない場合だけ使う。
    primary_material = []
    if authorization:
        primary_material.append(u'authorization=' + authorization)
    if cookie:
        primary_material.append(u'cookie=' + cookie)
    material = primary_material or auxiliary
    if authorization.lower().startswith(u'bearer '):
        auth_kind = u'Bearer'
    elif cookie:
        auth_kind = u'Cookie'
    elif material:
        auth_kind = u'Other'
    else:
        auth_kind = u'Guest'
        material.append(u'guest-host=' + (_display(host).lower() or u'unknown'))
    fingerprint = _sha256(u'\n'.join(material))
    return fingerprint, auth_kind


def _add_response_field(operation, path, value, packet_no):
    path = _schema_path(path)
    operation['_response_schema_paths'].add(path)
    current = operation['_response_fields'].get(path)
    if current is None:
        current = {'path': path, 'occurrences': 0, '_sample_values': set(),
                   '_packet_nos': set(), '_types': set(),
                   'sensitive': _secret_or_framework(path)}
        operation['_response_fields'][path] = current
    current['occurrences'] += 1
    current['_packet_nos'].add(packet_no)
    current['_types'].add(_json_type(value))
    visible = _redacted_value(path, u'Response', value)
    if visible and visible != u'[redacted]':
        current['_sample_values'].add(visible)


def _record_resource(resource_map, operation, path, value, packet_no, groups, source,
                     forced_hint=None):
    path = _schema_path(path)
    if _secret_or_framework(path):
        return None
    visible = _redacted_value(path, u'', value)
    if not visible or visible == u'[redacted]':
        return None
    hint = forced_hint or _resource_hint(path, visible)
    if hint is None:
        return None
    candidate_type, score, reason = hint
    resource_key = (visible, candidate_type)
    resource = resource_map.get(resource_key)
    if resource is None:
        resource = {'value': visible, 'candidate_type': candidate_type,
                    '_sources': set(), '_paths': set(), '_operation_ids': set(),
                    '_packet_nos': set(), '_groups': set(), 'occurrences': 0,
                    'score': int(score), '_reasons': set(), '_seen': set()}
        resource_map[resource_key] = resource
    seen_marker = (operation['operation_id'], path, packet_no, source)
    if seen_marker in resource['_seen']:
        return resource_key
    resource['_seen'].add(seen_marker)
    resource['_sources'].add(source)
    resource['_paths'].add(path)
    resource['_operation_ids'].add(operation['operation_id'])
    resource['_packet_nos'].add(packet_no)
    resource['_groups'].update(groups)
    resource['occurrences'] += 1
    resource['score'] = max(resource['score'], int(score))
    resource['_reasons'].add(_display(reason))
    if source == u'Response':
        operation['_response_resource_keys'].add(resource_key)
        _merge_candidate(operation, path, candidate_type, visible, packet_no, score, reason, u'Response')
    return resource_key


def _walk_response_value(value, prefix, operation, packet_no, groups, resource_map):
    if isinstance(value, dict):
        for raw_key in sorted(value.keys(), key=lambda item: _display(item).lower()):
            key = _display(raw_key)
            child_path = key if not prefix else prefix + u'.' + key
            _walk_response_value(value.get(raw_key), child_path, operation,
                                 packet_no, groups, resource_map)
    elif isinstance(value, list):
        child_path = prefix + u'[]'
        if not value:
            operation['_response_schema_paths'].add(_schema_path(child_path))
        for child in value:
            _walk_response_value(child, child_path, operation, packet_no, groups, resource_map)
    else:
        _add_response_field(operation, prefix or u'$', value, packet_no)
        _record_resource(resource_map, operation, prefix or u'$', value,
                         packet_no, groups, u'Response')


def _parse_aura_response(response_body, action_pairs, packet_no, groups,
                         resource_map, gaps):
    parsed = _safe_json(response_body)
    if not isinstance(parsed, dict):
        gaps.append({'packet_no': packet_no, 'stage': u'aura_response',
                     'reason': u'malformed Aura response JSON'})
        return
    response_actions = parsed.get('actions')
    if not isinstance(response_actions, list):
        gaps.append({'packet_no': packet_no, 'stage': u'aura_response',
                     'reason': u'Aura response does not contain actions[]'})
        return
    by_id = dict((action_id, operation) for action_id, operation in action_pairs if action_id)
    by_index = [operation for _action_id, operation in action_pairs]
    for index, response_action in enumerate(response_actions):
        if not isinstance(response_action, dict):
            gaps.append({'packet_no': packet_no, 'stage': u'aura_response',
                         'reason': u'Aura response action is not an object'})
            continue
        response_id = _display(response_action.get('id'))
        operation = by_id.get(response_id) if response_id else None
        if operation is None and not response_id and index < len(by_index):
            operation = by_index[index]
        if operation is None:
            gaps.append({'packet_no': packet_no, 'stage': u'aura_response',
                         'reason': u'Aura response action could not be matched to a request action'})
            continue
        for key in (u'state', u'returnValue', u'errors'):
            if key in response_action:
                _walk_response_value(response_action.get(key), key, operation,
                                     packet_no, groups, resource_map)


def _finalize_parameter(current):
    values = sorted(current.pop('_values'))
    packet_nos = sorted(current.pop('_packet_nos'))
    current['values'] = values
    current['packet_nos'] = packet_nos
    if values:
        current['value'] = values[0]
    elif current.get('value') != u'[redacted]':
        current['value'] = u''
    return current


def _finalize_candidate(current):
    current['sample_values'] = sorted(current.pop('_sample_values'))[:20]
    current['packet_nos'] = sorted(current.pop('_packet_nos'))
    current['reasons'] = sorted(current.pop('_reasons'))
    current.pop('_seen', None)
    return current


def _finalize_operation(operation, resources):
    operation['packet_nos'] = sorted(operation.pop('_packet_nos'))
    operation['status_codes'] = sorted(operation.pop('_status_codes'))
    operation['request_content_types'] = sorted(operation.pop('_request_content_types'))
    operation['response_content_types'] = sorted(operation.pop('_response_content_types'))
    operation['parameters'] = [_finalize_parameter(value) for value in operation.pop('_parameters').values()]
    candidate_by_path = {}
    for candidate in operation['_resource_candidates'].values():
        path = candidate.get('path', u'')
        current = candidate_by_path.get(path)
        if current is None or int(candidate.get('score', 0)) > int(current.get('score', 0)):
            candidate_by_path[path] = candidate
    for parameter in operation['parameters']:
        path = parameter.get('path', u'')
        candidate = candidate_by_path.get(path)
        if _secret_or_framework(path, parameter.get('region')):
            parameter['candidate_classification'] = u'Framework/session control'
            parameter['score'] = 0
            parameter['reasons'] = [u'excluded from authorization resource candidates']
        elif candidate is not None:
            parameter['candidate_classification'] = candidate.get('candidate_type', u'Resource candidate')
            parameter['score'] = int(candidate.get('score', 0))
            parameter['reasons'] = sorted(candidate.get('_reasons', set()))
        else:
            parameter['candidate_classification'] = u'Ordinary input'
            parameter['score'] = 0
            parameter['reasons'] = []
    operation['parameters'].sort(key=lambda row: (row['path'].lower(), row['type'].lower()))
    operation['resource_candidates'] = [_finalize_candidate(value) for value in operation.pop('_resource_candidates').values()]
    operation['resource_candidates'].sort(key=lambda row: (-row['score'], row['path'].lower()))
    operation['response_fields'] = []
    for field in operation.pop('_response_fields').values():
        field['sample_values'] = sorted(field.pop('_sample_values'))[:20]
        field['packet_nos'] = sorted(field.pop('_packet_nos'))
        field['types'] = sorted(field.pop('_types'))
        field['type'] = u' / '.join(field['types'])
        operation['response_fields'].append(field)
    operation['response_fields'].sort(key=lambda row: row['path'].lower())
    operation['response_schema_paths'] = sorted(operation.pop('_response_schema_paths'))
    keys = operation.pop('_response_resource_keys')
    operation['response_resource_candidates'] = [resources[key] for key in keys if key in resources]
    operation['observed_groups'] = sorted(operation.pop('_observed_groups'))
    operation['traffic_classes'] = sorted(operation.pop('_traffic_classes'))
    operation['session_contexts'] = []
    for context in operation.pop('_session_contexts').values():
        context['groups'] = sorted(context.pop('_groups'))
        context['packet_nos'] = sorted(context.pop('_packet_nos'))[:500]
        operation['session_contexts'].append(context)
    operation['session_contexts'].sort(key=lambda row: row['session_fingerprint'])
    operation['session_fingerprints'] = [
        row['session_fingerprint'] for row in operation['session_contexts']]
    operation['app_ids'] = sorted(operation.pop('_app_ids'))
    operation['aura_endpoints'] = sorted(operation.pop('_aura_endpoints'))
    operation['salesforce_features'] = sorted(operation.pop('_salesforce_features'))
    return operation


def _finalize_resource(resource):
    sources = resource.pop('_sources')
    resource['source'] = u'Both' if len(sources) > 1 else (next(iter(sources)) if sources else u'Request')
    resource['paths'] = sorted(resource.pop('_paths'))
    resource['operation_ids'] = sorted(resource.pop('_operation_ids'))
    resource['packet_nos'] = sorted(resource.pop('_packet_nos'))
    resource['groups'] = sorted(resource.pop('_groups'))
    resource['reasons'] = sorted(resource.pop('_reasons'))
    resource.pop('_seen', None)
    if resource.get('occurrences', 0) > 1:
        resource['score'] += 2
        resource['reasons'].append(u'value reappears in the selected History range')
    return resource


def _object_kind(name):
    lowered = (_display(name) or u'').lower()
    if lowered.endswith(u'__c'):
        return u'Custom Object'
    if lowered.endswith(u'__x'):
        return u'External Object'
    if lowered.endswith(u'__mdt'):
        return u'Custom Metadata Type'
    return u'Standard or unresolved'


def _field_kind(name):
    lowered = (_display(name) or u'').lower()
    if lowered.endswith(u'__c'):
        return u'Custom Field'
    if lowered.endswith(u'__r'):
        return u'Custom Relationship'
    return u'Standard or unresolved'


def _valid_api_name(value):
    return bool(re.match(r'^[A-Za-z][A-Za-z0-9_]{1,127}$', _display(value)))


def _operation_object_evidence(operation):
    evidence = {}
    graphql = operation.get('graphql') or {}
    for name in graphql.get('objects', []):
        evidence.setdefault(_display(name), set()).add(u'GraphQL UI API structure')
    path = operation.get('path', u'')
    match = re.search(r'/sobjects/([^/?]+)', path, re.I)
    if match:
        evidence.setdefault(_percent_decode(match.group(1), False), set()).add(u'REST sobjects path')
    match = re.search(r'/object-info/([^/?]+)', path, re.I)
    if match:
        evidence.setdefault(_percent_decode(match.group(1), False), set()).add(u'UI API object-info path')
    for parameter in operation.get('parameters', []):
        leaf = re.split(r'[.\[\]/]', parameter.get('path', u''))[-1]
        compact = leaf.lower().replace(u'_', u'')
        if compact not in _OBJECT_PARAMETER_NAMES:
            continue
        for value in parameter.get('values', []):
            if value != u'[redacted]' and _valid_api_name(value):
                evidence.setdefault(_display(value), set()).add(
                    u'object API name parameter ' + _display(parameter.get('path')))
    return evidence


def _build_object_field_catalog(operations):
    objects = {}
    fields = {}
    for operation in operations:
        object_evidence = _operation_object_evidence(operation)
        known_objects = sorted(object_evidence.keys())
        auth_kinds = set(context.get('auth_kind', u'Unknown')
                         for context in operation.get('session_contexts', []))
        for object_name, reasons in object_evidence.items():
            current = objects.get(object_name)
            if current is None:
                current = {
                    'object_name': object_name, 'object_kind': _object_kind(object_name),
                    '_crud_intents': set(), '_operation_ids': set(), '_fields': set(),
                    '_packet_nos': set(), '_groups': set(), '_auth_kinds': set(),
                    '_reasons': set(), '_data_interactions': set(),
                }
                objects[object_name] = current
            current['_crud_intents'].update(operation.get('crud_intents', []))
            current['_operation_ids'].add(operation.get('operation_id'))
            current['_packet_nos'].update(operation.get('packet_nos', []))
            current['_groups'].update(operation.get('observed_groups', []))
            current['_auth_kinds'].update(auth_kinds)
            current['_reasons'].update(reasons)
            current['_data_interactions'].add(operation.get('data_interaction', u'Unknown'))
        graphql = operation.get('graphql') or {}
        graphql_object_fields = graphql.get('object_fields', {})
        field_sources = []
        for object_name, names in graphql_object_fields.items():
            for name in names:
                field_sources.append((object_name, name, u'GraphQL selection'))
        # GraphQLでobjectが1つに解決できた場合だけ、選択fieldをそのobjectへ結び付ける。
        if len(known_objects) == 1:
            object_name = known_objects[0]
            for name in graphql.get('fields', []):
                field_sources.append((object_name, name, u'GraphQL selection'))
        # request/responseのfieldはobjectが一意な場合だけ帰属させる。推測による誤結合を避ける。
        if len(known_objects) == 1:
            object_name = known_objects[0]
            for parameter in operation.get('parameters', []):
                leaf = re.split(r'[.\[\]/]', parameter.get('path', u''))[-1]
                compact_leaf = leaf.lower().replace(u'_', u'')
                if (_valid_api_name(leaf) and compact_leaf not in _OBJECT_PARAMETER_NAMES and
                        leaf.lower() not in _GRAPHQL_SCAFFOLD_FIELDS and
                        not _secret_or_framework(leaf, parameter.get('region'))):
                    field_sources.append((object_name, leaf, u'Request parameter'))
            for response_field in operation.get('response_fields', []):
                leaf = re.split(r'[.\[\]/]', response_field.get('path', u''))[-1]
                if _valid_api_name(leaf) and not _secret_or_framework(leaf, u'Response'):
                    field_sources.append((object_name, leaf, u'Response field'))
        for object_name, field_name, source in field_sources:
            if not field_name or field_name.lower() in _GRAPHQL_SCAFFOLD_FIELDS:
                continue
            key = (object_name, field_name)
            current = fields.get(key)
            if current is None:
                hint = _resource_hint(field_name, u'')
                current = {
                    'object_name': object_name, 'field_name': field_name,
                    'field_kind': _field_kind(field_name),
                    'focus_type': hint[0] if hint else u'',
                    '_sources': set(), '_operation_ids': set(), '_packet_nos': set(),
                    '_groups': set(), '_auth_kinds': set(), '_crud_intents': set(),
                    '_reasons': set(),
                }
                fields[key] = current
            current['_sources'].add(source)
            current['_operation_ids'].add(operation.get('operation_id'))
            current['_packet_nos'].update(operation.get('packet_nos', []))
            current['_groups'].update(operation.get('observed_groups', []))
            current['_auth_kinds'].update(auth_kinds)
            current['_crud_intents'].update(operation.get('crud_intents', []))
            current['_reasons'].add(source + u' observed for ' + object_name)
            if object_name in objects:
                objects[object_name]['_fields'].add(field_name)
    object_rows = []
    for row in objects.values():
        row['crud_intents'] = sorted(row.pop('_crud_intents'))
        row['operation_ids'] = sorted(row.pop('_operation_ids'))
        row['fields'] = sorted(row.pop('_fields'))
        row['packet_nos'] = sorted(row.pop('_packet_nos'))[:500]
        row['groups'] = sorted(row.pop('_groups'))
        row['auth_kinds'] = sorted(row.pop('_auth_kinds'))
        row['reasons'] = sorted(row.pop('_reasons'))
        row['data_interactions'] = sorted(row.pop('_data_interactions'))
        row['confidence'] = u'high' if any(
            reason in (u'GraphQL UI API structure', u'REST sobjects path', u'UI API object-info path')
            for reason in row['reasons']) else u'medium'
        object_rows.append(row)
    field_rows = []
    for row in fields.values():
        row['sources'] = sorted(row.pop('_sources'))
        row['operation_ids'] = sorted(row.pop('_operation_ids'))
        row['packet_nos'] = sorted(row.pop('_packet_nos'))[:500]
        row['groups'] = sorted(row.pop('_groups'))
        row['auth_kinds'] = sorted(row.pop('_auth_kinds'))
        row['crud_intents'] = sorted(row.pop('_crud_intents'))
        row['reasons'] = sorted(row.pop('_reasons'))
        row['confidence'] = u'high' if u'GraphQL selection' in row['sources'] else u'medium'
        field_rows.append(row)
    object_rows.sort(key=lambda row: row['object_name'].lower())
    field_rows.sort(key=lambda row: (row['object_name'].lower(), row['field_name'].lower()))
    return {'objects': object_rows, 'fields': field_rows}


def _build_access_matrix(operations):
    """観測済み組合せだけを返す疎行列。未観測をDeniedとは解釈しない。"""
    rows = []
    for operation in operations:
        for context in operation.get('session_contexts', []):
            rows.append({
                'operation_id': operation.get('operation_id'),
                'operation': operation.get('operation_name'),
                'origin': operation.get('origin'),
                'data_interaction': operation.get('data_interaction'),
                'session_fingerprint': context.get('session_fingerprint'),
                'auth_kind': context.get('auth_kind'),
                'groups': list(context.get('groups', [])),
                'packet_nos': list(context.get('packet_nos', []))[:500],
                'occurrences': context.get('occurrences', 0),
                'observed': True,
                'evidence': u'Observed in HTTP History; this is not an Allow/Deny authorization verdict',
            })
    rows.sort(key=lambda row: (row['operation'].lower(), row['auth_kind'],
                               row['session_fingerprint']))
    return rows


def _build_app_endpoint_catalog(packets, operations=None):
    operation_by_id = dict((row.get('operation_id'), row) for row in (operations or []))
    catalog = {}
    for packet in packets:
        endpoint = packet.get('aura_endpoint', u'')
        if not endpoint:
            continue
        app_ids = packet.get('app_ids') or [u'(not observed)']
        for app_id in app_ids:
            key = (packet.get('host', u''), _display(app_id), endpoint)
            current = catalog.get(key)
            if current is None:
                current = {
                    'host': key[0], 'app_id': key[1], 'aura_endpoint': key[2],
                    'is_default_app': False, 'default_app_confidence': u'low',
                    '_default_reasons': set(), '_packet_nos': set(),
                    '_session_fingerprints': set(), '_groups': set(),
                    '_operation_ids': set(), '_features': set(),
                }
                catalog[key] = current
            current['is_default_app'] = bool(current['is_default_app'] or packet.get('is_default_app'))
            if packet.get('is_default_app'):
                current['default_app_confidence'] = packet.get('default_app_confidence', u'low')
            current['_default_reasons'].add(packet.get('default_app_reason', u''))
            current['_packet_nos'].add(packet.get('packet_no'))
            current['_session_fingerprints'].add(packet.get('session_fingerprint'))
            current['_groups'].update(packet.get('groups', []))
            current['_operation_ids'].update(packet.get('operation_ids', []))
            for operation_id in packet.get('operation_ids', []):
                operation = operation_by_id.get(operation_id) or {}
                current['_features'].update(operation.get('salesforce_features', []))
    rows = []
    for current in catalog.values():
        current['default_app_reasons'] = sorted(
            reason for reason in current.pop('_default_reasons') if reason)
        current['packet_nos'] = sorted(current.pop('_packet_nos'))[:500]
        current['session_fingerprints'] = sorted(current.pop('_session_fingerprints'))
        current['groups'] = sorted(current.pop('_groups'))
        current['operation_ids'] = sorted(current.pop('_operation_ids'))
        current['features'] = sorted(current.pop('_features'))
        rows.append(current)
    rows.sort(key=lambda row: (row['host'].lower(), row['app_id'].lower(), row['aura_endpoint']))
    return rows


def _build_endpoint_catalog(packets, operations=None):
    """Aura限定ではない全HTTP endpoint inventory。1 packetでも到達を追跡できる。"""
    operation_by_id = dict((row.get('operation_id'), row) for row in (operations or []))
    catalog = {}
    for packet in packets:
        key = (packet.get('host', u''), packet.get('method', u''),
               packet.get('normalized_path') or packet.get('path', u''),
               packet.get('protocol_kind', u''), packet.get('route_classification', u''),
               packet.get('destination_label', u''))
        current = catalog.get(key)
        if current is None:
            current = {
                'host': key[0], 'method': key[1], 'path': key[2], 'protocol_kind': key[3],
                'route_classification': key[4],
                'route_confidence': packet.get('route_confidence', u'low'),
                'route_evidence': list(packet.get('route_evidence', [])),
                'destination_label': key[5],
                'destination_confidence': packet.get('destination_confidence', u'low'),
                'destination_source': packet.get('destination_source', u''),
                'destination_evidence': list(packet.get('destination_evidence', [])),
                '_request_content_types': set(), '_response_content_types': set(),
                '_status_codes': set(), '_session_fingerprints': set(), '_groups': set(),
                '_packet_nos': set(), '_operation_ids': set(), '_parameters': set(),
                '_data_interactions': set(), 'occurrences': 0,
            }
            catalog[key] = current
        current['occurrences'] += 1
        if packet.get('request_content_type'):
            current['_request_content_types'].add(packet.get('request_content_type'))
        if packet.get('response_content_type'):
            current['_response_content_types'].add(packet.get('response_content_type'))
        if packet.get('status') is not None:
            current['_status_codes'].add(packet.get('status'))
        if packet.get('session_fingerprint'):
            current['_session_fingerprints'].add(packet.get('session_fingerprint'))
        current['_groups'].update(packet.get('groups', []))
        current['_packet_nos'].add(packet.get('packet_no'))
        for operation_id in packet.get('operation_ids', []):
            current['_operation_ids'].add(operation_id)
            operation = operation_by_id.get(operation_id) or {}
            current['_data_interactions'].add(operation.get('data_interaction', u'Unknown'))
            for parameter in operation.get('parameters', []):
                current['_parameters'].add(parameter.get('path', u''))
    rows = []
    for current in catalog.values():
        current['request_content_types'] = sorted(current.pop('_request_content_types'))
        current['response_content_types'] = sorted(current.pop('_response_content_types'))
        current['status_codes'] = sorted(current.pop('_status_codes'))
        current['session_fingerprints'] = sorted(current.pop('_session_fingerprints'))
        current['groups'] = sorted(current.pop('_groups'))
        current['packet_nos'] = sorted(current.pop('_packet_nos'))[:500]
        current['operation_ids'] = sorted(current.pop('_operation_ids'))
        current['parameters'] = sorted(value for value in current.pop('_parameters') if value)[:500]
        current['data_interactions'] = sorted(current.pop('_data_interactions'))
        rows.append(current)
    rows.sort(key=lambda row: (row['host'].lower(), row['path'], row['method'], row['protocol_kind']))
    return rows


def _build_packet_catalog(packets):
    """解析対象packetごとのOperation到達状況。未到達はTechnical Gapへも記録する。"""
    rows = []
    for packet in packets:
        rows.append({
            'packet_no': packet.get('packet_no'), 'host': packet.get('host', u''),
            'method': packet.get('method', u''), 'path': packet.get('normalized_path') or packet.get('path', u''),
            'protocol_kind': packet.get('protocol_kind', u''),
            'route_classification': packet.get('route_classification', u''),
            'destination_label': packet.get('destination_label', u''),
            'status': packet.get('status'), 'groups': list(packet.get('groups', [])),
            'operation_ids': list(packet.get('operation_ids', [])),
            'operation_count': len(packet.get('operation_ids', [])),
            'deduplication': list(packet.get('deduplication', [])),
        })
    return rows


def _annotate_exact_duplicates(packets, operations):
    """Operation内の完全一致候補を、代表Packetと重複Packetとして可視化する。

    session fingerprintと業務パラメータを含む保守的なsignatureを使う。別ユーザー、
    別レコード、異なる更新値は別variantのままであり、自動的に省略しない。
    """
    operation_map = dict((operation.get('operation_id'), operation) for operation in operations)
    buckets = {}
    for packet in packets:
        signature = packet.get('_dedup_signature', u'')
        for operation_id in packet.get('operation_ids', []):
            key = (operation_id, packet.get('session_fingerprint', u''), signature)
            buckets.setdefault(key, []).append(packet)

    details_by_packet = dict((packet.get('packet_no'), []) for packet in packets)
    variants_by_operation = {}
    groups_by_operation = {}
    duplicate_count = 0
    for (operation_id, _session, _signature), members in buckets.items():
        variants_by_operation.setdefault(operation_id, 0)
        variants_by_operation[operation_id] += 1
        if len(members) < 2:
            continue
        # Responseを持つ最初のPacketを優先し、代表Request/Responseの確認も可能にする。
        representative = next((packet for packet in members if packet.get('status') is not None), members[0])
        representative_no = representative.get('packet_no')
        member_nos = sorted(packet.get('packet_no') for packet in members)
        duplicate_nos = [number for number in member_nos if number != representative_no]
        if not duplicate_nos:
            continue
        duplicate_count += len(duplicate_nos)
        group = {'representative_packet_no': representative_no,
                 'duplicate_packet_nos': duplicate_nos,
                 'reason': u'same operation, subject, and request values (Aura framework context/token excluded)'}
        groups_by_operation.setdefault(operation_id, []).append(group)
        details_by_packet.setdefault(representative_no, []).append({
            'status': u'Representative', 'representative_packet_no': representative_no,
            'duplicate_packet_nos': duplicate_nos, 'operation_id': operation_id,
            'reason': group['reason']})
        for duplicate_no in duplicate_nos:
            details_by_packet.setdefault(duplicate_no, []).append({
                'status': u'Exact duplicate', 'representative_packet_no': representative_no,
                'duplicate_packet_nos': [], 'operation_id': operation_id,
                'reason': group['reason']})

    for operation in operations:
        operation_id = operation.get('operation_id')
        groups = groups_by_operation.get(operation_id, [])
        operation['deduplication_groups'] = groups
        operation['test_variants'] = variants_by_operation.get(operation_id, 0)
        operation['exact_duplicate_packet_nos'] = sorted(set(
            number for group in groups for number in group['duplicate_packet_nos']))
        operation['exact_duplicate_packet_count'] = len(operation['exact_duplicate_packet_nos'])
    for packet in packets:
        packet['deduplication'] = details_by_packet.get(packet.get('packet_no'), [])
        packet.pop('_dedup_signature', None)
    return duplicate_count


def _build_salesforce_feature_catalog(operations):
    catalog = {}
    for operation in operations:
        for feature in operation.get('salesforce_features', []):
            current = catalog.get(feature)
            if current is None:
                current = {'feature': feature, '_operation_ids': set(),
                           '_packet_nos': set(), 'occurrences': 0}
                catalog[feature] = current
            current['_operation_ids'].add(operation.get('operation_id'))
            current['_packet_nos'].update(operation.get('packet_nos', []))
            current['occurrences'] += operation.get('occurrences', 0)
    rows = []
    for current in catalog.values():
        current['operation_ids'] = sorted(current.pop('_operation_ids'))
        current['packet_nos'] = sorted(current.pop('_packet_nos'))[:500]
        rows.append(current)
    rows.sort(key=lambda row: row['feature'].lower())
    return rows


def _planning_gap(gap_id, category, severity, reason, recommendation,
                  scope=u'Global', operation_id=u'', evidence=None):
    return {
        'gap_id': gap_id, 'category': category, 'severity': severity,
        'scope': scope, 'operation_id': operation_id,
        'reason': reason, 'recommendation': recommendation,
        'evidence': list(evidence or []),
    }


def _build_planning_gaps(operations, sessions, packets, app_catalog):
    gaps = []
    guest_sessions = [row for row in sessions if row.get('auth_kind') == u'Guest']
    authenticated = [row for row in sessions if row.get('auth_kind') != u'Guest']
    if not guest_sessions:
        gaps.append(_planning_gap(
            u'subject-guest-not-observed', u'Subject coverage', u'High',
            u'Guest context was not observed in the selected History range',
            u'Capture intended public/Guest flows; not observed does not mean denied'))
    if not authenticated:
        gaps.append(_planning_gap(
            u'subject-authenticated-not-observed', u'Subject coverage', u'High',
            u'Authenticated context was not observed in the selected History range',
            u'Capture at least one authenticated low-privilege subject'))
    labeled_authenticated = {}
    for session in authenticated:
        for group in session.get('observed_groups', []):
            labeled_authenticated.setdefault(group, set()).add(session.get('fingerprint'))
    labeled_fingerprints = set(
        fingerprint for values in labeled_authenticated.values() for fingerprint in values)
    if len(labeled_authenticated) < 2 or len(labeled_fingerprints) < 2:
        gaps.append(_planning_gap(
            u'subject-fewer-than-two-labeled-groups', u'Subject labeling', u'High',
            u'Fewer than two distinctly labeled authenticated subjects were observed',
            u'Assign distinct group labels to captured test subjects; labels identify subjects but do not prove role/account equivalence',
            evidence=sorted(labeled_authenticated.keys())))
    gaps.append(_planning_gap(
        u'subject-relation-not-defined', u'Subject relationship', u'High',
        u'Role, account, contact, tenant, and ownership relationships cannot be inferred from group labels or HTTP History',
        u'Define the verified relationship between each labeled subject and test resource before replay testing',
        evidence=sorted(labeled_authenticated.keys())))
    aura_packets = [packet for packet in packets if packet.get('aura_endpoint')]
    if aura_packets:
        observed_apps = set(app_id for packet in aura_packets for app_id in packet.get('app_ids', []))
        if not observed_apps:
            gaps.append(_planning_gap(
                u'app-id-not-observed', u'Application coverage', u'Medium',
                u'Aura traffic was observed, but no application descriptor was extracted',
                u'Capture application bootstrap/context traffic for each Experience Cloud app'))
        if len(observed_apps) < 2:
            gaps.append(_planning_gap(
                u'multiple-app-coverage-not-demonstrated', u'Application coverage', u'Medium',
                u'Coverage of multiple Experience Cloud applications was not demonstrated',
                u'Confirm whether multiple apps/endpoints exist and capture each applicable app'))
        if not any(row.get('is_default_app') for row in app_catalog):
            gaps.append(_planning_gap(
                u'default-app-not-identified', u'Application coverage', u'Medium',
                u'The default Experience Cloud application was not identified from passive evidence',
                u'Capture the site-root/default-app flow; path-based inference is not treated as proof'))
    write_operations = [row for row in operations if row.get('behavior') == u'Write' or
                        row.get('data_interaction') in (
                            u'Record Create', u'Record Update', u'Record Delete')]
    if not write_operations:
        gaps.append(_planning_gap(
            u'write-operation-not-observed', u'Operation coverage', u'Medium',
            u'No write-like operation was observed in the selected History range',
            u'Capture authorized create/update/delete workflows using dedicated test data'))
    graphql_queries = [row for row in operations if (row.get('graphql') or {}).get('kind') == u'query']
    graphql_mutations = [row for row in operations if (row.get('graphql') or {}).get('kind') == u'mutation']
    if graphql_queries and not graphql_mutations:
        gaps.append(_planning_gap(
            u'graphql-mutation-not-observed', u'GraphQL coverage', u'Medium',
            u'GraphQL query traffic was observed, but no GraphQL mutation was observed',
            u'Confirm whether mutation capability is in scope and capture an authorized mutation workflow'))
    for operation in operations:
        operation_id = operation.get('operation_id', u'')
        if operation.get('origin') == u'Unknown' and operation.get('protocol_kind') == u'Aura':
            entry = _planning_gap(
                u'unknown-descriptor-' + operation_id, u'Descriptor coverage', u'Medium',
                u'Aura origin/descriptor could not be classified for ' + operation.get('operation_name', u''),
                u'Review the representative packet and recover descriptor/class/namespace metadata',
                scope=u'Operation', operation_id=operation_id,
                evidence=operation.get('packet_nos', []))
            entry['operation'] = operation.get('operation_name', u'')
            gaps.append(entry)
        if operation.get('data_interaction') == u'Unknown':
            entry = _planning_gap(
                u'unknown-interaction-' + operation_id, u'Data interaction', u'Medium',
                u'Data interaction remains Unknown for ' + operation.get('operation_name', u''),
                u'Review request parameters and response fields, then classify the operation intent',
                scope=u'Operation', operation_id=operation_id,
                evidence=operation.get('packet_nos', []))
            entry['operation'] = operation.get('operation_name', u'')
            gaps.append(entry)
        if len(operation.get('session_contexts', [])) < 2:
            entry = _planning_gap(
                u'single-context-' + operation_id, u'Subject-operation coverage', u'High',
                u'Operation was observed in fewer than two session contexts: ' + operation.get('operation_name', u''),
                u'Capture the operation under the intended comparison subjects; unobserved is not denied',
                scope=u'Operation', operation_id=operation_id,
                evidence=operation.get('packet_nos', []))
            entry['operation'] = operation.get('operation_name', u'')
            gaps.append(entry)
    gaps.append(_planning_gap(
        u'policy-ownership-relation-not-defined', u'Expected policy', u'High',
        u'Expected Allow/Deny policy and subject-to-resource ownership relation are not defined by HTTP History',
        u'Define the expected policy matrix and ownership/account/tenant relation before active authorization testing'))
    severity_order = {u'High': 0, u'Medium': 1, u'Low': 2}
    gaps.sort(key=lambda row: (severity_order.get(row['severity'], 9), row['category'], row['gap_id']))
    return gaps


def _priority(score):
    if score >= 12:
        return u'P0'
    if score >= 9:
        return u'P1'
    if score >= 6:
        return u'P2'
    return u'P3'


def _recommended_tests(operation, candidate):
    tests = [u'same-role cross-user substitution/replay',
             u'nonexistent-value negative control']
    if candidate.get('candidate_type') in (u'Ownership / subject', u'Tenant / organization',
                                            u'Record / subject identifier', u'Record identifier',
                                            u'Salesforce record identifier'):
        tests.append(u'cross-owner and cross-tenant boundary review')
    if candidate.get('candidate_type') in (u'Object / field selector', u'PII field', u'Money',
                                            u'Authorization / role', u'Workflow / status'):
        tests.append(u'property-level authorization review')
    tests.append(u'guest replay only when the endpoint is intended to support guests')
    if operation.get('behavior') == u'Write':
        tests.append(u'verify server-side ownership and state-transition checks')
    return tests


def _build_plan_rows(operations):
    rows = []
    for operation in operations:
        candidates = list(operation.get('resource_candidates', []))
        if not candidates:
            interaction = operation.get('data_interaction', u'Unknown')
            base_scores = {
                u'Record Create': 9, u'Record Update': 9, u'Record Delete': 10,
                u'Record List/Search': 7, u'Record Read': 6,
                u'Authentication/Self-registration': 8,
                u'Navigation/Admin Surface': 7, u'Metadata/Schema': 6,
                u'UI Definition': 5, u'Unknown': 3,
            }
            score = base_scores.get(interaction, 3)
            reasons = list(operation.get('data_interaction_reasons', []))
            reasons.append(u'operation-level planning row; no concrete resource candidate was observed')
            candidate = {
                'path': u'(operation-level)', 'candidate_type': interaction,
                'source': u'Operation', 'sample_values': [],
                'packet_nos': list(operation.get('packet_nos', [])),
                'reasons': reasons, 'score': score, 'occurrences': 1,
            }
            candidates.append(candidate)
        for candidate in candidates:
            score = int(candidate.get('score', 0))
            reasons = list(candidate.get('reasons', []))
            if operation.get('behavior') == u'Write':
                score += 3
                reasons.append(u'write-like operation may have higher authorization impact')
            elif operation.get('behavior') == u'Read':
                score += 2
                reasons.append(u'read-like operation is suitable for cross-subject visibility checks')
            if candidate.get('source') in (u'Response', u'Both'):
                score += 2
                reasons.append(u'response exposure confirms this field/value is observable in captured traffic')
            if operation.get('occurrences', 0) > 1:
                score += 1
                reasons.append(u'operation recurs in the selected History range')
            if candidate.get('occurrences', 0) > 1:
                score += 1
                reasons.append(u'candidate value/path reappears in the selected History range')
            rows.append({
                'priority': _priority(score), 'score': score,
                'operation_id': operation['operation_id'], 'origin': operation['origin'],
                'operation': operation['operation_name'],
                'data_interaction': operation.get('data_interaction', u'Unknown'),
                'candidate_path': candidate['path'],
                'candidate_type': candidate['candidate_type'],
                'sample_values': list(candidate.get('sample_values', [])),
                'packet_nos': list(candidate.get('packet_nos', [])),
                'reasons': sorted(set(reasons)),
                'recommended_tests': _recommended_tests(operation, candidate),
            })
    rows.sort(key=lambda row: (row['priority'], -row['score'], row['operation_id'], row['candidate_path']))
    return rows


def analyze_history(callbacks, helpers, start_packet_no=None, end_packet_no=None,
                    cancel_check=None, detector=None, progress_fn=None,
                    scope_only=False, destination_rules=None):
    """指定した1-based inclusive範囲（Noneなら全件）を受動解析する。

    ``scope_only=True``ではTarget scope内のURLだけを解析する。1件の解析失敗は
    ``gaps``へ記録して続行する。``progress_fn(considered, range_total)``は数値範囲を
    どこまで走査したかを示し、``summary.packets_analyzed``は実解析件数を示す。
    """
    try:
        history = list(callbacks.getProxyHistory())
    except Exception as exc:
        history = []
        initial_gap = {'packet_no': 0, 'stage': u'history',
                       'reason': u'could not read Proxy History: ' + _exception_text(exc)}
    else:
        initial_gap = None

    start = 1 if start_packet_no is None else max(1, int(start_packet_no))
    end = len(history) if end_packet_no is None else min(len(history), int(end_packet_no))
    selected_total = max(0, end - start + 1)
    gaps = [initial_gap] if initial_gap else []
    if isinstance(destination_rules, (str, type(u''))):
        destination_rules, rule_errors = parse_destination_rules(destination_rules)
        for error in rule_errors:
            gaps.append({'packet_no': 0, 'stage': u'destination_rule', 'reason': error})
    else:
        destination_rules = list(destination_rules or [])
    packets = []
    operations = {}
    sessions = {}
    resource_map = {}
    processed = 0
    considered = 0
    excluded_out_of_scope = 0
    scope_lookup_failures = 0
    packets_with_response = 0
    aura_actions = 0
    cancelled = False
    traffic_counts = {}

    for packet_no, item in enumerate(history, 1):
        if packet_no < start:
            continue
        if packet_no > end:
            break
        try:
            if cancel_check and cancel_check():
                cancelled = True
                break
        except Exception as exc:
            gaps.append({'packet_no': packet_no, 'stage': u'cancel_check',
                         'reason': u'cancel check failed: ' + _exception_text(exc)})

        considered += 1
        try:
            request_bytes = item.getRequest()
        except Exception as exc:
            request_bytes = None
            gaps.append({'packet_no': packet_no, 'stage': u'request',
                         'reason': u'getRequest failed: ' + _exception_text(exc)})
        if scope_only:
            if request_bytes is None:
                scope_lookup_failures += 1
                gaps.append({'packet_no': packet_no, 'stage': u'scope',
                             'reason': u'scope filtering skipped packet because request/URL was unavailable'})
                try:
                    if progress_fn:
                        progress_fn(considered, selected_total)
                except Exception as exc:
                    gaps.append({'packet_no': packet_no, 'stage': u'progress',
                                 'reason': u'progress callback failed: ' + _exception_text(exc)})
                continue
            try:
                request_url = _history_item_url(helpers, item, request_bytes)
                in_scope = bool(callbacks.isInScope(request_url))
            except Exception as exc:
                scope_lookup_failures += 1
                gaps.append({'packet_no': packet_no, 'stage': u'scope',
                             'reason': u'scope filtering skipped packet: ' + _exception_text(exc)})
                try:
                    if progress_fn:
                        progress_fn(considered, selected_total)
                except Exception as progress_exc:
                    gaps.append({'packet_no': packet_no, 'stage': u'progress',
                                 'reason': u'progress callback failed: ' + _exception_text(progress_exc)})
                continue
            if not in_scope:
                excluded_out_of_scope += 1
                try:
                    if progress_fn:
                        progress_fn(considered, selected_total)
                except Exception as exc:
                    gaps.append({'packet_no': packet_no, 'stage': u'progress',
                                 'reason': u'progress callback failed: ' + _exception_text(exc)})
                continue
        processed += 1
        try:
            response_bytes = item.getResponse()
        except Exception as exc:
            response_bytes = None
            gaps.append({'packet_no': packet_no, 'stage': u'response',
                         'reason': u'getResponse failed: ' + _exception_text(exc)})

        request_text = _http_text(helpers, request_bytes)
        response_text = _http_text(helpers, response_bytes)
        parsed_request = _parse_request(request_text)
        parsed_response = _parse_response(response_text) if response_bytes is not None else {
            'status': None, 'body': u'', 'headers': {}, 'header_rows': []}
        if response_bytes is None:
            gaps.append({'packet_no': packet_no, 'stage': u'response',
                         'reason': u'missing response'})
        else:
            packets_with_response += 1

        request_content_type = _content_type(parsed_request['headers'])
        response_content_type = _content_type(parsed_response['headers'])
        host = _header_value(parsed_request['headers'], u'host') or _service_host(item)
        host = _display(host)
        normalized_path = _normalized_path(parsed_request['path'])
        try:
            comment = _display(item.getComment()) if hasattr(item, 'getComment') else u''
        except Exception as exc:
            comment = u''
            gaps.append({'packet_no': packet_no, 'stage': u'comment',
                         'reason': u'comment read failed: ' + _exception_text(exc)})
        try:
            groups = [_display(group) for group in statistics_engine.group_names(comment)]
        except Exception as exc:
            groups = []
            gaps.append({'packet_no': packet_no, 'stage': u'comment',
                         'reason': u'group parsing failed: ' + _exception_text(exc)})
        try:
            highlight = _display(item.getHighlight()) if hasattr(item, 'getHighlight') else u''
        except Exception:
            highlight = u''
        try:
            traffic_class = _display(statistics_engine.classify_packet(
                parsed_request['path'], parsed_request['body'], response_text,
                response_content_type))
        except Exception as exc:
            traffic_class = u''
            gaps.append({'packet_no': packet_no, 'stage': u'traffic_class',
                         'reason': u'traffic classification failed: ' + _exception_text(exc)})
        if traffic_class:
            traffic_counts[traffic_class] = traffic_counts.get(traffic_class, 0) + 1

        fingerprint, auth_kind = _session_for_request(parsed_request, host)
        session = sessions.get(fingerprint)
        if session is None:
            session = {'fingerprint': fingerprint, 'auth_kind': auth_kind,
                       '_packet_nos': set(), '_hosts': set(), '_observed_groups': set()}
            sessions[fingerprint] = session
        session['_packet_nos'].add(packet_no)
        if host:
            session['_hosts'].add(host)
        session['_observed_groups'].update(groups)

        # Aura action POSTだけでなく、auraCmpDef/auraResourcesのGET queryも
        # 同じ文脈として扱う。
        form = _merge_request_values(parsed_request)
        aura_context = _aura_context_info(form, parsed_request)
        operation_path = _aura_component_definition_path(normalized_path, form)
        aura_component_operation = _aura_component_operation_name(normalized_path, form)
        packet_context = {
            'packet_no': packet_no, 'item': item, 'host': host,
            'method': parsed_request['method'], 'normalized_path': normalized_path,
            'operation_path': operation_path,
            'session_fingerprint': fingerprint, 'auth_kind': auth_kind,
            'app_ids': aura_context.get('app_ids', []),
            'page_uri': aura_context.get('page_uri', u''),
            'aura_endpoint': u'',
            # Noneだけを「History上でレスポンス未取得」と扱う。空レスポンスも
            # 実際に存在するHTTPメッセージとしてViewerへ渡す。
            'has_response': response_bytes is not None,
        }
        message_present = u'message' in form
        aura_message = None
        if message_present:
            aura_message = _safe_json((form.get(u'message') or [u''])[0])
        aura_present = (isinstance(aura_message, dict) and isinstance(aura_message.get('actions'), list))
        if not aura_present and (u'aura' in parsed_request['path'].lower() or u'aura.context' in form):
            aura_present = True
        if aura_present:
            packet_context['aura_endpoint'] = normalized_path
        route_protocol = _protocol_kind(parsed_request['path'], parsed_request['method'],
                                        request_content_type, response_content_type,
                                        parsed_request, aura_present)
        route_classification, route_confidence, route_evidence = _route_classification(
            route_protocol, parsed_request, host)
        destination_label, destination_confidence, destination_source, destination_evidence = \
            _destination_for_route(host, normalized_path, destination_rules)
        packet_context.update({
            'route_classification': route_classification,
            'route_confidence': route_confidence,
            'route_evidence': route_evidence,
            'destination_label': destination_label,
            'destination_confidence': destination_confidence,
            'destination_source': destination_source,
            'destination_evidence': destination_evidence,
        })
        action_operations = []
        packet_operation_ids = []

        if message_present and not isinstance(aura_message, dict):
            gaps.append({'packet_no': packet_no, 'stage': u'aura_request',
                         'reason': u'malformed Aura message JSON'})

        try:
            if isinstance(aura_message, dict) and isinstance(aura_message.get('actions'), list):
                for action_index, action in enumerate(aura_message.get('actions')):
                    if not isinstance(action, dict):
                        gaps.append({'packet_no': packet_no, 'stage': u'aura_request',
                                     'reason': u'Aura action is not an object'})
                        continue
                    operation_id, operation = _operation_for_action(
                        operations, action, action_index, packet_context,
                        resource_map=resource_map, groups=groups)
                    action_id = _display(action.get('id'))
                    action_operations.append((action_id, operation))
                    packet_operation_ids.append(operation_id)
                    aura_actions += 1
            elif aura_present:
                operation_id = _operation_id([u'Aura', host, parsed_request['method'], operation_path,
                                              aura_component_operation])
                operation = operations.get(operation_id)
                if operation is None:
                    operation = _new_operation(
                        operation_id, u'Aura', u'Unknown', u'low',
                        u'no parseable Aura action descriptor was available', host,
                        parsed_request['method'], operation_path, u'', u'', aura_component_operation,
                        _behavior(parsed_request['method'], aura_component_operation), item, packet_no)
                    operation['_salesforce_features'].update(_salesforce_features(
                        aura_component_operation, u'', normalized_path,
                        aura_context.get('page_uri', u''), None))
                    operations[operation_id] = operation
                _set_route_metadata(operation, packet_context)
                action_operations.append((u'', operation))
                packet_operation_ids.append(operation_id)
            else:
                operation_id, operation = _operation_for_non_aura(
                    operations, packet_context, parsed_request,
                    request_content_type, response_content_type)
                _add_non_aura_request_parameters(operation, parsed_request, packet_no,
                                                 resource_map=resource_map, groups=groups)
                action_operations.append((u'', operation))
                packet_operation_ids.append(operation_id)
        except Exception as exc:
            gaps.append({'packet_no': packet_no, 'stage': u'operation_catalog',
                         'reason': u'operation extraction failed: ' + _exception_text(exc)})

        # まずoccurrenceを一度だけ加算する。同一packetのAura batchで同型actionが
        # 複数ある場合は、action occurrenceを失わないため同じoperationも複数回数える。
        for _action_id, operation in action_operations:
            _add_operation_occurrence(operation, packet_context, parsed_response['status'],
                                      request_content_type, response_content_type,
                                      groups, traffic_class)
            _add_path_candidates(operation, parsed_request['path'], packet_no,
                                 resource_map=resource_map, groups=groups)

        detector_errors = []
        points = []
        if request_bytes is None:
            gaps.append({'packet_no': packet_no, 'stage': u'request',
                         'reason': u'missing request'})
        else:
            try:
                service = item.getHttpService() if hasattr(item, 'getHttpService') else None
                points = _call_detector(
                    detector, helpers, request_bytes, service,
                    lambda message: detector_errors.append(_display(message))) or []
            except Exception as exc:
                gaps.append({'packet_no': packet_no, 'stage': u'detector',
                             'reason': u'detector error: ' + _exception_text(exc)})
        for message in detector_errors:
            gaps.append({'packet_no': packet_no, 'stage': u'detector',
                         'reason': _display(message)})

        unique_operations = []
        seen_operation_objects = set()
        for _action_id, operation in action_operations:
            marker = id(operation)
            if marker not in seen_operation_objects:
                unique_operations.append(operation)
                seen_operation_objects.add(marker)
        for point in points:
            try:
                raw_path = _display(getattr(point, 'path', u''))
                action_index = _parameter_action_index(raw_path)
                targets = []
                if action_index is not None and action_index < len(action_operations):
                    targets = [action_operations[action_index][1]]
                    point_record = _point_record(point, _relative_action_parameter_path(raw_path))
                else:
                    targets = unique_operations
                    point_record = _point_record(point)
                for operation in targets:
                    _merge_parameter(operation, point_record, packet_no)
                    value = point_record.get('value', u'')
                    hint = _resource_hint(point_record['path'], value)
                    if hint:
                        candidate_type, score, reason = hint
                        _merge_candidate(operation, point_record['path'], candidate_type,
                                         value, packet_no, score, reason, u'Request')
                        _record_resource(resource_map, operation, point_record['path'], value,
                                         packet_no, groups, u'Request', hint)
            except Exception as exc:
                gaps.append({'packet_no': packet_no, 'stage': u'parameter',
                             'reason': u'insertion point parse failed: ' + _exception_text(exc)})

        if response_bytes is not None and parsed_response['body']:
            body_length = len(parsed_response['body'].encode('utf-8'))
            if body_length > _MAX_RESPONSE_JSON_BYTES:
                gaps.append({'packet_no': packet_no, 'stage': u'response_parse',
                             'reason': u'response body exceeds passive JSON analysis limit'})
            elif _is_binary_content_type(response_content_type):
                gaps.append({'packet_no': packet_no, 'stage': u'response_parse',
                             'reason': u'binary response body was not structurally parsed'})
            elif aura_present:
                _parse_aura_response(parsed_response['body'], action_operations,
                                     packet_no, groups, resource_map, gaps)
            elif (u'json' in response_content_type or
                  parsed_response['body'].lstrip().startswith((u'{', u'['))):
                response_json = _safe_json(parsed_response['body'])
                if response_json is None:
                    gaps.append({'packet_no': packet_no, 'stage': u'response_parse',
                                 'reason': u'malformed JSON response'})
                else:
                    for operation in unique_operations:
                        _walk_response_value(response_json, u'$', operation,
                                             packet_no, groups, resource_map)

        packets.append({
            'packet_no': packet_no, 'item': item,
            'operation_ids': sorted(set(packet_operation_ids)),
            'method': parsed_request['method'], 'path': parsed_request['path'],
            'normalized_path': normalized_path, 'protocol_kind': route_protocol,
            'route_classification': route_classification, 'route_confidence': route_confidence,
            'route_evidence': route_evidence, 'destination_label': destination_label,
            'destination_confidence': destination_confidence,
            'destination_source': destination_source,
            'destination_evidence': destination_evidence,
            'host': host, 'status': parsed_response['status'],
            'request_content_type': request_content_type,
            'response_content_type': response_content_type,
            'session_fingerprint': fingerprint, 'groups': sorted(set(groups)),
            'auth_kind': auth_kind, 'app_ids': list(aura_context.get('app_ids', [])),
            'page_uri': aura_context.get('page_uri', u''),
            'aura_endpoint': normalized_path if aura_present else u'',
            'is_default_app': bool(aura_context.get('is_default_app')),
            'default_app_reason': aura_context.get('default_app_reason', u''),
            'default_app_confidence': aura_context.get('default_app_confidence', u'low'),
            'comment': comment, 'highlight': highlight, 'traffic_class': traffic_class,
            # fingerprintのみ保持する。元のRequestや認証情報はこの集約情報へ複製しない。
            '_dedup_signature': _dedup_signature(parsed_request, form),
        })
        if not packet_operation_ids:
            gaps.append({'packet_no': packet_no, 'stage': u'operation_catalog',
                         'reason': u'parsed request did not reach Operation Catalog; inspect prior packet gaps'})
        try:
            if progress_fn:
                progress_fn(considered, selected_total)
        except Exception as exc:
            gaps.append({'packet_no': packet_no, 'stage': u'progress',
                         'reason': u'progress callback failed: ' + _exception_text(exc)})

    final_resources = {}
    resources = []
    for key, value in resource_map.items():
        final = _finalize_resource(value)
        final_resources[key] = final
        resources.append(final)
    resources.sort(key=lambda row: (-row['score'], row['candidate_type'], row['value']))

    operation_rows = [_finalize_operation(value, final_resources) for value in operations.values()]
    operation_rows.sort(key=lambda row: (row['protocol_kind'], row['host'].lower(),
                                         row['path'], row['operation_name']))
    session_rows = []
    for session in sessions.values():
        session['packet_nos'] = sorted(session.pop('_packet_nos'))
        session['occurrences'] = len(session['packet_nos'])
        session['hosts'] = sorted(session.pop('_hosts'))
        session['observed_groups'] = sorted(session.pop('_observed_groups'))
        session_rows.append(session)
    session_rows.sort(key=lambda row: row['fingerprint'])

    origin_counts = {}
    interaction_counts = {}
    unique_parameters = set()
    response_field_paths = set()
    candidate_count = 0
    hosts = set()
    for operation in operation_rows:
        origin = operation['origin']
        origin_counts[origin] = origin_counts.get(origin, 0) + 1
        interaction = operation.get('data_interaction', u'Unknown')
        interaction_counts[interaction] = interaction_counts.get(interaction, 0) + 1
        if operation['host']:
            hosts.add(operation['host'])
        for parameter in operation['parameters']:
            unique_parameters.add((parameter['path'], parameter['type'], parameter['region']))
        candidate_count += len(operation['resource_candidates'])
        for field in operation['response_schema_paths']:
            response_field_paths.add((operation['operation_id'], field))

    plan_rows = _build_plan_rows(operation_rows)
    object_field_catalog = _build_object_field_catalog(operation_rows)
    access_matrix = _build_access_matrix(operation_rows)
    app_endpoint_catalog = _build_app_endpoint_catalog(packets, operation_rows)
    endpoint_catalog = _build_endpoint_catalog(packets, operation_rows)
    exact_duplicate_packets = _annotate_exact_duplicates(packets, operation_rows)
    packet_catalog = _build_packet_catalog(packets)
    salesforce_features = _build_salesforce_feature_catalog(operation_rows)
    planning_gaps = _build_planning_gaps(
        operation_rows, session_rows, packets, app_endpoint_catalog)
    return {
        'summary': {
            'packets_analyzed': processed,
            'packets_selected_by_range': selected_total,
            'packets_considered': considered,
            'packets_excluded_out_of_scope': excluded_out_of_scope,
            'scope_lookup_failures': scope_lookup_failures,
            'scope_only': bool(scope_only),
            'packets_with_response': packets_with_response,
            'hosts': len(hosts), 'unique_operations': len(operation_rows),
            'aura_actions': aura_actions, 'origins': origin_counts,
            'data_interactions': interaction_counts,
            'unique_parameters': len(unique_parameters),
            'resource_candidates': candidate_count,
            'session_fingerprints': len(session_rows),
            'parse_gaps': len(gaps), 'technical_gaps': len(gaps),
            'planning_gaps': len(planning_gaps), 'cancelled': bool(cancelled),
            'traffic_classes': dict(traffic_counts),
            'response_fields': len(response_field_paths),
            'resources': len(resources),
            'objects': len(object_field_catalog['objects']),
            'fields': len(object_field_catalog['fields']),
            'apps': len(set(row.get('app_id') for row in app_endpoint_catalog
                            if row.get('app_id') != u'(not observed)')),
            'aura_endpoints': len(set((row.get('host'), row.get('aura_endpoint'))
                                      for row in app_endpoint_catalog)),
            'http_endpoints': len(endpoint_catalog),
            'exact_duplicate_packets': exact_duplicate_packets,
            'packets_without_operation': len([row for row in packet_catalog
                                               if not row.get('operation_ids')]),
        },
        'operations': operation_rows, 'sessions': session_rows,
        'gaps': gaps, 'packets': packets, 'plan_rows': plan_rows,
        'resources': resources,
        'planning_gaps': planning_gaps,
        'object_field_catalog': object_field_catalog,
        'app_endpoint_catalog': app_endpoint_catalog,
        'endpoint_catalog': endpoint_catalog,
        'packet_catalog': packet_catalog,
        'access_matrix': access_matrix,
        'salesforce_features': salesforce_features,
    }
