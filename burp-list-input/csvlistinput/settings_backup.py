# -*- coding: utf-8 -*-
"""Human-editable Markdown backup format for MyTools session settings."""

import base64
import json
import re
import time

from csvlistinput.color_snapshot_store import ColorSnapshotEntry
from csvlistinput.comment_snapshot_store import CommentSnapshotEntry
from csvlistinput.replace_rule_store import ReplaceRule
from csvlistinput.utils import to_display_text

FORMAT_VERSION = 1
_SECTIONS = ('My Word List', 'Request replacements', 'Response replacements', 'Target & List Mapping CSV')


def _json_text(value):
    """Return JSON-safe Unicode without Jython's implicit ASCII coercion.

    Snapshots can contain raw HTTP-derived strings.  Those may include any
    byte value (for example 0x89), and handing them directly to json.dumps
    makes Jython attempt an ASCII decode. Latin-1 is lossless for such byte
    strings; normal Swing/CSV Unicode stays unchanged and editable.
    """
    return to_display_text(value)


def _json_document_text(value):
    """json.dumps() returns a byte string on some Jython builds even with
    ensure_ascii=False. Decode that UTF-8 document *before* joining it to
    the Unicode Markdown document; otherwise Jython implicitly assumes
    ASCII and fails on bytes such as 0x89."""
    try:
        if isinstance(value, unicode):
            return value
        return str(value).decode('utf-8')
    except NameError:
        return value


def _base64_encode(value):
    """Encode a Proxy-history request identity losslessly.

    Burp's bytesToString() returns a Java/Jython Unicode string whose
    codepoints 0..255 represent raw request bytes.  base64.b64encode() only
    accepts a byte string on Jython, and otherwise attempts ASCII itself.
    Convert that one-byte-per-codepoint representation explicitly first.
    """
    if value is None:
        value = u''
    try:
        raw = unicode(value).encode('latin-1')
    except NameError:  # CPython
        raw = value.encode('latin-1') if isinstance(value, str) else value
    except UnicodeEncodeError:
        # Not expected for bytesToString identities, but retain a usable
        # backup if a third-party Burp API implementation supplies true text.
        raw = unicode(value).encode('utf-8')
    return base64.b64encode(raw).decode('ascii')


def _base64_decode(value):
    raw = base64.b64decode(value.encode('ascii'))
    # Match helpers.bytesToString() / Java String's one-codepoint-per-byte
    # identity representation so restored snapshots compare equal again.
    return raw.decode('latin-1')


def _identity_to_dict(identity):
    host, port, protocol, request = identity
    return {'host': _json_text(host), 'port': port, 'protocol': _json_text(protocol),
            'request_base64': _base64_encode(request)}


def _dict_to_identity(value):
    return (value.get('host', ''), int(value.get('port', 0)), value.get('protocol', ''),
            _base64_decode(value.get('request_base64', '')))


def _color_entries(store):
    data = []
    for entry in store.get_all():
        colors = []
        # A color snapshot records every packet, including the overwhelmingly
        # common ``None`` entries. Backups only need the actually colored
        # packets; restore already leaves absent packets untouched.
        for identity, color in entry.colors.items():
            if not color:
                continue
            item = _identity_to_dict(identity)
            item['highlight'] = color
            colors.append(item)
        data.append({'id': entry.seq_id, 'timestamp': entry.timestamp, 'note': _json_text(entry.comment or ''),
                     'total': len(colors), 'colored_count': len(colors), 'packets': colors})
    return data


def _comment_entries(store):
    data = []
    for entry in store.get_all():
        comments = []
        for identity, values in entry.comments.items():
            # Keep a duplicate-request group only if it contains a comment.
            # Empty elements within a kept group preserve duplicate ordering.
            if not any(values):
                continue
            item = _identity_to_dict(identity)
            item['comments'] = [_json_text(value) for value in values]
            comments.append(item)
        saved_total = sum(len(item['comments']) for item in comments)
        saved_nonempty = sum(len([value for value in item['comments'] if value]) for item in comments)
        data.append({'id': entry.seq_id, 'timestamp': entry.timestamp, 'note': _json_text(entry.comment or ''),
                     'total': saved_total, 'nonempty_count': saved_nonempty, 'packets': comments})
    return data


def _rule_entries(store):
    return [{'enabled': bool(rule.enabled), 'regex': bool(rule.is_regex),
             'before': _json_text(rule.before), 'after': _json_text(rule.after)} for rule in store.snapshot()]


def _mapping_csv_payload(csv_store):
    payload = csv_store.backup_snapshot()
    return {'headers': [_json_text(value) for value in payload.get('headers', [])],
            'rows': [[_json_text(value) for value in row] for row in payload.get('rows', [])],
            'start_row': payload.get('start_row', 1)}


def _csv_cell(value):
    value = _json_text(value)
    if any(ch in value for ch in (u',', u'"', u'\r', u'\n')):
        return u'"' + value.replace(u'"', u'""') + u'"'
    return value


def _mapping_csv_markdown(csv_store):
    payload = _mapping_csv_payload(csv_store)
    rows = [payload['headers']] + payload['rows'] if payload['headers'] else []
    csv_text = u'\n'.join(u','.join(_csv_cell(value) for value in row) for row in rows)
    return [u'## Target & List Mapping CSV', u'', u'<!-- start_row: %d -->' % payload['start_row'],
            u'```csv', csv_text, u'```', u'']


def _csv_markdown(title, headers, rows):
    csv_rows = [headers] + rows
    csv_text = u'\n'.join(u','.join(_csv_cell(value) for value in row) for row in csv_rows)
    return [u'## ' + title, u'', u'```csv', csv_text, u'```', u'']


def _parse_csv_text(text):
    """Small RFC-4180-compatible Unicode CSV parser for the editable block."""
    rows, row, cell = [], [], []
    quoted = False
    index = 0
    while index < len(text):
        ch = text[index]
        if quoted:
            if ch == u'"':
                if index + 1 < len(text) and text[index + 1] == u'"':
                    cell.append(u'"'); index += 1
                else:
                    quoted = False
            else:
                cell.append(ch)
        elif ch == u'"' and not cell:
            quoted = True
        elif ch == u',':
            row.append(u''.join(cell)); cell = []
        elif ch == u'\r' or ch == u'\n':
            if ch == u'\r' and index + 1 < len(text) and text[index + 1] == u'\n':
                index += 1
            row.append(u''.join(cell)); cell = []
            if row != [u''] or rows:
                rows.append(row)
            row = []
        else:
            cell.append(ch)
        index += 1
    if quoted:
        raise ValueError('Target & List Mapping CSV contains an unclosed quote.')
    if cell or row:
        row.append(u''.join(cell)); rows.append(row)
    return rows


def _mapping_csv_from_markdown(markdown):
    pattern = r'^##[ \t]+Target\ \&\ List\ Mapping\ CSV[ \t]*\r?\n(?:<!--\s*start_row:\s*(\d+)\s*-->\r?\n)?[\s\S]*?```csv\s*\r?\n([\s\S]*?)\r?\n```'
    match = re.search(pattern, markdown, re.MULTILINE)
    if match:
        rows = _parse_csv_text(match.group(2))
        if not rows:
            return {'headers': [], 'rows': [], 'start_row': 1}
        return {'headers': rows[0], 'rows': rows[1:], 'start_row': int(match.group(1) or 1)}
    # Compatibility with the previous JSON-based backup format.
    return _optional_section_payload(markdown, 'Target & List Mapping CSV', dict)


def _csv_section_rows(markdown, title):
    pattern = r'^##[ \t]+%s[ \t]*\r?\n[\s\S]*?```csv\s*\r?\n([\s\S]*?)\r?\n```' % re.escape(title)
    match = re.search(pattern, markdown, re.MULTILINE)
    if not match:
        raise ValueError('Missing CSV section: %s' % title)
    return _parse_csv_text(match.group(1))


def _word_rows_from_csv(rows):
    if not rows:
        return []
    header = [value.strip().lower() for value in rows[0]]
    regex_index = header.index(u'regex') if u'regex' in header else None
    comment_index = header.index(u'comment') if u'comment' in header else (2 if regex_index == 1 else 1)
    result = []
    for row in rows[1:]:
        if row and row[0]:
            is_regex = (regex_index is not None and regex_index < len(row)
                        and row[regex_index].strip().lower() in (u'1', u'true', u'yes', u'on'))
            result.append({'word': row[0], 'is_regex': is_regex,
                           'comment': row[comment_index] if comment_index < len(row) else u''})
    return result


def _rules_from_csv(rows):
    rules = []
    for row in rows[1:]:  # header: Enabled,Regex,Before,After
        if len(row) < 4:
            continue
        enabled = row[0].strip().lower() in (u'1', u'true', u'yes', u'on')
        is_regex = row[1].strip().lower() in (u'1', u'true', u'yes', u'on')
        rules.append(ReplaceRule(row[2], row[3], enabled, is_regex))
    return rules


def export_markdown(word_store, color_store, comment_store, request_rule_store, response_rule_store, csv_store):
    """Return an editable Markdown document made entirely of CSV blocks."""
    parts = [
        '# MyTools Settings Backup',
        '',
        'Format version: %d' % FORMAT_VERSION,
        '',
        'This is an editable Markdown backup. Edit the CSV blocks below as needed.',
        ''
    ]
    parts.extend(_csv_markdown('My Word List', [u'Word', u'Regex', u'Comment'], [
        [_json_text(row.get('word', u'')), u'1' if row.get('is_regex', False) else u'0',
         _json_text(row.get('comment', u''))]
        for row in word_store.snapshot()]))
    parts.extend(_csv_markdown('Request replacements', [u'Enabled', u'Regex', u'Before', u'After'], [
        [u'1' if rule.enabled else u'0', u'1' if rule.is_regex else u'0',
         _json_text(rule.before), _json_text(rule.after)] for rule in request_rule_store.snapshot()]))
    parts.extend(_csv_markdown('Response replacements', [u'Enabled', u'Regex', u'Before', u'After'], [
        [u'1' if rule.enabled else u'0', u'1' if rule.is_regex else u'0',
         _json_text(rule.before), _json_text(rule.after)] for rule in response_rule_store.snapshot()]))
    parts.extend(_mapping_csv_markdown(csv_store))
    return u'\n'.join(parts)


def _section_payload(markdown, title, expected_type=list):
    pattern = r'^##[ \t]+%s[ \t]*\r?\n[\s\S]*?```json\s*\r?\n([\s\S]*?)\r?\n```' % re.escape(title)
    match = re.search(pattern, markdown, re.MULTILINE)
    if not match:
        raise ValueError('Missing JSON section: %s' % title)
    try:
        result = json.loads(match.group(1))
    except Exception as error:
        raise ValueError('Invalid JSON in %s: %s' % (title, error))
    if not isinstance(result, expected_type):
        expected_name = 'JSON array' if expected_type is list else 'JSON object'
        raise ValueError('%s must be a %s.' % (title, expected_name))
    return result


def _optional_section_payload(markdown, title, expected_type=list):
    """Old backups predate Match & Replace; retain their active rules."""
    try:
        result = _section_payload(markdown, title, expected_type)
        return result
    except ValueError as error:
        if to_display_text(error).startswith('Missing JSON section:'):
            return None
        raise


def _color_from_payload(payload):
    entries = []
    for row in payload:
        entry = ColorSnapshotEntry()
        entry.seq_id = int(row.get('id', 0)) or None
        entry.timestamp = row.get('timestamp') or time.time()
        entry.comment = row.get('note', '')
        entry.colors = {}
        for packet in row.get('packets', []):
            entry.colors[_dict_to_identity(packet)] = packet.get('highlight')
        entry.total = int(row.get('total', len(entry.colors)))
        entry.colored_count = int(row.get('colored_count', len([c for c in entry.colors.values() if c])))
        entries.append(entry)
    return entries


def _comments_from_payload(payload):
    entries = []
    for row in payload:
        entry = CommentSnapshotEntry()
        entry.seq_id = int(row.get('id', 0)) or None
        entry.timestamp = row.get('timestamp') or time.time()
        entry.comment = row.get('note', '')
        entry.comments = {}
        for packet in row.get('packets', []):
            entry.comments[_dict_to_identity(packet)] = list(packet.get('comments', []))
        entry.total = int(row.get('total', sum(len(v) for v in entry.comments.values())))
        entry.nonempty_count = int(row.get('nonempty_count', sum(
            len([v for v in values if v]) for values in entry.comments.values())))
        entries.append(entry)
    return entries


def _rules_from_payload(payload):
    return [ReplaceRule(row.get('before', u''), row.get('after', u''),
                        bool(row.get('enabled', True)), bool(row.get('regex', False))) for row in payload]


def restore_markdown(markdown, word_store, color_store, comment_store, request_rule_store, response_rule_store,
                     csv_store):
    word_rows = _word_rows_from_csv(_csv_section_rows(markdown, 'My Word List'))
    request_rules_payload = _csv_section_rows(markdown, 'Request replacements')
    response_rules_payload = _csv_section_rows(markdown, 'Response replacements')
    mapping_csv_payload = _mapping_csv_from_markdown(markdown)
    request_rules = _rules_from_csv(request_rules_payload)
    response_rules = _rules_from_csv(response_rules_payload)
    # Parse every section before changing any active state.
    word_store.replace(word_rows)
    request_rule_store.replace_rules(request_rules)
    response_rule_store.replace_rules(response_rules)
    if mapping_csv_payload is not None:
        csv_store.restore_snapshot(mapping_csv_payload)
    return (len(word_store.snapshot()), 0, 0, len(request_rules), len(response_rules),
            len(mapping_csv_payload.get('rows', [])) if mapping_csv_payload is not None else None)
