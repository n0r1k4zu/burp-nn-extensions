# -*- coding: utf-8 -*-
"""Export selected HTTP History requests and their detected insertion points.

This module intentionally calls :func:`detection_engine.detect` rather than a
format-specific parser.  The export therefore has exactly the same URL,
cookie, header, form, XML and recursively nested JSON coverage as Target &
List Mapping.
"""

import csv

from csvlistinput import detection_engine
from csvlistinput.utils import from_bytestring_space


HEADERS = ['No', 'Packet No', 'URL', 'Type', 'Insertion Point', 'Comment']

try:
    _TEXT_TYPE = unicode
    _BYTESTRING_TYPE = str
except NameError:
    _TEXT_TYPE = str
    _BYTESTRING_TYPE = bytes


def _csv_text(value):
    """Return display text without asking Jython to ASCII-decode bytes.

    Insertion-point paths may originate in raw request byte-string space;
    calling ``unicode(path)`` on a UTF-8 Japanese key causes Jython's implicit
    ASCII decode and was the source of the export failure.  Decode request
    bytes explicitly, with the existing lossless fallback used elsewhere.
    """
    if value is None:
        return u''
    if isinstance(value, _TEXT_TYPE):
        return value
    if isinstance(value, _BYTESTRING_TYPE):
        try:
            return from_bytestring_space(value)
        except Exception:
            try:
                return value.decode('latin-1')
            except Exception:
                return _TEXT_TYPE(repr(value))
    try:
        return _TEXT_TYPE(value)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return _TEXT_TYPE(str(value), 'latin-1')


def _packet_numbers(callbacks, selected_messages):
    """Resolve selected HTTP History items to their 1-based History numbers.

Burp's legacy ``IHttpRequestResponse`` does not expose its History row
number.  Prefer object identity/equality against the current History, then
fall back to a request/service signature for implementations that wrap the
same Java object differently.
    """
    history = list(callbacks.getProxyHistory())
    claimed = set()
    numbers = []
    for message in selected_messages:
        found = None
        for index, item in enumerate(history):
            if index in claimed:
                continue
            try:
                if item is message or item == message:
                    found = index
                    break
            except Exception:
                pass
        if found is None:
            try:
                svc = message.getHttpService()
                request = message.getRequest()
                for index, item in enumerate(history):
                    if index in claimed:
                        continue
                    other = item.getHttpService()
                    if (other.getHost() == svc.getHost() and other.getPort() == svc.getPort()
                            and other.getProtocol() == svc.getProtocol()
                            and item.getRequest() == request):
                        found = index
                        break
            except Exception:
                pass
        if found is not None:
            claimed.add(found)
            numbers.append(found + 1)
        else:
            numbers.append('')
    return numbers


def build_rows(callbacks, helpers, messages, on_error=None):
    """Return one CSV row per detected insertion point in selection order."""
    rows = []
    sequence = 0
    packet_numbers = _packet_numbers(callbacks, messages)
    for message, packet_no in zip(messages, packet_numbers):
        try:
            service = message.getHttpService()
            request = message.getRequest()
            request_info = helpers.analyzeRequest(service, request)
            url = _csv_text(request_info.getUrl())
            comment = _csv_text(message.getComment() or u'')
            points = detection_engine.detect(helpers, request, service, on_error=on_error)
        except Exception as exc:
            if on_error:
                on_error('Could not inspect a selected packet: %s' % exc)
            continue
        for point in points:
            sequence += 1
            point_type = point.type + ('_RECOVERED' if getattr(point, 'recovered', False) else '')
            rows.append([sequence, packet_no, url, _csv_text(point_type), _csv_text(point.path), comment])
    return rows


def write_csv(file_path, rows, encoding='utf-8'):
    """Write Unicode-safe CSV in both Jython 2 and CPython 3."""
    try:
        unicode
        is_jython = True
    except NameError:
        is_jython = False
    handle = open(file_path, 'wb') if is_jython else open(file_path, 'w', newline='', encoding=encoding)
    try:
        writer = csv.writer(handle)
        if is_jython:
            writer.writerow([_csv_text(value).encode(encoding) for value in HEADERS])
            for row in rows:
                writer.writerow([_csv_text(value).encode(encoding) for value in row])
        else:
            writer.writerow(HEADERS)
            writer.writerows(rows)
    finally:
        handle.close()
