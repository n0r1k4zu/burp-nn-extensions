# -*- coding: utf-8 -*-
"""IHttpListener implementation -- the runtime hot path.

Design (see the plan doc): NEVER trust offsets stored on the armed
template across sends. On every matching outgoing request, re-run
detection_engine.detect() fresh against the live bytes and join the
saved path -> column mapping purely by structural `path`, so token
rotation / length drift from a Session Handling Rule macro can't
desynchronize substitution.

Burp calls processHttpMessage() twice per HTTP transaction: once for the
request (messageIsRequest=True) and later for the response
(messageIsRequest=False). The documented assumption that the SAME
messageInfo object is reused for both calls turned out NOT to hold in
practice here (confirmed via debug logging: the request-phase and
response-phase calls carried different java.lang.System.identityHashCode
values for what should have been "the same" object -- likely because
this Burp version's legacy Extender API is a compatibility shim over a
Montoya-based core that mints a fresh wrapper per callback). So instead
of correlating by object identity, we correlate by the CONTENT of the
request that was actually sent: messageInfo.getRequest() in the
response-phase callback reflects the exact bytes that were transmitted,
which is the same value we recorded as entry.request_bytes_after during
the request phase. Content equality is unaffected by however Burp
chooses to wrap/rewrap the surrounding object.

Three independent features share this listener:
  - CSV Insertion Point substitution, gated behind its own "armed" target
    (armed_target.py) -- unchanged in behavior from before Match & Replace
    was added.
  - Match & Replace (replace_engine.py), gated behind ReplaceSettings and
    completely independent of whether anything is armed -- it applies to
    any traffic through its own enabled tool flags.
  - Target & Replace with Decode & Encode (decode_replace_engine.py), gated behind
    DecodeReplaceSettings -- like CSV Insertion Point substitution (and
    unlike Match & Replace) it's scoped to an armed target's connection
    signature, but it's a SEPARATE, independently-armed target (its own
    ArmedTarget instance -- see context_menu.py's two distinct "Send to
    ..." menu items) with its own enabled/tool-flag switches, and it
    rewrites specific Insertion Points' values through a decode ->
    find/replace -> re-encode pipeline instead of splicing in a fixed
    CSV value.
When more than one of these fires for the same transaction, they share a
single LogEntry rather than producing multiple rows.

Any unexpected exception anywhere in this hot path is also reported to
error_store (the Errors tab) in addition to Burp's own Extender > Errors
console, so a bug tripped by, say, Scanner traffic through this listener
is impossible to miss from within the extension's own UI.
"""

import threading
import time
import traceback

from burp import IHttpListener

from csvlistinput import decode_replace_engine, detection_engine, matching, replace_engine, substitution_engine
from csvlistinput.constants import EscapeMode, PointStatus, SendStatus, TOOL_FLAG_LABELS
from csvlistinput.models import Edit, LogEntry, PointResult
from csvlistinput.utils import (bytes_to_bytestring, bytestring_to_bytes, escape_bytestring_for_context,
                                to_display_text)


def tool_label(tool_flag):
    for flag, label in TOOL_FLAG_LABELS:
        if flag == tool_flag:
            return label
    return "0x%08x" % tool_flag


class HttpListener(IHttpListener):
    def __init__(self, callbacks, helpers, armed_target, csv_store, log_store,
                 replace_settings, request_replace_store, response_replace_store,
                 decode_replace_settings, decode_replace_target, error_store):
        self.callbacks = callbacks
        self.helpers = helpers
        self.armed_target = armed_target
        self.csv_store = csv_store
        self.log_store = log_store
        self.replace_settings = replace_settings
        self.request_replace_store = request_replace_store
        self.response_replace_store = response_replace_store
        self.decode_replace_settings = decode_replace_settings
        self.decode_replace_target = decode_replace_target
        self.error_store = error_store
        self._apply_lock = threading.Lock()
        # request-bytes-as-string -> FIFO list[LogEntry], so the later
        # response-phase callback can find and update the entry the
        # request-phase callback already logged, keyed by what was
        # actually sent rather than by object identity (see module
        # docstring). A FIFO queue per content-key handles the edge case
        # of two requests with byte-identical bodies in flight at once.
        # Entries are removed as soon as the response arrives; a
        # transaction that never gets a response-phase callback (e.g. a
        # dropped connection) would leak its entry here, which is an
        # accepted minor limitation for a human-paced testing tool.
        self._pending_by_content = {}

    def _debug(self, msg, error_source=None):
        # Temporary, verbose-but-cheap diagnostic trail while chasing the
        # "response not showing in Log" report -- visible in Extender >
        # Extensions > CSV List Input > Output. Safe to leave in
        # permanently (printOutput is essentially free), but noisy; strip
        # once request/response correlation is confirmed reliable.
        try:
            self.callbacks.printOutput("CSV List Input [debug]: %s" % msg)
        except Exception:
            pass
        # Some of these _debug() call sites are genuine Burp-API-level
        # oddities (getRequest()/getResponse()/analyzeResponse() raising)
        # worth surfacing in the Errors tab, not just the Output console --
        # error_source is only passed at those call sites.
        if error_source is not None and self.error_store is not None:
            self.error_store.append(error_source, msg)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                self._handle_request_phase(toolFlag, messageInfo)
            else:
                self._handle_response_phase(toolFlag, messageInfo)
        except Exception as e:
            tb = traceback.format_exc()
            try:
                self.callbacks.printError("CSV List Input: processHttpMessage error: %s" % e)
            except Exception:
                pass
            if self.error_store is not None:
                self.error_store.append("HttpListener.processHttpMessage (tool=%s)" % tool_label(toolFlag),
                                         to_display_text(e), detail=tb)

    def _handle_request_phase(self, toolFlag, messageInfo):
        entry = LogEntry()
        entry.timestamp = time.time()
        entry.tool_flag = toolFlag
        entry.tool_label = tool_label(toolFlag)
        entry.http_service = messageInfo.getHttpService()

        # Stage 1: Match & Replace -- traffic-wide, independent of any armed target.
        replace_live = (self.replace_settings.enabled
                         and toolFlag in self.replace_settings.enabled_tool_flags
                         and (not self.replace_settings.scope_only or self._in_scope(messageInfo)))
        if replace_live:
            request_bytes = messageInfo.getRequest()
            http_service = messageInfo.getHttpService()
            entry.request_bytes_before = request_bytes
            new_bytes, applied = replace_engine.apply_to_request(
                self.helpers, http_service, request_bytes,
                self.request_replace_store, self.replace_settings)
            if applied:
                messageInfo.setRequest(new_bytes)
            entry.request_replace_count = applied

        # Stage 2: CSV Insertion Point substitution -- armed target's own Active toggle.
        target = self.armed_target
        logged = False
        if target.is_armed() and target.active:
            logged = self._handle_request_phase_armed(toolFlag, messageInfo, target, entry)

        # Stage 3: Target & Replace with Decode & Encode -- its OWN independently-
        # armed target (decode_replace_target, separate from `target`
        # above), plus its OWN Enabled toggle + tool flags.
        decode_replace_applied = 0
        decode_diagnostic_logged = False
        if self.decode_replace_settings.enabled and self.decode_replace_target.is_armed():
            if toolFlag in self.decode_replace_settings.enabled_tool_flags:
                decode_replace_applied = self._apply_decode_replace(messageInfo, self.decode_replace_target, entry)
            elif self.decode_replace_target.log_diagnostics_for_other_tools:
                decode_diagnostic_logged = self._maybe_log_diagnostic(
                    toolFlag, messageInfo.getHttpService(), messageInfo.getRequest(), self.decode_replace_target,
                    entry, feature_label="Target & Replace with Decode & Encode")

        notes = []
        if replace_live and entry.request_replace_count:
            notes.append("Match & Replace: %d request replacement(s)" % entry.request_replace_count)
        if decode_replace_applied:
            notes.append("Target & Replace with Decode & Encode: %d insertion point(s) updated"
                         % decode_replace_applied)

        if logged or decode_diagnostic_logged:
            # Stage 2 already logged `entry` (e.g. status APPLIED with no
            # note of its own) -- append the other stages' notes rather
            # than let them go unrepresented.
            if notes:
                prefix = (entry.note + " | ") if entry.note else ""
                entry.note = prefix + " | ".join(notes)
            return

        entry.request_bytes_after = messageInfo.getRequest()
        if notes:
            # A real hit from stage 1 and/or stage 3 -- show it immediately.
            entry.send_status = SendStatus.REPLACED
            entry.note = " | ".join(notes)
            self._log_and_track(entry)
        elif replace_live:
            # No hit anywhere yet, but Match & Replace is live for this
            # tool -- track for potential response-side correlation (see
            # _handle_response_phase). Target & Replace with Decode & Encode is
            # request-only, so it never needs this "wait for response"
            # path on its own.
            self._track_only(entry)
        # else: nothing is live/armed for this transaction -- nothing to do.

    def _handle_request_phase_armed(self, toolFlag, messageInfo, target, entry):
        """Returns True if `entry` was logged (by this call or by
        _maybe_log_diagnostic), False if the armed-target feature had
        nothing to do for this transaction."""
        request_bytes = messageInfo.getRequest()
        http_service = messageInfo.getHttpService()

        if toolFlag not in target.enabled_tool_flags:
            # Diagnostic hedge (opt-in, see ArmedTarget.log_diagnostics_for_other_tools):
            # Burp does not publicly document which TOOL_* flag (if any
            # distinct one) is attached to requests issued internally by a
            # Session Handling Rule macro. If host/path otherwise match the
            # armed target, log the flag we actually saw so the user can
            # enable it from the UI.
            if target.log_diagnostics_for_other_tools:
                return self._maybe_log_diagnostic(toolFlag, http_service, request_bytes, target, entry)
            return False

        live_sig = matching.signature_from_message(self.helpers, http_service, request_bytes)
        if target.connection_signature != live_sig:
            return False

        with self._apply_lock:
            return self._apply_and_send(toolFlag, messageInfo, request_bytes, http_service, live_sig, entry)

    def _content_key(self, request_bytes):
        return self.helpers.bytesToString(request_bytes)

    def _handle_response_phase(self, toolFlag, messageInfo):
        try:
            request_bytes = messageInfo.getRequest()
        except Exception as e:
            self._debug("response-phase: messageInfo.getRequest() raised: %s" % e,
                        error_source="HttpListener.responsePhase")
            return
        if request_bytes is None:
            return

        try:
            response_bytes = messageInfo.getResponse()
        except Exception as e:
            self._debug("response-phase: messageInfo.getResponse() raised: %s" % e,
                        error_source="HttpListener.responsePhase")
            response_bytes = None

        response_bytes_before = None
        response_replace_count = 0
        if (response_bytes is not None and self.replace_settings.enabled
                and toolFlag in self.replace_settings.enabled_tool_flags
                and (not self.replace_settings.scope_only or self._in_scope(messageInfo))):
            response_bytes_before = response_bytes
            response_bytes, response_replace_count = replace_engine.apply_to_response(
                self.helpers, response_bytes, self.response_replace_store, self.replace_settings)
            if response_replace_count:
                messageInfo.setResponse(response_bytes)

        key = self._content_key(request_bytes)
        queue = self._pending_by_content.get(key)
        if not queue:
            return  # not a transaction we're tracking (unrelated traffic, or already matched)
        entry = queue.pop(0)
        if not queue:
            del self._pending_by_content[key]

        if response_bytes is None:
            return

        # entry.seq_id is only assigned by LogStore.append() -- None means
        # _handle_request_phase tracked this transaction for correlation
        # without making it visible yet (no request-side hit). If the
        # response side doesn't hit either, drop it silently rather than
        # surfacing a row Match & Replace never actually touched.
        already_visible = entry.seq_id is not None
        if not already_visible and response_replace_count == 0:
            return

        entry.response_bytes = response_bytes
        entry.response_replace_count = response_replace_count
        if response_replace_count:
            entry.response_bytes_before = response_bytes_before
            prefix = (entry.note + " | ") if entry.note else ""
            entry.note = "%sMatch & Replace: %d response replacement(s)" % (prefix, response_replace_count)
        try:
            entry.response_status = self.helpers.analyzeResponse(response_bytes).getStatusCode()
        except Exception as e:
            self._debug("response-phase: analyzeResponse() raised: %s" % e,
                        error_source="HttpListener.responsePhase")

        if already_visible:
            self.log_store.notify_updated(entry)
        else:
            entry.send_status = SendStatus.REPLACED
            self.log_store.append(entry)

    def _in_scope(self, messageInfo):
        """Fail open only if Burp cannot derive a URL from this message."""
        try:
            return self.callbacks.isInScope(self.helpers.analyzeRequest(messageInfo).getUrl())
        except Exception:
            return True

    def _log_and_track(self, entry):
        self.log_store.append(entry)
        self._track_only(entry)

    def _track_only(self, entry):
        key = self._content_key(entry.request_bytes_after)
        self._pending_by_content.setdefault(key, []).append(entry)

    def _maybe_log_diagnostic(self, toolFlag, http_service, request_bytes, target, entry,
                              feature_label="Target & List Mapping"):
        try:
            live_sig = matching.signature_from_message(self.helpers, http_service, request_bytes)
        except Exception:
            return False
        if not target.connection_signature or not target.connection_signature.matches_host_path(live_sig):
            return False
        entry.send_status = SendStatus.DIAGNOSTIC
        entry.connection_display = repr(live_sig)
        entry.request_bytes_after = request_bytes  # unmodified -- so it's still viewable in the Log tab
        entry.note = ("Host/path matched the armed target but tool flag '%s' is not enabled -- "
                       "enable it in the %s panel if this send should be processed."
                       % (entry.tool_label, feature_label))
        self._log_and_track(entry)
        return True

    def _apply_and_send(self, toolFlag, messageInfo, request_bytes, http_service, live_sig, entry):
        target = self.armed_target
        buf = bytes_to_bytestring(self.helpers, request_bytes)
        # Must match the armed template's lenient setting -- otherwise a
        # point found via lenient recovery at arm time would never be
        # re-found (by path) on live sends, silently dropping it.
        live_points = detection_engine.detect(self.helpers, request_bytes, http_service,
                                                lenient=target.allow_lenient_json)

        row_index, row_no, row_values = self.csv_store.consume_next_row()

        entry.connection_display = repr(live_sig)

        if row_values is None:
            entry.send_status = SendStatus.EXHAUSTED
            entry.request_bytes_after = request_bytes
            entry.note = "CSV payload list exhausted -- sent unmodified. Use Reset to start over."
            self._log_and_track(entry)
            return True

        request_info = self.helpers.analyzeRequest(http_service, request_bytes)
        body_offset = request_info.getBodyOffset()

        edits, results = matching.build_edits(target, live_points, row_values, self.helpers)
        new_buf, _applied, _skipped = substitution_engine.substitute(buf, edits, body_offset=body_offset)
        new_request_bytes = bytestring_to_bytes(self.helpers, new_buf)
        messageInfo.setRequest(new_request_bytes)

        entry.send_status = SendStatus.APPLIED
        entry.csv_row_index_used = row_index
        entry.csv_row_no = row_no
        entry.csv_row_values = row_values
        entry.per_point_results = results
        entry.request_bytes_after = new_request_bytes
        self._log_and_track(entry)
        return True

    def _apply_decode_replace(self, messageInfo, target, entry):
        """Target & Replace with Decode & Encode: for each Insertion Point with an
        enabled rule, decode its current value, run the rule's find/
        replace, re-encode, and splice back in. `target` here is
        self.decode_replace_target -- its OWN independently-armed target,
        separate from self.armed_target (CSV Insertion Point substitution)
        even though both are ArmedTarget instances. Scoped to that
        target's connection signature (unlike Match & Replace, this
        doesn't apply to arbitrary traffic). Returns the number of points
        actually rewritten (0 if the connection signature didn't match,
        there were no enabled rules, or every rule skipped/no-matched)."""
        enabled_rules = self.decode_replace_settings.enabled_rules()
        if not enabled_rules:
            return 0

        request_bytes = messageInfo.getRequest()
        http_service = messageInfo.getHttpService()
        live_sig = matching.signature_from_message(self.helpers, http_service, request_bytes)
        if target.connection_signature != live_sig:
            return 0

        live_points = detection_engine.detect(self.helpers, request_bytes, http_service,
                                                lenient=target.allow_lenient_json)
        live_points_by_path = dict((p.path, p) for p in live_points)

        buf = bytes_to_bytestring(self.helpers, request_bytes)
        edits = []
        results = []
        for path, rule in enabled_rules.items():
            point = live_points_by_path.get(path)
            if point is None:
                results.append(PointResult(path, rule.codec, PointStatus.SKIPPED_PATH_MISSING))
                continue
            try:
                new_raw_value, hit_count = decode_replace_engine.apply_rule(point.original_value, rule)
            except Exception as e:
                results.append(PointResult(path, rule.codec, PointStatus.SKIPPED_DECODE_ERROR,
                                           preview_value=to_display_text(e)))
                continue
            if not hit_count:
                results.append(PointResult(path, rule.codec, PointStatus.SKIPPED_NO_MATCH))
                continue
            escaped = escape_bytestring_for_context(new_raw_value, point, EscapeMode.AUTO, helpers=self.helpers,
                                                      allow_crlf_in_headers=target.allow_crlf_in_headers)
            edits.append(Edit(point.start, point.end, escaped, path=path))
            results.append(PointResult(path, rule.codec, PointStatus.OK, preview_value=new_raw_value))

        entry.per_point_results.extend(results)
        if not edits:
            return 0

        request_info = self.helpers.analyzeRequest(http_service, request_bytes)
        body_offset = request_info.getBodyOffset()
        new_buf, accepted, skipped = substitution_engine.substitute(buf, edits, body_offset=body_offset)
        for e in skipped:
            entry.per_point_results.append(PointResult(e.path, None, PointStatus.SKIPPED_OVERLAP_CONFLICT))
        new_request_bytes = bytestring_to_bytes(self.helpers, new_buf)
        messageInfo.setRequest(new_request_bytes)

        entry.connection_display = repr(live_sig)
        entry.request_bytes_after = new_request_bytes
        return len(accepted)
