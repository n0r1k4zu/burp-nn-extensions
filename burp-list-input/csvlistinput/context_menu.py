# -*- coding: utf-8 -*-
"""IContextMenuFactory: adds "Send to Target & List Mapping" and "Send to
Target & Replace with Decode & Encode" entries to Repeater / Proxy-history /
Target-site-map right-click menus. These arm TWO INDEPENDENT targets (one
per feature, each its own ArmedTarget instance) from whichever message
was right-clicked -- a request armed for Target & List Mapping's CSV
substitution does not have to be the same request armed for Target &
Replace with Decode's per-point rewriting, and vice versa. Arm-time
detection uses the exact same detection_engine code path as every later
live send, per the plan's path-based re-matching design.

Also adds, whenever the right-click happens inside a message editor/
viewer (Repeater, Proxy, our own Log tab's request/response panes, etc.)
with an active text selection:
  - "Add selection to Match & Replace" -- appends the selected text as a
    new Before rule on whichever side (request/response) the editor was
    showing.
  - "Send selection to Decode" -- shows the selected text in the
    extension's Decode tab, with every supported transform applied.
Both reuse the same selection-extraction logic (_extract_selection).
"""

import traceback

from java.awt.event import ActionListener
from java.io import File
from javax.swing import JFileChooser, JMenuItem, JOptionPane

from burp import IContextMenuFactory, IContextMenuInvocation

from csvlistinput import detection_engine, matching
from csvlistinput import insertion_point_export
from csvlistinput import statistics_engine
from csvlistinput.utils import bytes_to_bytestring, from_bytestring_space

_REQUEST_CONTEXTS = set([
    IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
    IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
])
_RESPONSE_CONTEXTS = set([
    IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
    IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
])


class _ArmAction(ActionListener):
    def __init__(self, helpers, armed_target, message, feature_label, on_armed, log_fn, error_fn):
        self.helpers = helpers
        self.armed_target = armed_target
        self.message = message
        self.feature_label = feature_label  # "Target & List Mapping" or "Target & Replace with Decode & Encode"
        self.on_armed = on_armed
        self.log_fn = log_fn
        self.error_fn = error_fn

    def actionPerformed(self, event):
        try:
            http_service = self.message.getHttpService()
            request_bytes = self.message.getRequest()

            def on_detect_error(msg):
                if self.log_fn:
                    self.log_fn("Insertion Point detection: %s" % msg)
                if self.error_fn:
                    self.error_fn("%s: Insertion Point detection" % self.feature_label, msg)

            lenient_flag = self.armed_target.allow_lenient_json
            if self.log_fn:
                self.log_fn("%s: arming with lenient=%r" % (self.feature_label, lenient_flag))
            template_points = detection_engine.detect(
                self.helpers, request_bytes, http_service, on_error=on_detect_error,
                lenient=lenient_flag)
            signature = matching.signature_from_message(self.helpers, http_service, request_bytes)
            request_info = self.helpers.analyzeRequest(http_service, request_bytes)
            label = "%s %s" % (request_info.getMethod(), signature.url_path)
            self.armed_target.arm(signature, template_points, http_service, request_bytes, label=label)
            if self.log_fn:
                recovered_count = sum(1 for p in template_points if getattr(p, 'recovered', False))
                self.log_fn(
                    "%s: armed target %s (%d insertion points detected, %d recovered)."
                    % (self.feature_label, label, len(template_points), recovered_count))
            if self.on_armed:
                self.on_armed()
        except Exception as e:
            if self.log_fn:
                self.log_fn("%s: failed to arm target: %s" % (self.feature_label, e))
            if self.error_fn:
                self.error_fn("%s: Send to..." % self.feature_label, str(e), traceback.format_exc())


class _AddSelectionToReplaceAction(ActionListener):
    def __init__(self, rule_store, selected_text, side_label, on_change, log_fn):
        self.rule_store = rule_store
        self.selected_text = selected_text
        self.side_label = side_label
        self.on_change = on_change
        self.log_fn = log_fn

    def actionPerformed(self, event):
        self.rule_store.add_rule(before=self.selected_text, after=u"", enabled=True, is_regex=False)
        if self.on_change:
            self.on_change()
        if self.log_fn:
            preview = self.selected_text
            if len(preview) > 60:
                preview = preview[:57] + u"..."
            self.log_fn(u"Match & Replace: added selection to %s Before list: %s" % (self.side_label, preview))


class _SendToDecodeAction(ActionListener):
    def __init__(self, selected_text, on_decode):
        self.selected_text = selected_text
        self.on_decode = on_decode

    def actionPerformed(self, event):
        if self.on_decode:
            self.on_decode(self.selected_text)


class _GroupHistoryAction(ActionListener):
    """Append a user-named bracket tag to the selected History comments."""
    def __init__(self, messages, log_fn, error_fn):
        self.messages = messages
        self.log_fn = log_fn
        self.error_fn = error_fn

    def actionPerformed(self, event):
        name = JOptionPane.showInputDialog(None, 'Group name:', 'MyTools: Group selected packets',
                                           JOptionPane.QUESTION_MESSAGE)
        if name is None:
            return
        try:
            changed = statistics_engine.add_group(self.messages, name)
            if self.log_fn:
                self.log_fn('Statistics: added group [%s] to %d selected packet(s).' % (name, changed))
        except Exception as e:
            if self.error_fn:
                self.error_fn('Statistics: Group selected packets', str(e), traceback.format_exc())


class _AuraTargetAction(ActionListener):
    def __init__(self, message, callback, log_fn):
        self.message = message
        self.callback = callback
        self.log_fn = log_fn

    def actionPerformed(self, event):
        if self.callback:
            self.callback(self.message)
        elif self.log_fn:
            self.log_fn('Aura Diagnostic: panel is not available.')


class _ExportPacketInsertionPointsAction(ActionListener):
    """Save one CSV row for every insertion point of every selected packet."""
    def __init__(self, callbacks, helpers, messages, log_fn, error_fn):
        self.callbacks = callbacks
        self.helpers = helpers
        self.messages = list(messages)
        self.log_fn = log_fn
        self.error_fn = error_fn

    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File('packet_insertion_points.csv'))
        if chooser.showSaveDialog(None) != JFileChooser.APPROVE_OPTION:
            return
        try:
            def report_detection_error(message):
                if self.log_fn:
                    self.log_fn('Insertion Point export: %s' % message)

            rows = insertion_point_export.build_rows(
                self.callbacks, self.helpers, self.messages, on_error=report_detection_error)
            insertion_point_export.write_csv(chooser.getSelectedFile().getAbsolutePath(), rows)
            message = 'Exported %d insertion point row(s) from %d selected packet(s).' % (len(rows), len(self.messages))
            if self.log_fn:
                self.log_fn('Insertion Point export: ' + message)
            JOptionPane.showMessageDialog(None, message, 'MyTools: Export Packet & Insertion Point',
                                          JOptionPane.INFORMATION_MESSAGE)
        except Exception as exc:
            if self.error_fn:
                self.error_fn('Export Packet & Insertion Point', str(exc), traceback.format_exc())
            JOptionPane.showMessageDialog(None, 'Export failed: %s' % exc,
                                          'MyTools: Export Packet & Insertion Point', JOptionPane.ERROR_MESSAGE)


class _ExportPacketInsertionPointsWithStatisticsAction(ActionListener):
    """Number, annotate, then export only the selected HTTP History items."""
    def __init__(self, callbacks, helpers, messages, log_fn, error_fn):
        self.callbacks = callbacks
        self.helpers = helpers
        self.messages = list(messages)
        self.log_fn = log_fn
        self.error_fn = error_fn

    def actionPerformed(self, event):
        chooser = JFileChooser()
        chooser.setSelectedFile(File('packet_insertion_points_statistics.csv'))
        if chooser.showSaveDialog(None) != JFileChooser.APPROVE_OPTION:
            return
        try:
            # Keep the exact original Java/Python comment value.  If the user
            # chooses cleanup after a successful export, restoration is safer
            # than trying to infer which old number/tag was already present.
            original_comments = [(message, message.getComment()) for message in self.messages]
            # The Numbering & Grouping tab's defaults are Start=1, Digits=4.
            numbered = statistics_engine.number_selected(self.messages, 1, 4)
            selected_numbers = set(no for no in insertion_point_export._packet_numbers(
                self.callbacks, self.messages) if no != '')
            # Build aggregation against the whole History so an Aura target
            # selected alone still receives the same classification/role it
            # has in the Statistics tab.  Only selected records are changed.
            all_records = statistics_engine.analyze_history(self.callbacks, self.helpers)
            selected_records = [record for record in all_records
                                if record['packet_no'] in selected_numbers]
            annotated, _colored = statistics_engine.annotate_analysis(
                selected_records, add_class_tags=True, add_aggregation_tags=True)

            def report_detection_error(message):
                if self.log_fn:
                    self.log_fn('Insertion Point export: %s' % message)

            rows = insertion_point_export.build_rows(
                self.callbacks, self.helpers, self.messages, on_error=report_detection_error)
            insertion_point_export.write_csv(chooser.getSelectedFile().getAbsolutePath(), rows)
            message = ('Numbered %d and added Statistics tags to %d selected packet(s); '
                       'exported %d insertion point row(s).'
                       % (numbered, annotated, len(rows)))
            if self.log_fn:
                self.log_fn('Export Packet & Insertion Point with Statistics comment: ' + message)
            JOptionPane.showMessageDialog(
                None, message, 'MyTools: Export Packet & Insertion Point with Statistics comment',
                JOptionPane.INFORMATION_MESSAGE)
            cleanup = JOptionPane.showConfirmDialog(
                None,
                'Remove the numbering and Statistics comments added for this export?\n'
                'Yes restores each selected packet comment to its state before this export.\n'
                'No keeps the added comments.',
                'MyTools: Keep or remove export comments',
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE)
            if cleanup == JOptionPane.YES_OPTION:
                restored = 0
                for selected_message, original_comment in original_comments:
                    selected_message.setComment(original_comment)
                    restored += 1
                if self.log_fn:
                    self.log_fn('Export Packet & Insertion Point with Statistics comment: '
                                'restored comments for %d selected packet(s).' % restored)
        except Exception as exc:
            if self.error_fn:
                self.error_fn('Export Packet & Insertion Point with Statistics comment', str(exc), traceback.format_exc())
            JOptionPane.showMessageDialog(
                None, 'Export failed: %s' % exc,
                'MyTools: Export Packet & Insertion Point with Statistics comment', JOptionPane.ERROR_MESSAGE)


class _ClearSelectedHistoryFieldAction(ActionListener):
    """Clear only the selected Proxy History packets' comment or highlight."""
    def __init__(self, messages, field, log_fn, error_fn):
        self.messages = list(messages)
        self.field = field
        self.log_fn = log_fn
        self.error_fn = error_fn

    def actionPerformed(self, event):
        try:
            changed = 0
            for message in self.messages:
                if self.field == 'comment':
                    old = message.getComment()
                    if old:
                        message.setComment(u'')
                        changed += 1
                else:
                    old = message.getHighlight()
                    if old:
                        message.setHighlight(None)
                        changed += 1
            label = 'Clear Comment' if self.field == 'comment' else 'Clear Color'
            if self.log_fn:
                self.log_fn('%s: cleared %d selected History packet(s).' % (label, changed))
        except Exception as exc:
            label = 'Clear Comment' if self.field == 'comment' else 'Clear Color'
            if self.error_fn:
                self.error_fn(label, str(exc), traceback.format_exc())


class ContextMenuFactory(IContextMenuFactory):
    def __init__(self, callbacks, helpers, armed_target, decode_replace_target, request_replace_store,
                 response_replace_store, on_armed=None, on_replace_added=None, on_decode=None,
                 on_aura_target=None, log_fn=None, error_fn=None):
        self.callbacks = callbacks
        self.helpers = helpers
        self.armed_target = armed_target
        self.decode_replace_target = decode_replace_target
        self.request_replace_store = request_replace_store
        self.response_replace_store = response_replace_store
        self.on_armed = on_armed
        self.on_replace_added = on_replace_added
        self.on_decode = on_decode
        self.on_aura_target = on_aura_target
        self.log_fn = log_fn
        self.error_fn = error_fn

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        message = messages[0]

        items = []
        try:
            is_proxy_history = (invocation.getInvocationContext() ==
                                IContextMenuInvocation.CONTEXT_PROXY_HISTORY)
        except Exception:
            is_proxy_history = False
        if is_proxy_history:
            comment_clear_item = JMenuItem('Clear Comment')
            comment_clear_item.addActionListener(_ClearSelectedHistoryFieldAction(
                messages, 'comment', self.log_fn, self.error_fn))
            items.append(comment_clear_item)
            color_clear_item = JMenuItem('Clear Color')
            color_clear_item.addActionListener(_ClearSelectedHistoryFieldAction(
                messages, 'color', self.log_fn, self.error_fn))
            items.append(color_clear_item)

        export_item = JMenuItem('Export Packet & Insertion Point')
        export_item.addActionListener(_ExportPacketInsertionPointsAction(
            self.callbacks, self.helpers, messages, self.log_fn, self.error_fn))
        items.append(export_item)
        if is_proxy_history:
            export_statistics_item = JMenuItem('Export Packet & Insertion Point with Statistics comment')
            export_statistics_item.addActionListener(_ExportPacketInsertionPointsWithStatisticsAction(
                self.callbacks, self.helpers, messages, self.log_fn, self.error_fn))
            items.append(export_statistics_item)

        list_mapping_item = JMenuItem("Send to Target & List Mapping")
        list_mapping_item.addActionListener(_ArmAction(
            self.helpers, self.armed_target, message, "Target & List Mapping",
            self.on_armed, self.log_fn, self.error_fn))
        items.append(list_mapping_item)

        decode_replace_item = JMenuItem("Send to Target & Replace with Decode & Encode")
        decode_replace_item.addActionListener(_ArmAction(
            self.helpers, self.decode_replace_target, message, "Target & Replace with Decode & Encode",
            self.on_armed, self.log_fn, self.error_fn))
        items.append(decode_replace_item)

        group_item = JMenuItem('MyTools: Group selected History packets')
        group_item.addActionListener(_GroupHistoryAction(messages, self.log_fn, self.error_fn))
        items.append(group_item)

        aura_item = JMenuItem('MyTools: Set Aura diagnostic target')
        aura_item.addActionListener(_AuraTargetAction(message, self.on_aura_target, self.log_fn))
        items.append(aura_item)

        selected_text, side_label = self._extract_selection(invocation, message)
        if selected_text:
            rule_store = self.request_replace_store if side_label == "Request" else self.response_replace_store
            replace_item = JMenuItem(u"Add selection to Match & Replace → %s Before" % side_label)
            replace_item.addActionListener(_AddSelectionToReplaceAction(
                rule_store, selected_text, side_label, self.on_replace_added, self.log_fn))
            items.append(replace_item)

            decode_item = JMenuItem("Send selection to Decode")
            decode_item.addActionListener(_SendToDecodeAction(selected_text, self.on_decode))
            items.append(decode_item)

        return items

    def _extract_selection(self, invocation, message):
        """Returns (selected_text, side_label) for the currently active
        text selection in a message editor/viewer context, or (None,
        None) if there's no applicable selection. Shared by the
        Match & Replace and Decode context menu actions."""
        try:
            context = invocation.getInvocationContext()
            bounds = invocation.getSelectionBounds()
        except Exception:
            return None, None
        if not bounds or len(bounds) != 2:
            return None, None
        start, end = bounds[0], bounds[1]
        if start is None or end is None or end <= start:
            return None, None  # no active selection

        if context in _REQUEST_CONTEXTS:
            raw_bytes = message.getRequest()
            side_label = "Request"
        elif context in _RESPONSE_CONTEXTS:
            raw_bytes = message.getResponse()
            side_label = "Response"
        else:
            return None, None  # not a message editor/viewer -- selection bounds don't apply
        if raw_bytes is None:
            return None, None

        try:
            buf = bytes_to_bytestring(self.helpers, raw_bytes)
        except Exception:
            return None, None
        if start < 0 or end > len(buf):
            return None, None
        selected_text = from_bytestring_space(buf[start:end])
        if not selected_text:
            return None, None
        return selected_text, side_label
