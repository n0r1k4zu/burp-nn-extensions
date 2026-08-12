# -*- coding: utf-8 -*-
"""Armed-target summary, activation toggle, tool-flag selection, and
re-detect control (requirement (1), plus the tool-flag hedge from the
plan's open-risks section for the macro toolFlag uncertainty)."""

import traceback

from java.awt import FlowLayout, GridLayout
from java.awt.event import ActionListener
from javax.swing import BoxLayout, JButton, JCheckBox, JComboBox, JLabel, JPanel

from csvlistinput import detection_engine
from csvlistinput.constants import TOOL_FLAG_LABELS


class _FlagToggleListener(ActionListener):
    def __init__(self, panel, flag, checkbox):
        self.panel = panel
        self.flag = flag
        self.checkbox = checkbox

    def actionPerformed(self, event):
        self.panel._on_flag_toggle(self.flag, self.checkbox)


class _PayloadEncodingListener(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel.armed_target.payload_text_encoding = str(self.panel.payload_encoding_combo.getSelectedItem())


class TargetInfoPanel(JPanel):
    def __init__(self, armed_target, helpers, on_change=None, log_fn=None, error_fn=None):
        JPanel.__init__(self)
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.armed_target = armed_target
        self.helpers = helpers
        self.on_change = on_change
        self.log_fn = log_fn
        self.error_fn = error_fn

        self.summary_label = JLabel(
            "No target armed. Right-click a request in Repeater / Proxy history and choose "
            "'Send to Target & List Mapping'.")
        self.add(self.summary_label)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.active_checkbox = JCheckBox("Active", False, actionPerformed=self._on_active_toggle)
        self.redetect_button = JButton("Re-detect insertion points", actionPerformed=self._on_redetect)
        self.crlf_checkbox = JCheckBox("Allow CRLF in header values (dangerous)", False,
                                        actionPerformed=self._on_crlf_toggle)
        self.diagnostics_checkbox = JCheckBox(
            "Log DIAGNOSTIC entries for non-enabled tools hitting the same host/path",
            armed_target.log_diagnostics_for_other_tools, actionPerformed=self._on_diagnostics_toggle)
        self.lenient_checkbox = JCheckBox(
            "Attempt lenient recovery for malformed nested JSON (experimental)",
            armed_target.allow_lenient_json, actionPerformed=self._on_lenient_toggle)
        controls.add(self.active_checkbox)
        controls.add(self.redetect_button)
        controls.add(self.crlf_checkbox)
        controls.add(self.diagnostics_checkbox)
        controls.add(self.lenient_checkbox)
        self.add(controls)

        encoding_row = JPanel(FlowLayout(FlowLayout.LEFT))
        encoding_row.add(JLabel("Payload text encoding (how CSV values are encoded into the request body):"))
        self.payload_encoding_combo = JComboBox(["utf-8", "shift_jis", "cp932", "euc-jp"])
        self.payload_encoding_combo.setSelectedItem(armed_target.payload_text_encoding)
        self.payload_encoding_combo.addActionListener(_PayloadEncodingListener(self))
        encoding_row.add(self.payload_encoding_combo)
        self.add(encoding_row)

        self.add(JLabel("Tool flags to apply substitution for (enable whichever your macro "
                         "sends actually carry -- check the Log tab's diagnostic entries):"))
        flags_panel = JPanel(GridLayout(0, 4))
        self.flag_checkboxes = {}
        for flag, label in TOOL_FLAG_LABELS:
            cb = JCheckBox(label, flag in armed_target.enabled_tool_flags)
            cb.addActionListener(_FlagToggleListener(self, flag, cb))
            flags_panel.add(cb)
            self.flag_checkboxes[flag] = cb
        self.add(flags_panel)

    def _on_active_toggle(self, event):
        self.armed_target.active = self.active_checkbox.isSelected()

    def _on_crlf_toggle(self, event):
        self.armed_target.allow_crlf_in_headers = self.crlf_checkbox.isSelected()

    def _on_diagnostics_toggle(self, event):
        self.armed_target.log_diagnostics_for_other_tools = self.diagnostics_checkbox.isSelected()

    def _on_lenient_toggle(self, event):
        self.armed_target.allow_lenient_json = self.lenient_checkbox.isSelected()

    def _on_flag_toggle(self, flag, checkbox):
        if checkbox.isSelected():
            self.armed_target.enabled_tool_flags.add(flag)
        else:
            self.armed_target.enabled_tool_flags.discard(flag)

    def _on_redetect(self, event):
        target = self.armed_target
        if not target.is_armed():
            if self.log_fn:
                self.log_fn("No target armed yet.")
            return
        try:
            def on_detect_error(msg):
                if self.log_fn:
                    self.log_fn("Insertion Point detection: %s" % msg)
                if self.error_fn:
                    self.error_fn("Target & List Mapping: Re-detect", msg)

            lenient_flag = target.allow_lenient_json
            if self.log_fn:
                self.log_fn("Re-detecting with lenient=%r" % (lenient_flag,))
            points = detection_engine.detect(self.helpers, target.original_request_bytes, target.http_service,
                                              on_error=on_detect_error, lenient=lenient_flag)
            target.arm(target.connection_signature, points, target.http_service,
                       target.original_request_bytes, label=target.label)
            if self.log_fn:
                recovered_count = sum(1 for p in points if getattr(p, 'recovered', False))
                self.log_fn("Re-detected %d insertion points (%d recovered)." % (len(points), recovered_count))
            if self.on_change:
                self.on_change()
        except Exception as e:
            if self.log_fn:
                self.log_fn("Re-detect failed: %s" % e)
            if self.error_fn:
                self.error_fn("Target & List Mapping: Re-detect", str(e), traceback.format_exc())

    def refresh(self):
        target = self.armed_target
        if target.is_armed():
            self.summary_label.setText("Target: %s  |  %s  |  %d insertion points, %d mapped" % (
                target.label or "?", target.connection_signature,
                len(target.template_points), target.mapped_count()))
            self.active_checkbox.setSelected(target.active)
        else:
            self.summary_label.setText(
                "No target armed. Right-click a request in Repeater / Proxy history and choose "
                "'Send to Target & List Mapping'.")
