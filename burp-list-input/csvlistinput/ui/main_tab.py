# -*- coding: utf-8 -*-
"""ITab: assembles the target/mapping panels and the log panel into the
extension's suite tab."""

import time

from java.awt import BorderLayout, Color
from javax.swing import JPanel, JSplitPane, JTabbedPane, SwingUtilities

from burp import ITab

from csvlistinput.constants import SendStatus
from csvlistinput.models import LogEntry
from csvlistinput.ui.color_snapshot_panel import ColorSnapshotPanel
from csvlistinput.ui.csv_panel import CsvPanel
from csvlistinput.ui.decode_panel import DecodePanel
from csvlistinput.ui.decode_replace_panel import DecodeReplacePanel
from csvlistinput.ui.errors_panel import ErrorsPanel
from csvlistinput.ui.insertion_point_panel import InsertionPointPanel
from csvlistinput.ui.log_panel import LogPanel
from csvlistinput.ui.replace_panel import ReplacePanel
from csvlistinput.ui.target_info_panel import TargetInfoPanel
from csvlistinput.ui.word_search_panel import WordSearchPanel


class MainTab(ITab):
    def __init__(self, callbacks, helpers, armed_target, csv_store, log_store,
                 replace_settings, request_replace_store, response_replace_store,
                 decode_replace_settings, decode_replace_target, error_store, color_snapshot_store):
        self.callbacks = callbacks
        self.armed_target = armed_target
        self.csv_store = csv_store
        self.log_store = log_store
        self.error_store = error_store

        self.log_panel = LogPanel(callbacks, helpers, log_store)
        self.insertion_point_panel = InsertionPointPanel(armed_target, csv_store)
        self.target_info_panel = TargetInfoPanel(armed_target, helpers, on_change=self.refresh,
                                                   log_fn=self.log, error_fn=self.log_error)
        self.csv_panel = CsvPanel(csv_store, on_loaded=self.refresh, log_fn=self.log)
        self.replace_panel = ReplacePanel(replace_settings, request_replace_store, response_replace_store)
        self.decode_panel = DecodePanel(request_replace_store, response_replace_store,
                                         on_replace_added=self.refresh, log_fn=self.log)
        self.decode_replace_panel = DecodeReplacePanel(decode_replace_target, decode_replace_settings, helpers,
                                                         log_fn=self.log, error_fn=self.log_error)
        self.color_snapshot_panel = ColorSnapshotPanel(callbacks, helpers, color_snapshot_store,
                                                          log_fn=self.log, error_fn=self.log_error)
        self.word_search_panel = WordSearchPanel(callbacks, helpers, log_fn=self.log, error_fn=self.log_error)
        self.errors_panel = ErrorsPanel(error_store)

        mapping_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.insertion_point_panel, self.csv_panel)
        mapping_split.setResizeWeight(0.6)

        target_mapping_panel = JPanel(BorderLayout())
        top_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.target_info_panel, mapping_split)
        top_split.setResizeWeight(0.15)
        target_mapping_panel.add(top_split, BorderLayout.CENTER)

        self.tabbed_pane = JTabbedPane()
        self.tabbed_pane.addTab("Target & List Mapping", target_mapping_panel)
        self.tabbed_pane.addTab("Target & Replace with Decode & Encode", self.decode_replace_panel)
        self.tabbed_pane.addTab("Match & Replace", self.replace_panel)
        self.tabbed_pane.addTab("Log", self.log_panel)
        self.tabbed_pane.addTab("Color Snapshots", self.color_snapshot_panel)
        self.tabbed_pane.addTab("History Search", self.word_search_panel)
        self.tabbed_pane.addTab("Decode", self.decode_panel)
        self.errors_tab_index = self.tabbed_pane.getTabCount()
        self.tabbed_pane.addTab("Errors", self.errors_panel)
        self._update_errors_tab_title()

        # Every log append means a send was attempted, which may have
        # consumed a CSV row -- keep the CSV panel's "Row N of M" pointer
        # display live instead of only refreshing it on Load/Reset clicks.
        log_store.add_listener(self._on_log_entry)

        # Keep the tab label itself an at-a-glance indicator (count + red
        # text) so an error is impossible to miss without having to click
        # into the tab first -- this is the whole point of this tab.
        error_store.add_listener(self._on_error_entry)
        error_store.add_clear_listener(self._on_errors_cleared)

    def _on_log_entry(self, entry):
        SwingUtilities.invokeLater(self.csv_panel.refresh_pointer_label)

    def refresh(self):
        def do_refresh():
            self.target_info_panel.refresh()
            self.insertion_point_panel.refresh()
            self.replace_panel.refresh()
            self.decode_replace_panel.refresh()
        SwingUtilities.invokeLater(do_refresh)

    def show_decode(self, text):
        """Called from the right-click 'Send selection to Decode' action
        -- populates the Decode tab and switches focus to it."""
        def do_show():
            self.decode_panel.set_text(text)
            self.tabbed_pane.setSelectedComponent(self.decode_panel)
        SwingUtilities.invokeLater(do_show)

    def log(self, message):
        entry = LogEntry()
        entry.timestamp = time.time()
        entry.send_status = SendStatus.DIAGNOSTIC
        entry.tool_label = "-"
        entry.note = message
        self.log_store.append(entry)

    def log_error(self, source, message, detail=None):
        """Central entry point for "something in this extension's own
        code failed" -- called from http_listener.py (all three
        substitution stages, across every Burp tool including Scanner),
        context_menu.py, and the arm/re-detect paths. Safe to call from
        any thread."""
        self.error_store.append(source, message, detail=detail)

    def _on_error_entry(self, entry):
        SwingUtilities.invokeLater(self._update_errors_tab_title)

    def _on_errors_cleared(self):
        SwingUtilities.invokeLater(self._update_errors_tab_title)

    def _update_errors_tab_title(self):
        count = self.error_store.count()
        if count:
            self.tabbed_pane.setTitleAt(self.errors_tab_index, "Errors (%d)" % count)
            self.tabbed_pane.setForegroundAt(self.errors_tab_index, Color.RED)
        else:
            self.tabbed_pane.setTitleAt(self.errors_tab_index, "Errors")
            self.tabbed_pane.setForegroundAt(self.errors_tab_index, None)

    def getTabCaption(self):
        return "CSV List Input"

    def getUiComponent(self):
        return self.tabbed_pane
