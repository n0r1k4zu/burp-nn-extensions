# -*- coding: utf-8 -*-
"""Burp Extender entry point (Jython, loaded via jython.jar in
Extender > Options > Python Environment, then Extender > Extensions >
Add > Extension type: Python, pointing at this file).

CSV-driven Insertion Point substitution for Repeater sends (including
sends that go through a Session Handling Rule macro): arm a captured
request, auto-detect insertion points at JSON/XML-nesting-aware
granularity, map them to CSV columns, and every matching outgoing send
gets the next CSV row's values spliced in.

This file is intentionally a thin composition root -- all real logic
lives in the csvlistinput package alongside it. See
csvlistinput/http_listener.py for the runtime hot path.
"""

import os
import sys

from burp import IBurpExtender, IExtensionStateListener

EXTENSION_NAME = "MyTools"

# Last-resort manual override: if neither __file__ nor sys.argv[0] resolve
# to this file's real location (see _get_extension_dir), set this to the
# extension's install directory, e.g. "/Users/pentester/Desktop/burp-list-input".
MANUAL_EXTENSION_DIR = "/Users/pentester/Desktop/burp-list-input"


def _get_extension_dir():
    # Burp's Jython extension loader executes this script directly rather
    # than importing it as a module, so `__file__` is not set in the
    # global namespace (a well-known Jython/Burp quirk -- referencing the
    # bare name raises NameError, so look it up via globals().get()
    # instead of a bare reference). `sys.argv[0]` is what Burp actually
    # sets to this file's own path in that situation.
    candidates = [globals().get('__file__'), sys.argv[0] if sys.argv else None, MANUAL_EXTENSION_DIR]
    for candidate in candidates:
        if not candidate:
            continue
        path = os.path.abspath(candidate)
        if os.path.isfile(path):
            return os.path.dirname(path)
        if os.path.isdir(path):
            return path
    raise RuntimeError(
        "CSV List Input: could not determine the extension's own directory "
        "(neither __file__ nor sys.argv[0] pointed at an existing path). "
        "Set MANUAL_EXTENSION_DIR near the top of csv_list_input.py to the "
        "folder containing this file, then reload the extension.")


def _purge_module_cache():
    # Burp's "Reload extension" does not clear sys.modules, so edits to
    # submodules would otherwise silently not take effect on reload.
    for name in list(sys.modules.keys()):
        if name == "csvlistinput" or name.startswith("csvlistinput."):
            del sys.modules[name]


def _purge_compiled_bytecode_cache(ext_dir):
    # Jython additionally caches compiled bytecode alongside each .py file
    # as "<module>$py.class", and will silently keep using a stale one
    # instead of recompiling if its mtime looks >= the .py source's mtime
    # (which can happen depending on how the source file was edited/synced
    # -- purging sys.modules alone does NOT invalidate this on-disk cache).
    # Deleting them here forces a fresh compile from the current source on
    # every reload, so a code change always actually takes effect.
    pkg_dir = os.path.join(ext_dir, "csvlistinput")
    for root, _dirs, files in os.walk(pkg_dir):
        for name in files:
            if name.endswith("$py.class"):
                try:
                    os.remove(os.path.join(root, name))
                except OSError:
                    pass


class BurpExtender(IBurpExtender, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)

        ext_dir = _get_extension_dir()
        if ext_dir not in sys.path:
            sys.path.append(ext_dir)
        _purge_compiled_bytecode_cache(ext_dir)
        _purge_module_cache()

        from csvlistinput.armed_target import ArmedTarget
        from csvlistinput.color_snapshot_store import ColorSnapshotStore
        from csvlistinput.context_menu import ContextMenuFactory
        from csvlistinput.csv_payload_store import CsvPayloadStore
        from csvlistinput.decode_replace_settings import DecodeReplaceSettings
        from csvlistinput.error_store import ErrorStore
        from csvlistinput.http_listener import HttpListener
        from csvlistinput.live_word_watch_listener import LiveWordWatchListener
        from csvlistinput.live_word_watch_settings import LiveWordWatchSettings
        from csvlistinput.live_word_watch_store import LiveWordWatchStore
        from csvlistinput.log_store import LogStore
        from csvlistinput.replace_rule_store import ReplaceRuleStore
        from csvlistinput.replace_settings import ReplaceSettings
        from csvlistinput.ui.main_tab import MainTab

        self.armed_target = ArmedTarget()
        self.decode_replace_target = ArmedTarget()
        self.csv_store = CsvPayloadStore()
        self.log_store = LogStore()
        self.replace_settings = ReplaceSettings()
        self.request_replace_store = ReplaceRuleStore()
        self.response_replace_store = ReplaceRuleStore()
        self.decode_replace_settings = DecodeReplaceSettings()
        self.error_store = ErrorStore()
        self.color_snapshot_store = ColorSnapshotStore()
        self.live_word_watch_settings = LiveWordWatchSettings()
        self.live_word_watch_store = LiveWordWatchStore()

        self.main_tab = MainTab(callbacks, self.helpers, self.armed_target, self.csv_store, self.log_store,
                                 self.replace_settings, self.request_replace_store, self.response_replace_store,
                                 self.decode_replace_settings, self.decode_replace_target, self.error_store,
                                 self.color_snapshot_store, self.live_word_watch_settings, self.live_word_watch_store)

        self.http_listener = HttpListener(callbacks, self.helpers, self.armed_target,
                                           self.csv_store, self.log_store,
                                           self.replace_settings, self.request_replace_store,
                                           self.response_replace_store, self.decode_replace_settings,
                                           self.decode_replace_target, self.error_store)
        self.live_word_watch_listener = LiveWordWatchListener(
            callbacks, self.helpers, self.live_word_watch_settings, self.live_word_watch_store,
            error_fn=self.main_tab.log_error)
        self.context_menu_factory = ContextMenuFactory(
            self.helpers, self.armed_target, self.decode_replace_target,
            self.request_replace_store, self.response_replace_store,
            on_armed=self.main_tab.refresh, on_replace_added=self.main_tab.refresh,
            on_decode=self.main_tab.show_decode, log_fn=self.main_tab.log, error_fn=self.main_tab.log_error)

        callbacks.registerHttpListener(self.http_listener)
        callbacks.registerHttpListener(self.live_word_watch_listener)
        callbacks.registerContextMenuFactory(self.context_menu_factory)
        callbacks.addSuiteTab(self.main_tab)
        callbacks.registerExtensionStateListener(self)

        callbacks.printOutput(
            "%s loaded. Right-click a request in Repeater/Proxy history and choose "
            "'Send to Target & List Mapping' or 'Send to Target & Replace with Decode & Encode' to get started."
            % EXTENSION_NAME)

    def extensionUnloaded(self):
        try:
            self.armed_target.disarm()
        except Exception:
            pass
        try:
            self.decode_replace_target.disarm()
        except Exception:
            pass
