# -*- coding: utf-8 -*-
"""Holds Live Word Watch's global configuration: the feature master
switch, the search word, the before/after context sizes, and which tool
flags it applies to. Deliberately independent of ArmedTarget -- like
Match & Replace, this watches any traffic through the enabled tools,
with no "arm" step required. Edits from the UI take effect on the next
processed message, same discipline as ReplaceSettings.
"""

from csvlistinput.constants import DEFAULT_ENABLED_TOOL_FLAGS


class LiveWordWatchSettings(object):
    def __init__(self):
        self.enabled = False
        self.word = ""
        self.before_chars = 30
        self.after_chars = 30
        self.enabled_tool_flags = set(DEFAULT_ENABLED_TOOL_FLAGS)
        # Off by default (Burp's Target Scope may not be configured, and
        # silently scanning nothing would be confusing) -- restricts
        # watching to in-scope traffic, which matters most when Proxy is
        # among the enabled tool flags and general browsing traffic
        # (trackers/CDNs/ads) would otherwise all be scanned too.
        self.scope_only = False
