# -*- coding: utf-8 -*-
"""Holds Target & Replace with Decode & Encode's configuration: the feature master
switch, which tool flags it applies to, and one DecodeReplaceRule per
Insertion Point path. This feature is scoped to its OWN independently-
armed target (a separate ArmedTarget instance from Target & List
Mapping's -- see context_menu.py's two distinct "Send to ..." menu
items); this module just reads that target's template_points and keeps
rules keyed by each point's structural `path` (the same stable identity
used everywhere else in this codebase for live re-matching -- see
armed_target.py / matching.py).
"""

from csvlistinput.codec_engine import CODEC_NAMES

_PROXY_FLAG = 0x00000004
_REPEATER_FLAG = 0x00000040


class DecodeReplaceRule(object):
    def __init__(self):
        self.enabled = False
        self.codec = CODEC_NAMES[0]  # "None"
        self.find = u""
        self.replace_with = u""
        self.is_regex = False


class DecodeReplaceSettings(object):
    def __init__(self):
        self.enabled = False
        self.enabled_tool_flags = set([_REPEATER_FLAG])
        self.rules_by_path = {}  # path -> DecodeReplaceRule

    def get_rule(self, path):
        rule = self.rules_by_path.get(path)
        if rule is None:
            rule = DecodeReplaceRule()
            self.rules_by_path[path] = rule
        return rule

    def enabled_rules(self):
        """Returns {path: DecodeReplaceRule} for rules the user has
        actually turned on."""
        return dict((path, rule) for path, rule in self.rules_by_path.items() if rule.enabled)
