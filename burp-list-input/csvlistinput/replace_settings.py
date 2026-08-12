# -*- coding: utf-8 -*-
"""Holds Match & Replace's global configuration: the feature master
switch, which tool flags it applies to, and which packet regions are in
scope. Deliberately independent of ArmedTarget -- this feature applies to
any traffic through the enabled tools, with no "arm" step required."""

_PROXY_FLAG = 0x00000004
_REPEATER_FLAG = 0x00000040


class ReplaceSettings(object):
    def __init__(self):
        self.enabled = False
        self.enabled_tool_flags = set([_PROXY_FLAG, _REPEATER_FLAG])
        self.scope_method = True
        self.scope_path = True
        self.scope_headers = True
        self.scope_body = True

    def scope_all_selected(self):
        return self.scope_method and self.scope_path and self.scope_headers and self.scope_body
