# -*- coding: utf-8 -*-
"""NN-Extensions composition root (Jython, loaded via jython.jar in
Extender > Options > Python Environment, then Extender > Extensions >
Add > Extension type: Python, pointing at this file).

This file does not contain any extension logic of its own. It simply
loads the two independent extensions below as normal Python modules and
drives each one's existing registerExtenderCallbacks() against the same
Burp `callbacks` object, so Burp shows a single "NN-Extensions" entry in
its Extensions list while both tools keep working exactly as they do
when loaded standalone:

  - burp-list-input/csv_list_input.py   -> adds the "CSV List Input" tab
  - burp-sf-aura/sf_aura_burp_helper.py -> adds the "SF Helper" tab

Keep burp-list-input/ and burp-sf-aura/ (each with their own contents
unchanged) as sibling folders next to this file.
"""

import os
import sys

from burp import IBurpExtender

EXTENSION_NAME = "NN-Extensions"

# Set this to True in this file, then reload the extension, when the legacy
# SF Helper tab/context menus are needed.  MyTools includes the migrated Aura
# Diagnostic functionality, so SF Helper is hidden by default.
ENABLE_SF_HELPER = False

# Last-resort manual override: if neither __file__ nor sys.argv[0] resolve
# to this file's real location, set this to this file's own directory.
MANUAL_EXTENSION_DIR = "/Users/pentester/Desktop/Burp-NN-Extensions"


def _get_extension_dir():
    # Same __file__/sys.argv[0] fallback approach as csv_list_input.py's
    # _get_extension_dir(): Burp's Jython loader executes this script
    # directly, so `__file__` is not set in the global namespace at that
    # point (referencing the bare name raises NameError -- look it up via
    # globals().get() instead). `sys.argv[0]` is what Burp actually sets
    # to this file's own path in that situation.
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
        "NN-Extensions: could not determine the extension's own directory "
        "(neither __file__ nor sys.argv[0] pointed at an existing path). "
        "Set MANUAL_EXTENSION_DIR near the top of nn_extensions.py to the "
        "folder containing this file, then reload the extension.")


class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName(EXTENSION_NAME)

        ext_dir = _get_extension_dir()
        list_input_dir = os.path.join(ext_dir, "burp-list-input")
        sf_aura_dir = os.path.join(ext_dir, "burp-sf-aura")
        for sub_dir in (list_input_dir, sf_aura_dir):
            if sub_dir not in sys.path:
                sys.path.append(sub_dir)

        # Each import below is a normal module import (not Burp's direct-exec
        # of a script), so __file__ is set correctly inside csv_list_input's
        # own _get_extension_dir() and its csvlistinput/ package import keeps
        # working unmodified.
        import csv_list_input
        self.csv_list_input_extender = csv_list_input.BurpExtender()
        self.csv_list_input_extender.registerExtenderCallbacks(callbacks)

        self.sf_aura_extender = None
        if ENABLE_SF_HELPER:
            import sf_aura_burp_helper
            self.sf_aura_extender = sf_aura_burp_helper.BurpExtender()
            self.sf_aura_extender.registerExtenderCallbacks(callbacks)

        # Both sub-extensions call setExtensionName() themselves during the
        # registerExtenderCallbacks() calls above; reassert the combined
        # name last so it's what actually shows up in Burp's Extensions list.
        callbacks.setExtensionName(EXTENSION_NAME)
        loaded = "MyTools + SF Aura Helper (see the 'MyTools' and 'SF Helper' tabs)" if ENABLE_SF_HELPER else "MyTools (SF Helper hidden; set ENABLE_SF_HELPER = True in nn_extensions.py to show it)"
        callbacks.printOutput("%s loaded: %s." % (EXTENSION_NAME, loaded))
