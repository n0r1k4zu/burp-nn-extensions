# -*- coding: utf-8 -*-
"""Decode tab: the selected/pasted text on the left, every supported
decode/encode transform stacked on the right, each auto-wrapping at its
own width. Unlike Burp's own docked Decoder (a single narrow chain you
step through one transform at a time), this uses the full suite-tab area
and shows every transform at once so nothing needs horizontal scrolling
or manual chaining.

Both halves have their own search box: the left one highlights and steps
through matches within the source text (like a normal editor find), the
right one highlights matches within each transform's result AND hides
transforms whose result doesn't contain the search term, so a user
looking for "which decoding contains X" doesn't have to scan every block.

Right-clicking a text selection anywhere in this tab (the source area or
any decode result) pops up "Add selection to Match & Replace -> Request
Before" / "-> Response Before". Unlike the same feature on Burp's own
message editors (context_menu.py), there is no request/response context
to infer here -- this panel isn't tied to a captured HTTP transaction --
so the user picks the side explicitly from the popup instead.

A checkbox row across the top lets the user manually narrow which
transforms run (default: every transform in decode_engine.TRANSFORM_LABELS
is on, i.e. "try everything" -- unchecking one just stops it from being
computed/shown, it doesn't change the other transforms' behavior).
"""

from java.awt import BorderLayout, Color, FlowLayout, GridBagConstraints, GridBagLayout, Insets
from java.awt.event import ActionListener, MouseAdapter
from javax.swing import (BorderFactory, BoxLayout, JButton, JCheckBox, JLabel, JMenuItem, JPanel,
                          JPopupMenu, JScrollPane, JSplitPane, JTextArea, JTextField, ScrollPaneConstants)
from javax.swing.event import DocumentListener
from javax.swing.text import DefaultHighlighter

from csvlistinput import decode_engine

_PLACEHOLDER = ("Select text in a request/response and right-click -> "
                "'Send selection to Decode', or type/paste text on the left and click Decode.")
_MATCH_COLOR = Color(255, 235, 59)


def _make_wrapping_area(editable, rows):
    area = JTextArea(rows, 20)
    area.setEditable(editable)
    area.setLineWrap(True)
    area.setWrapStyleWord(False)  # encoded data has no natural word breaks -- wrap at any character
    return area


def _find_all(haystack, needle):
    """Case-insensitive substring search. Returns a list of (start, end)."""
    if not needle:
        return []
    haystack_lower = haystack.lower()
    needle_lower = needle.lower()
    matches = []
    start = 0
    while True:
        idx = haystack_lower.find(needle_lower, start)
        if idx < 0:
            break
        matches.append((idx, idx + len(needle)))
        start = idx + len(needle)
    return matches


def _paint_highlights(text_area, spans):
    highlighter = text_area.getHighlighter()
    highlighter.removeAllHighlights()
    painter = DefaultHighlighter.DefaultHighlightPainter(_MATCH_COLOR)
    for start, end in spans:
        try:
            highlighter.addHighlight(start, end, painter)
        except Exception:
            pass


class _DocChangeListener(DocumentListener):
    """Fires the same handler on any edit -- see insertion_point_panel's
    _FilterListener for the same pattern."""

    def __init__(self, handler):
        self.handler = handler

    def insertUpdate(self, event):
        self.handler()

    def removeUpdate(self, event):
        self.handler()

    def changedUpdate(self, event):
        self.handler()


class _AddSelectionAction(ActionListener):
    def __init__(self, selected_text, side_label, on_add):
        self.selected_text = selected_text
        self.side_label = side_label
        self.on_add = on_add

    def actionPerformed(self, event):
        self.on_add(self.selected_text, self.side_label)


class _SelectionPopupListener(MouseAdapter):
    """Attached to every text area in this tab (source + each decode
    result) -- there's no Burp IContextMenuFactory hook for plain third-
    party Swing components, so the right-click menu has to be built by
    hand here rather than reusing context_menu.py's mechanism."""

    def __init__(self, text_area, on_add):
        self.text_area = text_area
        self.on_add = on_add

    def mousePressed(self, event):
        self._maybe_show(event)

    def mouseReleased(self, event):
        self._maybe_show(event)

    def _maybe_show(self, event):
        if not event.isPopupTrigger():
            return
        selected = self.text_area.getSelectedText()
        if not selected:
            return
        menu = JPopupMenu()
        for side_label in ("Request", "Response"):
            item = JMenuItem(u"Add selection to Match & Replace → %s Before" % side_label)
            item.addActionListener(_AddSelectionAction(selected, side_label, self.on_add))
            menu.add(item)
        menu.show(event.getComponent(), event.getX(), event.getY())


class _TransformToggleListener(ActionListener):
    def __init__(self, panel, label, checkbox):
        self.panel = panel
        self.label = label
        self.checkbox = checkbox

    def actionPerformed(self, event):
        self.panel._on_transform_toggle(self.label, self.checkbox)


class DecodePanel(JPanel):
    def __init__(self, request_replace_store, response_replace_store, on_replace_added=None, log_fn=None):
        JPanel.__init__(self, BorderLayout())
        self.request_replace_store = request_replace_store
        self.response_replace_store = response_replace_store
        self.on_replace_added = on_replace_added
        self.log_fn = log_fn
        self._current_results = []
        self._source_matches = []
        self._source_match_index = -1
        # Start focused on the common case.  The All button still enables
        # every transform when a broader inspection is wanted.
        self.enabled_transforms = set(["URL Decode"])

        self.add(self._build_transform_toggle_row(), BorderLayout.NORTH)

        left = JPanel(BorderLayout())
        left_header = JPanel()
        left_header.setLayout(BoxLayout(left_header, BoxLayout.Y_AXIS))
        left_header.add(JLabel("Selected text:"))
        left_header.add(self._build_source_search_row())
        left.add(left_header, BorderLayout.NORTH)
        self.source_area = _make_wrapping_area(True, rows=10)
        self._attach_selection_popup(self.source_area)
        left.add(JScrollPane(self.source_area), BorderLayout.CENTER)
        self.decode_button = JButton("Decode", actionPerformed=self._on_decode_clicked)
        left.add(self.decode_button, BorderLayout.SOUTH)

        right = JPanel(BorderLayout())
        right.add(self._build_results_search_row(), BorderLayout.NORTH)
        self.results_container = JPanel(GridBagLayout())
        results_scroll = JScrollPane(self.results_container)
        results_scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER)
        results_scroll.getVerticalScrollBar().setUnitIncrement(16)
        right.add(results_scroll, BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right)
        split.setResizeWeight(0.5)
        self.add(split, BorderLayout.CENTER)

        self._render_results()

    def _build_transform_toggle_row(self):
        outer = JPanel(BorderLayout())
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        header.add(JLabel("Transforms to show (default: URL Decode only -- tick others as needed):"))
        header.add(JButton("All", actionPerformed=self._on_select_all_transforms))
        header.add(JButton("None", actionPerformed=self._on_select_none_transforms))
        outer.add(header, BorderLayout.NORTH)

        checks_row = JPanel(FlowLayout(FlowLayout.LEFT))
        self.transform_checkboxes = {}
        for label in decode_engine.TRANSFORM_LABELS:
            cb = JCheckBox(label, label == "URL Decode")
            cb.addActionListener(_TransformToggleListener(self, label, cb))
            checks_row.add(cb)
            self.transform_checkboxes[label] = cb
        outer.add(checks_row, BorderLayout.CENTER)
        return outer

    def _on_transform_toggle(self, label, checkbox):
        if checkbox.isSelected():
            self.enabled_transforms.add(label)
        else:
            self.enabled_transforms.discard(label)
        self._run_decode()

    def _on_select_all_transforms(self, event):
        for label, cb in self.transform_checkboxes.items():
            cb.setSelected(True)
        self.enabled_transforms = set(decode_engine.TRANSFORM_LABELS)
        self._run_decode()

    def _on_select_none_transforms(self, event):
        for cb in self.transform_checkboxes.values():
            cb.setSelected(False)
        self.enabled_transforms = set()
        self._run_decode()

    def _build_source_search_row(self):
        row = JPanel(FlowLayout(FlowLayout.LEFT))
        row.add(JLabel("Find:"))
        self.source_search_field = JTextField(16, actionPerformed=self._on_source_search_next)
        self.source_search_field.getDocument().addDocumentListener(
            _DocChangeListener(self._on_source_search_changed))
        row.add(self.source_search_field)
        row.add(JButton(u"◀", actionPerformed=self._on_source_search_prev))
        row.add(JButton(u"▶", actionPerformed=self._on_source_search_next))
        self.source_match_label = JLabel("")
        row.add(self.source_match_label)
        return row

    def _build_results_search_row(self):
        row = JPanel(FlowLayout(FlowLayout.LEFT))
        row.add(JLabel("Find in results:"))
        self.results_search_field = JTextField(16)
        self.results_search_field.getDocument().addDocumentListener(
            _DocChangeListener(self._on_results_search_changed))
        row.add(self.results_search_field)
        self.results_match_label = JLabel("")
        row.add(self.results_match_label)
        return row

    # ---- right-click: send a selection (source or any result) to Match & Replace ----

    def _attach_selection_popup(self, text_area):
        text_area.addMouseListener(_SelectionPopupListener(text_area, self._on_add_selection_to_replace))

    def _on_add_selection_to_replace(self, selected_text, side_label):
        rule_store = self.request_replace_store if side_label == "Request" else self.response_replace_store
        rule_store.add_rule(before=selected_text, after=u"", enabled=True, is_regex=False)
        if self.on_replace_added:
            self.on_replace_added()
        if self.log_fn:
            preview = selected_text if len(selected_text) <= 60 else selected_text[:57] + u"..."
            self.log_fn(u"Match & Replace: added Decode-tab selection to %s Before list: %s"
                         % (side_label, preview))

    # ---- left side: source text + find/highlight/step ----

    def set_text(self, text):
        """Called from the right-click 'Send selection to Decode' action."""
        self.source_area.setText(text or u"")
        self.source_area.setCaretPosition(0)
        self.source_search_field.setText("")
        self._run_decode()

    def _on_decode_clicked(self, event):
        self._run_decode()

    def _run_decode(self):
        text = self.source_area.getText()
        self._current_results = (decode_engine.run_all(text, enabled_labels=self.enabled_transforms)
                                  if text else [])
        self._on_source_search_changed()
        self._render_results()

    def _on_source_search_changed(self, event=None):
        query = self.source_search_field.getText()
        self._source_matches = _find_all(self.source_area.getText(), query)
        self._source_match_index = -1
        _paint_highlights(self.source_area, self._source_matches)
        if self._source_matches:
            self._goto_source_match(0)
        else:
            self._update_source_match_label()

    def _goto_source_match(self, index):
        if not self._source_matches:
            return
        index = index % len(self._source_matches)
        self._source_match_index = index
        start, end = self._source_matches[index]
        self.source_area.setCaretPosition(start)
        self.source_area.moveCaretPosition(end)
        self._update_source_match_label()

    def _update_source_match_label(self):
        if not self.source_search_field.getText():
            self.source_match_label.setText("")
        elif not self._source_matches:
            self.source_match_label.setText("0 matches")
        else:
            self.source_match_label.setText("%d / %d" % (self._source_match_index + 1, len(self._source_matches)))

    def _on_source_search_next(self, event):
        if self._source_matches:
            self._goto_source_match(self._source_match_index + 1)

    def _on_source_search_prev(self, event):
        if self._source_matches:
            self._goto_source_match(self._source_match_index - 1)

    # ---- right side: decode results + find/highlight/filter ----

    def _on_results_search_changed(self, event=None):
        self._render_results()

    def _render_results(self):
        query = self.results_search_field.getText() if hasattr(self, 'results_search_field') else u""

        self.results_container.removeAll()
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        gbc.insets = Insets(3, 3, 3, 3)

        row = 0
        shown = 0
        if not self._current_results:
            gbc.gridy = row
            gbc.weighty = 1.0
            gbc.anchor = GridBagConstraints.NORTH
            if self.source_area.getText() and not self.enabled_transforms:
                message = "No transforms selected -- tick at least one above, or click \"All\"."
            else:
                message = _PLACEHOLDER
            placeholder = JLabel("<html><body style='width: 260px'>%s</body></html>" % message)
            self.results_container.add(placeholder, gbc)
            row += 1
        else:
            for result in self._current_results:
                matches = _find_all(result.text, query) if result.ok() and result.text else []
                if query and not matches:
                    continue
                shown += 1
                block = JPanel(BorderLayout())
                block.setBorder(BorderFactory.createTitledBorder(result.label))
                if result.ok():
                    area = _make_wrapping_area(False, rows=3)
                    area.setText(result.text)
                    area.setCaretPosition(0)
                    self._attach_selection_popup(area)
                    if matches:
                        _paint_highlights(area, matches)
                    block.add(area, BorderLayout.CENTER)
                else:
                    block.add(JLabel("  (not applicable: %s)" % result.error), BorderLayout.CENTER)
                gbc.gridy = row
                gbc.weighty = 0.0
                self.results_container.add(block, gbc)
                row += 1

            if shown == 0:
                gbc.gridy = row
                gbc.weighty = 1.0
                gbc.anchor = GridBagConstraints.NORTH
                self.results_container.add(JLabel("  No transform's result contains \"%s\"." % query), gbc)
                row += 1

            filler = JPanel()
            gbc.gridy = row
            gbc.weighty = 1.0
            self.results_container.add(filler, gbc)

        self._update_results_match_label(shown, len(self._current_results), query)
        self.results_container.revalidate()
        self.results_container.repaint()

    def _update_results_match_label(self, shown, total, query):
        if not query or not total:
            self.results_match_label.setText("")
        else:
            self.results_match_label.setText("%d / %d transforms match" % (shown, total))
