# -*- coding: utf-8 -*-
"""Numeric comparators shared by Swing list tables."""

from java.util import Comparator


class NumericTextComparator(Comparator):
    """Compare numeric values and display text such as '-' naturally."""
    def compare(self, left, right):
        def key(value):
            try:
                return (0, int(str(value)))
            except (ValueError, TypeError):
                return (1, str(value))
        a = key(left)
        b = key(right)
        return (a > b) - (a < b)


class NumericSequenceComparator(Comparator):
    """Compare comma/slash-separated numeric lists as integer sequences."""
    def compare(self, left, right):
        def key(value):
            numbers = []
            for part in str(value).replace('/', ',').split(','):
                try:
                    numbers.append(int(part.strip()))
                except ValueError:
                    pass
            return numbers
        a = key(left)
        b = key(right)
        return (a > b) - (a < b)
