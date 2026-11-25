"""Resolve genuine spaCy types only when annotations are inspected."""

from importlib import import_module


def __getattr__(name):
    if name not in ("Doc", "Span"):
        raise AttributeError(name)
    return getattr(import_module("spacy.tokens"), name)
