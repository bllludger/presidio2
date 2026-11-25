"""NLP engine package. Performs text pre-processing."""

from .device_detector import device_detector
from .ner_model_configuration import NerModelConfiguration
from .nlp_artifacts import NlpArtifacts
from .nlp_engine import NlpEngine
from .no_op_nlp_engine import NoOpNlpEngine

from .nlp_engine_provider import NlpEngineProvider  # isort:skip

__all__ = [
    "device_detector",
    "NerModelConfiguration",
    "NlpArtifacts",
    "NlpEngine",
    "NoOpNlpEngine",
    "SlimSpacyNlpEngine",
    "SpacyNlpEngine",
    "StanzaNlpEngine",
    "NlpEngineProvider",
    "TransformersNlpEngine",
]


_LAZY_ENGINES = {
    "SlimSpacyNlpEngine": "slim_spacy_nlp_engine",
    "SpacyNlpEngine": "spacy_nlp_engine",
    "StanzaNlpEngine": "stanza_nlp_engine",
    "TransformersNlpEngine": "transformers_nlp_engine",
}


def __getattr__(name):
    if name not in _LAZY_ENGINES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module("." + _LAZY_ENGINES[name], __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_ENGINES))
