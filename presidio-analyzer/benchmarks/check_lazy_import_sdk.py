import importlib
import pickle
import sys
from typing import get_type_hints, List
from unittest.mock import patch
import presidio_analyzer.nlp_engine as nlp

assert "spacy" not in sys.modules
assert set(nlp.__all__) <= set(dir(nlp))
try:
    nlp.missing_engine
except AttributeError:
    pass
else:
    raise AssertionError("missing export accepted")
# Reflection imports genuine types on demand.
hints = get_type_hints(nlp.NlpArtifacts.__init__, localns={"NlpEngine": nlp.NlpEngine})
from spacy.tokens import Doc, Span
from presidio_analyzer.nlp_engine.nlp_artifacts import (
    Doc as LegacyDoc,
    Span as LegacySpan,
)

assert hints["tokens"] is Doc and hints["entities"] == List[Span]
assert LegacyDoc is Doc and LegacySpan is Span
for name, module in [
    ("SpacyNlpEngine", "spacy_nlp_engine"),
    ("SlimSpacyNlpEngine", "slim_spacy_nlp_engine"),
    ("StanzaNlpEngine", "stanza_nlp_engine"),
    ("TransformersNlpEngine", "transformers_nlp_engine"),
]:
    cls = getattr(nlp, name)
    assert cls is getattr(
        importlib.import_module("presidio_analyzer.nlp_engine." + module), name
    )
    assert pickle.loads(pickle.dumps(cls)) is cls
namespace = {}
exec("from presidio_analyzer.nlp_engine import *", namespace)
assert all(namespace[name] is getattr(nlp, name) for name in nlp.__all__)
conf = {"nlp_engine_name": "no_op", "models": [{"lang_code": "ru", "model_name": ""}]}
for engines in (None, (nlp.NoOpNlpEngine,)):
    engine = nlp.NlpEngineProvider(
        nlp_engines=engines, nlp_configuration=conf
    ).create_engine()
    artifacts = engine.process_text("fixture", "ru")
    assert isinstance(artifacts.tokens, Doc) and len(artifacts.tokens) == 0
    assert len(list(engine.process_batch(["a", "b"], "ru"))) == 2
import spacy

conf = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "fixture"}],
}
with (
    patch.object(nlp.SpacyNlpEngine, "_download_spacy_model_if_needed"),
    patch("spacy.load", return_value=spacy.blank("en")),
):
    engine = nlp.NlpEngineProvider(nlp_configuration=conf).create_engine()
    artifacts = engine.process_text("hello world", "en")
    assert isinstance(artifacts.tokens, Doc) and len(artifacts.tokens) == 2
from presidio_analyzer.recognizer_registry import RecognizerRegistry
from presidio_analyzer.predefined_recognizers import SpacyRecognizer

assert RecognizerRegistry.get_nlp_recognizer(engine) is SpacyRecognizer
print("SDK compatibility checks passed")
