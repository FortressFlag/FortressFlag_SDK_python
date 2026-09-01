"""The published evaluation vectors, run through THIS SDK's production decoder and
evaluator — the whole point of publishing them in the export's wire shape. A failure here
is a wire-contract bug, never a test to fix (src/fortressflag/_vectors/README.md).
"""

import json
from importlib import resources
from typing import Any

import pytest

from fortressflag._evaluate import evaluate_flag
from fortressflag._ruleset import parse_flag_config

_FILE: Any = json.loads(
    resources.files("fortressflag._vectors").joinpath("evaluation.json").read_text()
)
_VECTORS: list[dict[str, Any]] = _FILE["vectors"]


def test_the_vector_file_is_not_empty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_evaluation_vector(vector: dict[str, Any]) -> None:
    config = parse_flag_config(vector["flag"])
    assert config is not None, "the vector's flag config must parse through the production decoder"
    value, ok = evaluate_flag(
        config,
        vector["input"]["tags"],
        vector["input"]["contextKey"],
        vector["input"]["flagKey"],
    )
    if vector["expected"].get("noValue"):
        assert ok is False
    else:
        assert ok is True
        expected = vector["expected"]["value"]
        if isinstance(expected, bool):
            assert value is expected
        elif isinstance(expected, (int, float)):
            assert value == float(expected)
        else:
            assert value == expected
