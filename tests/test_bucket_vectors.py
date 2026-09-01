"""The published bucketing vectors. The JSON field is named deviceID because the backend
hashes device IDs; this SDK feeds its caller's context key through the same algorithm —
the rename happens here, keeping the vendored file verbatim. A failure here flips real
users between cohorts.
"""

import json
from importlib import resources
from typing import Any

import pytest

from fortressflag._bucket import bucket

_FILE: Any = json.loads(
    resources.files("fortressflag._vectors").joinpath("buckets.json").read_text()
)
_VECTORS: list[dict[str, Any]] = _FILE["vectors"]


def test_the_vector_file_is_not_empty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize(
    "vector", _VECTORS, ids=[f"{v['deviceID']}/{v['flagKey']}" for v in _VECTORS]
)
def test_bucket_vector(vector: dict[str, Any]) -> None:
    assert bucket(vector["deviceID"], vector["flagKey"]) == vector["bucket"]
