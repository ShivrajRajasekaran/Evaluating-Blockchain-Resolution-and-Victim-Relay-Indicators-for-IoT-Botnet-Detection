"""
schema — the observation data model.

Import from here, not from the submodules, so the public surface stays small:

    from src.schema import columns as K
    from src.schema import (build_observations, validate_observations,
                            read_observations, write_observations, trainable)
"""
from . import columns
from .build import build_observations, make_observation_id
from .validate import (
    SchemaError,
    ValidationReport,
    assert_valid,
    read_observations,
    trainable,
    validate_observations,
    write_observations,
)

__all__ = [
    "columns",
    "build_observations",
    "make_observation_id",
    "SchemaError",
    "ValidationReport",
    "assert_valid",
    "read_observations",
    "trainable",
    "validate_observations",
    "write_observations",
]
