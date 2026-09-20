"""Inference preprocessing compatible with the SecureMail training notebooks."""

from __future__ import annotations

import numpy as np
import pandas as pd


TEXT_COLUMNS = ("Subject", "Body", "Concatenated_URLs")
CATEGORICAL_COLUMNS = ("From", "To")
TIME_COLUMN = "Hour_temp"
MISSING_VALUE = "No Data"
HASH_PREFIX = "col_"


def build_model_text(email_data: object, separator: str = "[SEP]") -> str:
    """Build text in the same order and format used during training."""
    values = [
        str(getattr(email_data, "Subject", MISSING_VALUE)),
        str(getattr(email_data, "Body", MISSING_VALUE)),
        str(getattr(email_data, "Concatenated_URLs", MISSING_VALUE)),
    ]
    return f" {separator} ".join(values)


def transform_additional_features(
    email_data: object,
    label_encoders: dict[str, object],
    scaler: object,
) -> np.ndarray:
    """Apply the trained HashingEncoder and Hour_temp transformation."""
    frame = pd.DataFrame(
        {
            "From": [getattr(email_data, "From", MISSING_VALUE)],
            "To": [getattr(email_data, "To", MISSING_VALUE)],
            "Date": [getattr(email_data, "Date", MISSING_VALUE)],
        }
    )
    parsed_date = pd.to_datetime(frame["Date"], errors="coerce", utc=True)
    frame[TIME_COLUMN] = parsed_date.dt.hour.astype(float).fillna(0)

    hasher = label_encoders["feature_hasher"]
    columns_to_hash = [column for column in CATEGORICAL_COLUMNS if column in frame]
    categorical_frame = frame[columns_to_hash].astype(str).fillna(MISSING_VALUE)
    hashed = hasher.transform(categorical_frame)
    hashed_values = hashed.values.astype(float)

    expected_hash_columns = [
        name for name in scaler.feature_names_in_ if str(name).startswith(HASH_PREFIX)
    ]
    if hashed_values.shape[1] != len(expected_hash_columns):
        raise ValueError(
            "The HashingEncoder output does not match the trained scaler: "
            f"got {hashed_values.shape[1]} columns, expected {len(expected_hash_columns)}."
        )

    features = np.hstack([hashed_values, frame[[TIME_COLUMN]].values.astype(float)])
    if features.shape[1] != len(scaler.feature_names_in_):
        raise ValueError(
            "The additional feature count does not match the trained scaler: "
            f"got {features.shape[1]}, expected {len(scaler.feature_names_in_)}."
        )
    return scaler.transform(features).astype(np.float32)
