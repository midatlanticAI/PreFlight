# Positive fixture for PY-DESERIALIZE-001 (XL-001 Unsafe Deserialization).
# Every line below MUST be flagged by the adapter.

import pickle
import yaml
import torch
import joblib
import pandas as pd


def load_from_request(request):
    # pickle on a request body is remote code execution
    return pickle.loads(request.data)


def load_config(stream):
    # yaml.load with no safe loader constructs arbitrary objects
    return yaml.load(stream)


def load_model(path):
    # explicit weights_only=False defeats the PyTorch 2.6 safe default
    return torch.load(path, weights_only=False)


def load_artifact(path):
    return joblib.load(path)


def load_frame(path):
    return pd.read_pickle(path)
