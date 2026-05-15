# Negative fixture for PY-DESERIALIZE-001. NONE of these lines should fire.
# The safe alternatives the remediation points at.

import json
import yaml
import torch
from safetensors.torch import load_file


def load_from_request(request):
    # JSON for data, not pickle
    return json.loads(request.data)


def load_config(stream):
    # safe loader: no arbitrary object construction
    return yaml.safe_load(stream)


def load_config_explicit(stream):
    # explicit SafeLoader is also fine
    return yaml.load(stream, Loader=yaml.SafeLoader)


def load_model(path):
    # weights_only=True is the safe path (and the 2.6+ default)
    return torch.load(path, weights_only=True)


def load_weights(path):
    # safetensors cannot execute code on load
    return load_file(path)
