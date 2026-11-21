import pickle
import yaml


def load_config(text):
    # ruleid: unsafe-yaml-load
    return yaml.load(text)


def load_config_safe(text):
    # ok: unsafe-yaml-load
    return yaml.load(text, Loader=yaml.SafeLoader)


def load_config_safest(text):
    # ok: unsafe-yaml-load
    return yaml.safe_load(text)


def load_session(blob):
    # ruleid: pickle-loads
    return pickle.loads(blob)
