"""CWE-502: Deserialization of Untrusted Data in Python
Uses pickle/yaml.load on untrusted input."""

import pickle
import sys
import base64


def load_session(data_b64):
    """Unsafe deserialization via pickle."""
    raw = base64.b64decode(data_b64)
    session = pickle.loads(raw)
    return session


def process_message(raw_bytes):
    """Unsafe deserialization from network data."""
    msg = pickle.loads(raw_bytes)
    return msg.get("action"), msg.get("payload")


def load_config_yaml(path):
    """Unsafe YAML load (yaml.load without SafeLoader)."""
    try:
        import yaml
        with open(path, "r") as f:
            return yaml.load(f, Loader=yaml.FullLoader)
    except ImportError:
        return None


def cache_get(key):
    """Loads pickled cache entry from file."""
    try:
        with open(f"/tmp/cache/{key}.pkl", "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None


def main():
    if len(sys.argv) > 1:
        session = load_session(sys.argv[1])
        print(f"Session: {session}")


if __name__ == "__main__":
    main()
