"""Persisted local settings (VT API key, safe-mode default, VT rate limit)."""

import json
import os
from pathlib import Path

APP_DIR_NAME = "PhishAnalyzer"
CONFIG_FILENAME = "config.json"

DEFAULTS = {
    "vt_api_key": "",
    "safe_mode_default": True,
    "vt_requests_per_minute": 4,
}


def _config_dir():
    appdata = os.getenv("APPDATA")
    if appdata:
        return Path(appdata) / APP_DIR_NAME
    return Path.home() / ".config" / "phishanalyzer"


def _config_path():
    return _config_dir() / CONFIG_FILENAME


class ConfigManager:
    def __init__(self):
        self.path = _config_path()
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            for key in DEFAULTS:
                if key in loaded:
                    self.data[key] = loaded[key]
        except Exception:
            pass
        return self.data

    def save(self, **updates):
        self.data.update(updates)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    def get(self, key):
        return self.data.get(key, DEFAULTS.get(key))
