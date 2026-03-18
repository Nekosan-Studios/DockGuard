import os
from typing import Any

from sqlmodel import Session

from backend.models import Setting


class ConfigManager:
    """Manages application settings, combining environment variables and database values."""

    # Default values for settings that can be configured via UI
    DEFAULTS = {
        "SCAN_INTERVAL_SECONDS": "60",
        "MAX_CONCURRENT_SCANS": "1",
        "DB_CHECK_INTERVAL_SECONDS": "3600",
        "DATA_RETENTION_DAYS": "30",
        "DAILY_DIGEST_HOUR": "8",
        "BASE_URL": "",
        "REGISTRY_CHECK_INTERVAL_SECONDS": "86400",
    }

    @staticmethod
    def get_setting(key: str, db_session: Session) -> dict[str, Any]:
        """
        Gets a setting by key. Looks in environment variables first, then database, then defaults.
        Returns a dictionary with the value, source, and whether it's editable in the UI.
        """
        # 1. Check environment variable (highest priority)
        env_val = os.environ.get(key)
        if env_val is not None:
            return {"key": key, "value": str(env_val), "source": "env", "editable": False}

        # 2. Check database
        db_setting = db_session.get(Setting, key)
        if db_setting is not None:
            return {"key": key, "value": db_setting.value, "source": "db", "editable": True}

        # 3. Fallback to default
        default_val = ConfigManager.DEFAULTS.get(key)
        if default_val is not None:
            return {"key": key, "value": default_val, "source": "default", "editable": True}

        # 4. Unknown setting
        return {"key": key, "value": None, "source": "unknown", "editable": False}

    @staticmethod
    def get_all_settings(db_session: Session) -> dict[str, dict[str, Any]]:
        """Returns all configurable settings."""
        settings = {}
        for key in ConfigManager.DEFAULTS.keys():
            settings[key] = ConfigManager.get_setting(key, db_session)
        return settings

    @staticmethod
    def set_setting(key: str, value: str, db_session: Session) -> bool:
        """
        Updates a setting in the database.
        Returns True if successful, False if the setting is driven by an environment variable.
        Raises KeyError if the setting key is unknown.
        """
        if key not in ConfigManager.DEFAULTS:
            raise KeyError(f"Unknown setting: {key}")

        current = ConfigManager.get_setting(key, db_session)
        if not current["editable"]:
            return False  # Cannot override an environment variable

        db_setting = db_session.get(Setting, key)
        if value == ConfigManager.DEFAULTS[key]:
            # Value matches the default — remove any DB override so source reverts to "default"
            if db_setting:
                db_session.delete(db_setting)
                db_session.commit()
            return True

        if db_setting:
            db_setting.value = value
        else:
            db_setting = Setting(key=key, value=value)
            db_session.add(db_setting)

        db_session.commit()
        return True
