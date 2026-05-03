import logging
import json
from datetime import datetime, timezone
import os

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "msg": record.getMessage()
        }
        if hasattr(record, 'extra_data') and isinstance(record.extra_data, dict):
            log_obj.update(record.extra_data)
        return json.dumps(log_obj)

def get_logger(name="waechter"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

        level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, level_str, logging.INFO))
    return logger

