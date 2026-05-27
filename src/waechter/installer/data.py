from __future__ import annotations

import logging
import shutil
from pathlib import Path

from waechter.installer.models import InstallerConfig

logger = logging.getLogger(__name__)


def ensure_data_and_config(config: InstallerConfig) -> None:
    """
    Ensures that default configuration and data files exist.
    Uses .example files as templates to avoid overwriting user changes during updates.
    """
    logger.info("Ensuring data and configuration files exist")
    
    # 1. Configuration
    cfg_file = config.app_dir / "config" / "waechter.yaml"
    _ensure_from_example(cfg_file)
    
    # 2. Heuristic Data
    data_dir = config.app_dir / "data" / "keywords" / "heuristic"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    for filename in ["brand_keywords.csv", "brand_domains.csv", "path_keywords.csv", "url_keywords.csv"]:
        _ensure_from_example(data_dir / filename)


def _ensure_from_example(target: Path) -> None:
    if target.exists():
        logger.debug("File already exists: %s", target)
        return
        
    example = target.with_suffix(target.suffix + ".example")
    if example.exists():
        logger.info("Creating %s from template %s", target, example)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(example, target)
    else:
        logger.warning("No template found for %s (expected %s)", target, example)
