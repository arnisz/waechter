import os
import csv
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional at test time if not needed
    yaml = None  # lazy failure if actually used

logger = logging.getLogger(__name__)


def _project_root() -> Path:
    # src/waechter/ is two levels below the project root in editable installs.
    return Path(__file__).resolve().parents[2]


def _default_config_path() -> Path:
    return _project_root() / "config" / "waechter.yaml"


@lru_cache(maxsize=1)
def load_config() -> Dict[str, Any]:
    """Load YAML config once. If missing or invalid, return empty dict."""
    path_env = os.environ.get("WAECHTER_CONFIG")
    if path_env:
        cfg_path = Path(path_env)
    else:
        cfg_path = _default_config_path()

    if yaml is None:
        logger.warning("PyYAML not available; proceeding without external config")
        return {}

    if not cfg_path.exists():
        logger.info("Config file not found; using defaults", extra={"extra_data": {"path": str(cfg_path)}})
        return {}

    try:
        with cfg_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                logger.warning("Invalid config root; expected mapping, got %s", type(data))
                return {}
            return data
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("Failed to load config %s: %s", str(cfg_path), e)
        return {}


def cfg_get(path: str, default: Any = None) -> Any:
    """Get a value from the loaded config by dot path."""
    data = load_config()
    cur: Any = data
    for part in path.split('.'):  # simple traversal
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def provider_cfg(name: str) -> Dict[str, Any]:
    return cfg_get(f"providers.{name}", {}) or {}


def _keywords_dir() -> Path:
    # Allow base dir override via env, else relative to project root
    base = os.environ.get("WAECHTER_KEYWORDS_DIR")
    if base:
        return Path(base)
    return _project_root() / "data" / "keywords"


def _resolve_path(p: str | Path) -> Path:
    pth = Path(p)
    if pth.is_absolute():
        return pth
    # Try relative to project root first
    candidate = _project_root() / pth
    if candidate.exists():
        return candidate
    # Try relative to keywords dir (for convenience)
    return _keywords_dir() / pth


def _iter_rows(file_path: Path) -> Iterable[Dict[str, str]]:
    with file_path.open("r", encoding="utf-8") as f:
        # Support both header and simple one-column files; ignore comments and blanks
        # Detect if first non-comment line has a comma (CSV with headers) or not
        pos = f.tell()
        first_line = ""
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            first_line = s
            break
        f.seek(pos)

        if not first_line:
            return []  # empty file

        if ',' in first_line:
            reader = csv.DictReader((ln for ln in f if not ln.lstrip().startswith('#')))
            yield from ({k.strip(): (v.strip() if v is not None else v) for k, v in row.items()} for row in reader)
        else:
            # one value per line, expose under generic key 'value'
            for ln in f:
                s = ln.strip()
                if not s or s.startswith('#'):
                    continue
                yield {"value": s}


@lru_cache(maxsize=64)
def load_brand_keywords(file_path: str | Path) -> Dict[str, float]:
    p = _resolve_path(file_path)
    if not p.exists():
        logger.warning("Brand keywords CSV not found: %s", str(p))
        return {}
    kws: Dict[str, float] = {}
    try:
        for row in _iter_rows(p):
            key = (row.get('keyword') or row.get('brand') or row.get('value') or '').strip().lower()
            if not key:
                continue
            try:
                sc = float(row.get('score') or row.get('weight') or '0')
            except Exception:
                sc = 0.0
            if sc <= 0:
                continue
            kws[key] = max(kws.get(key, 0.0), sc)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("Failed to parse brand keywords %s: %s", str(p), e)
    return kws


@lru_cache(maxsize=64)
def load_keywords_list(file_path: str | Path) -> List[str]:
    p = _resolve_path(file_path)
    if not p.exists():
        logger.warning("Keyword CSV not found: %s", str(p))
        return []
    items: List[str] = []
    try:
        for row in _iter_rows(p):
            val = (row.get('path') or row.get('keyword') or row.get('value') or '').strip()
            if not val:
                continue
            items.append(val.lower())
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("Failed to parse keywords %s: %s", str(p), e)
    return items
