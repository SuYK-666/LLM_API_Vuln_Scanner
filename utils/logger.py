from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional


def setup_run_logger(log_dir: str = "logs", level: int = logging.DEBUG) -> str:
    """Create one timestamped log file per run and configure root logger."""
    log_root = Path(log_dir)
    log_root.mkdir(parents=True, exist_ok=True)

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_root / f"run_{run_ts}.log"

    root = logging.getLogger()
    root.setLevel(level)

    # Reset handlers so each run writes to a new file cleanly.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_fmt)

    root.addHandler(file_handler)
    root.addHandler(console_handler)

    logging.getLogger(__name__).info("Run logger initialized at %s", log_path)
    return str(log_path)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name if name else __name__)
