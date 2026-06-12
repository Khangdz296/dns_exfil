"""
Shared logging setup for pipeline tools.

Each tool logs to both the console and a timestamped file under logs/ so every
pipeline run leaves its own execution trail.
"""

import logging
import os
from datetime import datetime
from pathlib import Path

RUN_ID = f"{datetime.now():%Y%m%d_%H%M%S_%f}_{os.getpid()}"
LOG_PATH = Path("logs") / f"pipeline_{RUN_ID}.log"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_pipeline_logger(name: str) -> logging.Logger:
    """Return a logger configured for console and this run's log file."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
