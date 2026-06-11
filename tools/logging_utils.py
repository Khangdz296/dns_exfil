"""
Shared logging setup for pipeline tools.

Each tool logs to both the console and data/output/pipeline.log so Pi runs and
manual CLI runs leave an execution trail for demos and reports.
"""

import logging
from pathlib import Path

LOG_PATH = Path("data/output/pipeline.log")
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_pipeline_logger(name: str) -> logging.Logger:
    """Return a logger configured for console and shared pipeline file output."""
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
