import logging
import os


LOG_DIRECTORY = "reports"
LOG_FILE = os.path.join(LOG_DIRECTORY, "vapt.log")


def setup_logger():
    os.makedirs(LOG_DIRECTORY, exist_ok=True)

    logger = logging.getLogger("NEXUS-VAPT")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s"
    )

    # File Handler
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger
