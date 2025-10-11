import logging
import sys
import time

DEFAULT_LOGGER_NAME = "email-feeder"
DEFAULT_LOG_FILE = "application.log"


def setup_logging(
    logger_name: str = DEFAULT_LOGGER_NAME,
    log_file: str = DEFAULT_LOG_FILE,
    file_log_level: int = logging.INFO,
    console_log_level: int = logging.ERROR,
    log_to_console: bool = True,
    log_to_file: bool = True,
) -> logging.Logger:
    """
    Configures and returns a logger instance.

    This function sets up a logger with a specified name, file handler,
    and console (stdout) handler. It allows customization of log levels
    for both handlers.

    Args:
        logger_name: The name for the logger.
        log_file: The path to the log file.
        file_log_level: The logging level for the file handler (e.g., logging.INFO, logging.DEBUG).
        console_log_level: The logging level for the console handler.
        log_to_console: Whether to enable console logging.
        log_to_file: Whether to enable file logging.

    Returns:
        A configured logging.Logger instance.
    """
    logger = logging.getLogger(logger_name)

    logger.setLevel(
        min(file_log_level, console_log_level)
        if log_to_file and log_to_console
        else (
            file_log_level
            if log_to_file
            else console_log_level
            if log_to_console
            else logging.WARNING
        )
    )

    if logger.hasHandlers():
        logger.handlers.clear()

    log_formatter = logging.Formatter(
        fmt="%(asctime)s UTC %(name)s %(levelname)s %(message)s",
        datefmt="%d/%m/%Y %H:%M:%S",
    )
    log_formatter.converter = time.gmtime

    if log_to_file:
        try:
            file_handler = logging.FileHandler(
                filename=log_file, mode="a", encoding="utf-8"
            )
            file_handler.setLevel(file_log_level)
            file_handler.setFormatter(log_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(
                f"Error setting up file logger at {log_file}: {e}. Logging to console instead.",
                file=sys.stderr,
            )
            if not log_to_console:
                log_to_console = True
                console_log_level = logging.INFO

    if log_to_console:
        stdout_handler = logging.StreamHandler(stream=sys.stdout)
        stdout_handler.setLevel(console_log_level)
        stdout_handler.setFormatter(log_formatter)
        logger.addHandler(stdout_handler)

    if not log_to_file and not log_to_console:
        logger.addHandler(logging.NullHandler())
        print(
            f"Warning: Logger '{logger_name}' has no handlers configured (file or console).",
            file=sys.stderr,
        )

    return logger


def get_logger(logger_name: str = DEFAULT_LOGGER_NAME) -> logging.Logger:
    """
    Retrieves a logger instance by name.
    It's generally recommended to call setup_logging once at the start
    of your application, and then use getLogger wherever you need it.
    """
    return logging.getLogger(logger_name)
