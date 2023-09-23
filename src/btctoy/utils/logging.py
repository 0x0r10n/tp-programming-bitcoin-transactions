import os
from enum import (
    Enum,
)

# Ignoring type errors here because our logging.py seems to hide std logging
from logging import Formatter as BaseFormatter  # type: ignore
from logging import Logger  # type: ignore
from logging import LogRecord  # type: ignore
from logging import StreamHandler  # type: ignore
from logging import getLogger  # type: ignore # noqa: N813
from pathlib import (
    Path,
)
from typing import (
    Optional,
    Union,
)

import colorama
from colorama import (
    Fore,
)


def _get_root_path() -> Path:
    current = Path(__file__)
    while current.name != "src":
        current = current.parent
    return current.parent


MODULE_PATH = _get_root_path()


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


COLORS = {
    LogLevel.DEBUG.value: Fore.CYAN,
    LogLevel.INFO.value: Fore.BLUE,
    LogLevel.WARNING.value: Fore.YELLOW,
    LogLevel.ERROR.value: Fore.RED,
}

colorama.init()


def set_level(level: LogLevel, *loggers: Union[str, Logger]) -> None:
    import logging

    level_code = getattr(logging, level)
    for logger in loggers:
        if isinstance(logger, str):
            logger = get_logger(logger)
        logger.setLevel(level_code)


class Formatter(BaseFormatter):
    def format(self, record: LogRecord) -> str:  # noqa: A003
        """
        The role of this custom formatter is:
        - append filepath and lineno to logging format but shorten path to files, to make logs more clear
        - to append "./" at the begining to permit going to the line quickly with VS Code CTRL+click from terminal
        """
        try:
            relpathname = (
                f"{os.curdir}{os.sep}{Path(record.pathname).relative_to(MODULE_PATH)}"
            )
        except Exception:  # pragma: no cover
            relpathname = record.pathname
        record.asctime = self.formatTime(record, self.datefmt)
        message = super().format(
            record
        )  # note: format() injects important fields to record + append exec and stack info
        return (
            f"{COLORS[record.levelname]}{record.asctime} {record.levelname[0]}{Fore.RESET} {message} "
            f"{COLORS[record.levelname]}({record.name} {record.threadName} {record.processName} {relpathname}:{record.lineno}){Fore.RESET}"
        )


STREAM_HANDLER = StreamHandler()
STREAM_HANDLER.setFormatter(Formatter())


def init_logging(
    level: LogLevel,
    *root_loggers: Union[str, Logger],
) -> None:
    if len(root_loggers) == 0:
        raise ValueError("Specify at least one root logger to initialize")

    for root_logger in root_loggers:
        if isinstance(root_logger, str):
            root_logger = get_logger(root_logger)

        root_logger.removeHandler(STREAM_HANDLER)
        root_logger.addHandler(STREAM_HANDLER)
        set_level(level, root_logger)

        root_logger.debug(
            f"Logging initialized with level {level.value} for root logger {root_logger.name}",
        )


def get_logger(name: Optional[str] = None) -> Logger:
    if name is not None:
        return getLogger(name)

    import inspect

    frm = inspect.stack()[1]
    mod = inspect.getmodule(frm[0])
    if mod is None:
        raise RuntimeError("Unable to get module of caller")  # pragma: no cover
    if mod.__name__ == "__main__":
        return getLogger(f"{mod.__package__}.__main__")  # pragma: no cover
    else:
        return getLogger(mod.__name__)
