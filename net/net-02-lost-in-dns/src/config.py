"""Application configuration for NET-02 — Lost in DNS.

Environment variables are validated at startup. Values are never printed, and
there is no fallback flag: a missing flag is a fatal configuration error.
"""

import logging
import os

DEFAULT_PORT = 8080
DEFAULT_CAPTURE_PATH = "/app/runtime/capture.pcap"
DEFAULT_LOG_LEVEL = "INFO"

LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class ConfigError(RuntimeError):
    """Raised when the runtime configuration is unusable."""


class Config:
    def __init__(self, flag, port, capture_path, log_level):
        self.flag = flag
        self.port = port
        self.capture_path = capture_path
        self.log_level = log_level

    def __repr__(self):  # never include the flag
        return (
            f"Config(port={self.port}, capture_path={self.capture_path!r}, "
            f"log_level={self.log_level!r})"
        )


def load_config(environ=None, require_flag=True):
    """Build a validated configuration from the environment."""
    environ = os.environ if environ is None else environ

    flag = environ.get("GZCTF_FLAG")
    if require_flag:
        if flag is None or flag.strip() == "":
            raise ConfigError("GZCTF_FLAG is missing or empty; refusing to start")
    elif flag is not None and flag.strip() == "":
        flag = None

    raw_port = environ.get("PORT", str(DEFAULT_PORT))
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as error:
        raise ConfigError("PORT must be an integer") from error

    if not 1 <= port <= 65535:
        raise ConfigError("PORT must be between 1 and 65535")

    capture_path = environ.get("PCAP_PATH") or DEFAULT_CAPTURE_PATH
    log_level = (environ.get("LOG_LEVEL") or DEFAULT_LOG_LEVEL).upper()

    if log_level not in LOG_LEVELS:
        raise ConfigError("LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL")

    return Config(flag=flag, port=port, capture_path=capture_path, log_level=log_level)


def configure_logging(level_name):
    logging.basicConfig(
        level=getattr(logging, level_name, logging.INFO),
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
