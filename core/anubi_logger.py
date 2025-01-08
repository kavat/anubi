import config
import logging
import sys
import os

from core.common import current_datetime

class AnubiLogger:

  def __init__(self, nome_log, path_log, log_std=True, log_level="INFO"):
    self.nome_log = nome_log
    self.path_log = self._prepare_log_path(path_log)
    self.log_std = log_std
    self.logger = logging.getLogger(nome_log)
    self._configure_logger(log_level)

  def _prepare_log_path(self, path_log):
    dir_path = os.path.dirname(path_log)
    if dir_path and not os.path.exists(dir_path):
      os.makedirs(dir_path, exist_ok=True)
    return path_log

  def _configure_logger(self, log_level):
    self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    file_handler = logging.FileHandler(self.path_log)
    file_handler.setFormatter(self._get_formatter())
    self.logger.addHandler(file_handler)

    if self.log_std:
      console_handler = logging.StreamHandler(sys.stdout)
      console_handler.setFormatter(self._get_formatter())
      self.logger.addHandler(console_handler)

  def _get_formatter(self):
    return logging.Formatter(
      fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
      datefmt="%Y-%m-%d %H:%M:%S"
    )

  def set_level(self, log_level):
    self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

  def wipe(self):
    open(self.path_log, "w").close()

  def debug(self, msg):
    self.logger.debug(msg)

  def info(self, msg):
    self.logger.info(msg)

  def warning(self, msg):
    self.logger.warning(msg)

  def error(self, msg):
    self.logger.error(msg)

  def critical(self, msg):
    self.logger.critical(msg)

  def exception(self, msg):
    self.logger.exception(msg, exc_info=True)

  def get_logger(self):
    return self.logger
