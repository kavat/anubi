import config
import logging
import sys

class AnubiLogger:

  def __init__(self, nome_log, path_log, log_std, log_level):
    self.path_log = path_log
    self.nome_log = nome_log
    self.log_std = log_std
    self.logger = logging.getLogger(self.nome_log)
    self.logger.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(log_level)
    stdout_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(self.path_log)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    self.logger.addHandler(file_handler)
    if self.log_std == True:
      self.logger.addHandler(stdout_handler)

  def wipe(self):
    file_handler = logging.FileHandler(self.path_log, 'w')
    self.logger.addHandler(file_handler)

  def get_logger(self):
    return self.logger 

  def set_level(self, log_level):
    level = False
    if log_level == "debug":
      level = logging.DEBUG
    if log_level == "info":
      level = logging.INFO
    if log_level == "warn":
      level = logging.WARN
    if log_level == "error":
      level = logging.ERROR
    if log_level == "critical":
      level = logging.CRITICAL
    if level != False:
      self.logger.setLevel(level)
      for handler in self.logger.handlers:
        handler.setLevel(level)
