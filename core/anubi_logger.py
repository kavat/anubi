import config
import logging
import sys
import os

from core.common import current_datetime

class AnubiLogger:

  def __init__(self, nome_log, path_log, log_std, log_level):
    self.path_log = self.create_log_path(path_log)
    self.nome_log = nome_log
    self.log_std = log_std
    self.logger = self.forge_logger('a')
    if self.logger == False:
      sys.exit(1)
    self.level = log_level
    self.log_std = log_std
    
  def forge_logger(self, mode):
    if self.path_log != "":
      try:
        return open(self.path_log, mode)
      except Exception as e:
        print("Unable to return logger {}: {}".format(self.path_log, e))
    return False

  def create_log_path(self, path_log):
    if os.path.isdir(os.path.dirname(path_log)) == False:
      os.mkdir(os.path.dirname(path_log))
    return path_log

  def wipe(self):
    self.logger = self.forge_logger('w')

  def get_logger(self):
    return self 

  def set_level(self, log_level):
    self.level = log_level
    
  def debug(self, msg):
    if self.level == "debug" or self.level == "info" or self.level == "warning" or self.level == "error" or self.level == "critical" :
      self.write("{} - {} - debug - {}\n".format(current_datetime(), self.nome_log, msg))
    if self.log_std == True:
      self.to_stdout("{} - {} - debug - {}".format(current_datetime(), self.nome_log, msg))
      
  def info(self, msg):
    if self.level == "info" or self.level == "info" or self.level == "warning" or self.level == "error" or self.level == "critical":
      self.write("{} - {} - info - {}\n".format(current_datetime(), self.nome_log, msg))
    if self.log_std == True:
      self.to_stdout("{} - {} - info - {}".format(current_datetime(), self.nome_log, msg))
      
  def warning(self, msg):
    if self.level == "warning" or self.level == "error" or self.level == "critical":
      self.write("{} - {} - warning - {}\n".format(current_datetime(), self.nome_log, msg))
    if self.log_std == True:
      self.to_stdout("{} - {} - warning - {}".format(current_datetime(), self.nome_log, msg))
      
  def warn(self, msg):
    self.warning(msg)
    
  def error(self, msg):
    if self.level == "error" or self.level == "critical":
      self.write("{} - {} - error - {}\n".format(current_datetime(), self.nome_log, msg))
    if self.log_std == True:
      self.to_stdout("{} - {} - error - {}".format(current_datetime(), self.nome_log, msg))
      
  def critical(self, msg):
    if self.level == "critical":
      self.write("{} - {} - critical - {}\n".format(current_datetime(), self.nome_log, msg))
    if self.log_std == True:
      self.to_stdout("{} - {} - critical - {}".format(current_datetime(), self.nome_log, msg))

  def exception(self, e_msg, e_trace):
    self.write("{} - {} - exception - {}\n".format(current_datetime(), self.nome_log, e_msg))
    if self.log_std == True:
      self.to_stdout("{} - {} - exception - {}".format(current_datetime(), self.nome_log, e_msg))
    for riga in e_trace.split("\n"):
      self.write("{} - {} - trace - {}\n".format(current_datetime(), self.nome_log, riga))
      if self.log_std == True:
        self.to_stdout("{} - {} - trace - {}".format(current_datetime(), self.nome_log, riga))

  def write(self, msg):
    try:
      self.logger.write(msg)
    except UnicodeEncodeError:
      try:
        self.logger.write(byte(msg, 'utf-8').decode('utf-8', 'ignore'))
      except:
        print("Unable to write log {} for UnicodeEncodeError".format(self.nome_log))
      #print("Unable to write log {} for UnicodeEncodeError: {}".format(self.nome_log, msg))
      pass
   
  def to_stdout(self, msg):
    try:
      print(msg)
    except UnicodeEncodeError:
      try:
        print(byte(msg, 'utf-8').decode('utf-8', 'ignore'))
      except:
        print("Unable to print ti stdout log {} for UnicodeEncodeError".format(self.nome_log))
      #print("Unable to write log {} for UnicodeEncodeError: {}".format(self.nome_log, msg))
      pass
