import yara
import os
import config
import time
import pathlib
import re
import subprocess
import sys
import conf_anubi

from core.common import (
  wait_for_updating,
  file_exclusions,
  pull_rules_repo,
  get_current_hours_minutes
)

class YaraScan:

    status = False

    def get(self):
      return self.status

    def set(self, status):
      self.status = status

class YaraScanner:

  compiled_rules = False 

  def __init__(self):
    if os.path.isdir(config.anubi_path['rule_path']) == False and os.path.isdir(config.anubi_path['custom_rule_path']) == False:
      config.loggers["resources"]["logger_anubi_yara"].get_logger().critical("{} not found, exit".format(config.anubi_path['rule_path']))
      sys.exit(1)
    #pull_rules_repo('yara')
    self.load_rules()

  def load_rules(self):
    rules = {}
    if os.path.isdir(config.anubi_path['rule_path']) == True:
      for file_rule in os.listdir(config.anubi_path['rule_path']):
        full_path_rule = "{}/{}".format(config.anubi_path['rule_path'], file_rule)
        try:
          yara.compile(full_path_rule)
          config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Loaded {}".format(full_path_rule))
          rules[full_path_rule] = full_path_rule
        except Exception as e:
          config.loggers["resources"]["logger_anubi_yara"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("yara load_rules() BOOM!!!")
          config.loggers["resources"]["logger_anubi_yara"].get_logger().warning("Skipped {}".format(full_path_rule))
    if os.path.isdir(config.anubi_path['custom_rule_path']) == True:
      for file_rule in os.listdir(config.anubi_path['custom_rule_path']):
        full_path_rule = "{}/{}".format(config.anubi_path['custom_rule_path'], file_rule)
        try:
          yara.compile(full_path_rule)
          config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Loaded {}".format(full_path_rule))
          rules[full_path_rule] = full_path_rule
        except Exception as e:
          config.loggers["resources"]["logger_anubi_yara"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_yara"].get_logger().warning("Skipped {}".format(full_path_rule))
    self.compiled_rules = yara.compile(filepaths=rules)

  def get(self):
    return self.compiled_rules

  def check(self, file_path):
    try:
      return self.compiled_rules.match(file_path)
    except yara.Error as e:
      config.loggers["resources"]["logger_anubi_yara"].get_logger().critical("Exception on {}: {}".format(file_path, e))
    return []

def yara_scan_file(yara_scanner, file_path, func_orig):
  if file_exclusions(file_path) == False:
    matches = yara_scanner.check(file_path)
    if matches != []:
      for found in matches:
        config.loggers["resources"]["logger_anubi_" + func_orig].get_logger().critical("Rule {} matched for {}".format(found, file_path))
    else:
      config.loggers["resources"]["logger_anubi_" + func_orig].get_logger().debug("{} cleaned".format(file_path))
  else:
    config.loggers["resources"]["logger_anubi_" + func_orig].get_logger().debug("{} discarded".format(file_path))

def start_yara_scanner(yara_scanner, file_paths):
  config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Check for updating status")
  wait_for_updating('yara')
  config.yara_scan.set(True)
  config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Yara scan started")
  try:
    for file_path in file_paths:
      if os.path.isdir(file_path):
        file_path_dir = pathlib.Path(file_path)
        for file_path_rec in file_path_dir.rglob("*"):
          if os.path.isfile(str(file_path_rec)):
            yara_scan_file(yara_scanner, str(file_path_rec), 'yara')
      if os.path.isfile(file_path):
        yara_scan_file(yara_scanner, file_path, 'yara')
  except Exception as e:
    config.loggers["resources"]["logger_anubi_yara"].get_logger().critical("Error during start_yara_scanner")
    config.loggers["resources"]["logger_anubi_yara"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("start_yara_scanner() BOOM!!!")
  config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Yara scan finished")
  config.yara_scan.set(False)

def yara_scanner_polling(yara_scanner, file_paths):
  try:
    while True:
      if get_current_hours_minutes() == config.conf_anubi['yara_hhmm']:
        start_yara_scanner(yara_scanner, file_paths)
      time.sleep(20)
  except Exception as e:
    config.loggers["resources"]["logger_anubi_yara"].get_logger().critical("Error during yara_scanner_polling")
    config.loggers["resources"]["logger_anubi_yara"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("yara_scanner_polling() BOOM!!!")
    config.loggers["resources"]["logger_anubi_yara"].get_logger().critical("YARA: Waiting {} for process restart".format(conf_anubi.sleep_thread_restart))
    time.sleep(conf_anubi.sleep_thread_restart)
    config.loggers["resources"]["logger_anubi_yara"].get_logger().critical("YARA: Thread restarted")
    yara_scanner_polling(yara_scanner, file_paths)
  
