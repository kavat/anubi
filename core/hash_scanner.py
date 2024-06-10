import os
import config
import time
import pathlib
import re
import subprocess
import traceback
import sys
import conf_anubi

from core.common import (
  wait_for_updating,
  get_hash_file,
  file_exclusions,
  pull_rules_repo,
  get_current_hours_minutes
)

class HashScan:

    status = False

    def get(self):
      return self.status

    def set(self, status):
      self.status = status

class HashScanner:

  hash_tables = {}

  def __init__(self):
    if os.path.isdir(config.anubi_path['hash_path']) == False and os.path.isdir(config.anubi_path['custom_hash_path']) == False:
      config.loggers["resources"]["logger_anubi_hash"].get_logger().critical("{} not found, exit".format(config.anubi_path['hash_path']))
      sys.exit(1)
    #pull_rules_repo('hash')
    self.load_rules()

  def load_rules(self):
    if os.path.isdir(config.anubi_path['hash_path']) == True:
      for file_hash in os.listdir(config.anubi_path['hash_path']):
        full_path_hash = "{}/{}".format(config.anubi_path['hash_path'], file_hash)
        try:
          with open(full_path_hash) as f:
            for line in f:
              try:
                self.hash_tables[line.rstrip().split(":")[0]] = line.rstrip().split(":")[1]
              except Exception as ee:
                config.loggers["resources"]["logger_anubi_hash"].get_logger().warning("Error on {}".format(line.rstrip()))
                config.loggers["resources"]["logger_anubi_hash"].get_logger().warning(ee, exc_info=True)
          config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Loaded {}".format(full_path_hash))
        except Exception as e:
          config.loggers["resources"]["logger_anubi_hash"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("hash load_rules() BOOM!!!")
          config.loggers["resources"]["logger_anubi_hash"].get_logger().warning("Skipped {}".format(full_path_hash))
    if os.path.isdir(config.anubi_path['custom_hash_path']) == True:
      for file_hash in os.listdir(config.anubi_path['custom_hash_path']):
        full_path_hash = "{}/{}".format(config.anubi_path['custom_hash_path'], file_hash)
        try:
          with open(full_path_hash) as f:
            for line in f:
              self.hash_tables[line.rstrip().split(":")[0]] = line.rstrip().split(":")[1]
          config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Loaded {}".format(full_path_hash))
        except Exception as e:
          config.loggers["resources"]["logger_anubi_hash"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_hash"].get_logger().warning("Skipped {}".format(full_path_hash))

  def check(self, file_path):
    (sha1_file, sha256_file, md5_file) = get_hash_file(file_path)
    if sha1_file is not None and sha1_file in self.hash_tables:
      if sha1_file not in conf_anubi.hash_whitelist:
        return self.hash_tables[sha1_file]
      else:
        return ""
    if sha256_file is not None and sha256_file in self.hash_tables: 
      if sha256_file not in conf_anubi.hash_whitelist:
        return self.hash_tables[sha256_file]
      else:
        return ""
    if md5_file is not None and md5_file in self.hash_tables: 
      if md5_file not in conf_anubi.hash_whitelist:
        return self.hash_tables[md5_file]
      else:
        return ""
    return ""

def hash_scan_file(hash_scanner, file_path, func_orig):
  try:
    if file_exclusions(file_path) == False:
      matches = hash_scanner.check(file_path)
      if matches != "":
        config.loggers["resources"]["logger_anubi_" + func_orig].get_logger().critical("Malware {} matched for {}".format(matches, file_path))
      else:
        config.loggers["resources"]["logger_anubi_" + func_orig].get_logger().debug("{} cleaned".format(file_path))
    else:
      config.loggers["resources"]["logger_anubi_" + func_orig].get_logger().debug("{} discarded".format(file_path))
  except FileNotFoundError:
    pass

def start_hash_scanner(hash_scanner, file_paths):
  config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Check for updating status")
  wait_for_updating('hash')
  config.hash_scan.set(True)
  config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Hash scan started")
  try:
    for file_path in file_paths:
      if os.path.isdir(file_path):
        file_path_dir = pathlib.Path(file_path)
        for file_path_rec in file_path_dir.rglob("*"):
          if os.path.isfile(str(file_path_rec)):
            hash_scan_file(hash_scanner, str(file_path_rec), 'hash')
      if os.path.isfile(file_path):
        hash_scan_file(hash_scanner, file_path, 'hash')
  except Exception as e:
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical("Error during start_hash_scanner")
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("start_hash_scanner() BOOM!!!")
  config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Hash scan finished")
  config.hash_scan.set(False)

def hash_scanner_polling(hash_scanner, file_paths):
  try:
    while True:
      if get_current_hours_minutes() == config.conf_anubi['hash_hhmm'] or config.force_hash_scan == True:
        if config.force_hash_scan == True:
          if config.force_hash_scan_dirs != "":
            config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Forced hash_scan on {}, waiting to start".format(config.force_hash_scan_dirs))
            start_hash_scanner(hash_scanner, [config.force_hash_scan_dirs])
            config.force_hash_scan_dirs = ""
          else:
            config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Forced hash_scan without dirs as argument, skipped action")
          config.force_hash_scan = False
        else:
          config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Periodic hash_scan started")
          start_hash_scanner(hash_scanner, file_paths)
      time.sleep(20)
  except Exception as e:
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical("Error during hash_scanner_polling")
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("hash_scanner_polling() BOOM!!!")
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical("HASH: Waiting {} for process restart".format(config.sleep_thread_restart))
    time.sleep(config.sleep_thread_restart)
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical("HASH: Thread restarted")
    hash_scanner_polling(hash_scanner, file_paths)

