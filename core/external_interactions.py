import os
import config
import conf_anubi

from core.common import (
  check_anubi_struct,
  create_anubi_struct,
  init_rules_repo,
  id_generator
)
 
from core.yara_scanner import ( 
  YaraScanner,
  start_yara_scanner,
  yara_scan_single_file
)
 
from core.hash_scanner import (
  HashScanner,
  start_hash_scanner,
  hash_scan_single_file
)

def analyze_single_file_or_directory(filepath):

  rit = {'status':True, 'hash_scan':"", 'yara_scan':[], 'msg':"", "file":filepath}

  if os.path.isfile(filepath) == False and os.path.isdir(filepath) == False:
    rit['msg'] = "{} not exists".format(filepath)
    rit['status'] = False
    return rit

  if check_anubi_struct() == False:
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Create necessary structs")
    create_anubi_struct()
  else: 
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Update existing rules: {}".format(init_rules_repo('main')))
    
  config.loggers["resources"]["logger_anubi_main"].get_logger().info("Starting Anubi for single scan file use..")
    
  report_filename = "{}/{}_{}.report".format(config.anubi_path['report_path'], conf_anubi.yara_report_suffix, id_generator(10))
  config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Oneshot yara_scan started")
  rit['yara_scan'] = start_yara_scanner(YaraScanner(), [filepath], 'main')
  
  report_filename = "{}/{}_{}.report".format(config.anubi_path['report_path'], conf_anubi.hash_report_suffix, id_generator(10))
  config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Oneshot hash_scan started")
  rit['hash_scan'] = start_hash_scanner(HashScanner(), [filepath], 'main')
    
  config.loggers["resources"]["logger_anubi_main"].get_logger().info("Finished Anubi for single scan file use..")
  
  return rit

def analyze_dir(dirpath):

  rit = {'status':True, 'hash_scan':"", 'yara_scan':[], 'msg':"", "file":filepath}

  if os.path.isdir(dirpath) == False:
    rit['msg'] = "{} not exists".format(dirpath)
    rit['status'] = False
    return rit

  if check_anubi_struct() == False:
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Create necessary structs")
    create_anubi_struct()
  else:
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Update existing rules: {}".format(init_rules_repo('main')))

  config.loggers["resources"]["logger_anubi_main"].get_logger().info("Starting Anubi for single scan dir use..")

  report_filename = "{}/{}_{}.report".format(config.anubi_path['report_path'], conf_anubi.yara_report_suffix, id_generator(10))
  config.loggers["resources"]["logger_anubi_yara"].get_logger().info("Oneshot yara_scan started")
  rit['yara_scan'] = yara_scan_single_file(YaraScanner(), dirpath, 'main')

  report_filename = "{}/{}_{}.report".format(config.anubi_path['report_path'], conf_anubi.hash_report_suffix, id_generator(10))
  config.loggers["resources"]["logger_anubi_hash"].get_logger().info("Oneshot hash_scan started")
  rit['hash_scan'] = hash_scan_single_file(HashScanner(), dirpath, 'main')

  config.loggers["resources"]["logger_anubi_main"].get_logger().info("Finished Anubi for single scan dir use..")

  return rit
