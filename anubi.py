#!/usr/bin/python3

import sys
import os
import config
import time
import conf_anubi

from core.anubi_thread import (
  AnubiThread,
  start_threads,
  join_threads
)
from core.yara_scanner import (
  YaraScanner,
  yara_scanner_polling
)
from core.hash_scanner import (
  HashScanner,
  hash_scanner_polling
)
from core.ip_checker import (
  IpChecker,
  ip_checker_polling
)
from core.fs_voyeur import (
  FsVoyeur,
  fs_voyeur_polling
)
from core.api import start_api
from core.common import (
  first_setup,
  get_anubi_conf,
  init_rules_repo,
  get_current_hours_minutes,
  get_voyeur_dirs,
  check_string_time,
  check_anubi_struct,
  create_anubi_struct
)
from argparse import ArgumentParser

parser = ArgumentParser(
                    prog='Anubi',
                    description='List of Anubi command line options')

parser.add_argument('--check-conf', action='store_true', help='Check current configuration')
parser.add_argument('--check-struct', action='store_true', help='Check Anubi directory structure') 
parser.add_argument('--create-struct', action='store_true', help='Create Anubi directory structure') 
parser.add_argument('--init', action='store_true', help='Init configuration')
parser.add_argument('--start', action='store_true', help='Start Anubi with configuration created and rules already present')
parser.add_argument('--start-full', action='store_true', help='Start Anubi with configuration created downloading last rules')
parser.add_argument('--wipe', action='store_true', help='Wipe Anubi logs')
args = parser.parse_args()

if args.check_conf == False and args.check_struct == False and args.create_struct == False and args.init == False and args.start == False and args.start_full == False and args.wipe == False:
  print("Run with argument or -h/--help")
  sys.exit(1)

if args.init == True:
  first_setup()
  sys.exit(1)

if args.check_conf == True:
  print(get_anubi_conf('desc'))
  sys.exit(1)

if args.check_struct == True:
  check_anubi_struct()
  sys.exit(1)

if args.create_struct == True:
  create_anubi_struct()
  sys.exit(1)

if args.wipe == True:
  for logger_name in config.loggers["resources"]:
    config.loggers["resources"][logger_name].wipe()
  sys.exit(1)

if args.start == True and args.start_full == True:
  print("Can not use --start with --start-full, use one")
  sys.exit(1)

if args.start == True or args.start_full == True:

  if args.start == True and check_anubi_struct() == False:
    print("Something wrong during structure checks, run --create-struct before")
    sys.exit(1)

  if args.start_full == True:
    create_anubi_struct()

  if os.path.isfile(config.anubi_path['configfile_path']) == False:
    first_setup()

  config.conf_anubi = get_anubi_conf('list')

  try:

    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Starting Anubi..")

    config.scanners['yara_scanner'] = YaraScanner()
    config.scanners['hash_scanner'] = HashScanner()
    config.scanners['ip_checker'] = IpChecker()

    if 'yara' in config.conf_anubi and config.conf_anubi['yara'] == 'Y':
      if check_string_time(config.conf_anubi['yara_hhmm']) == True:
        config.threads["yara"] = AnubiThread("yara", yara_scanner_polling, (config.scanners['yara_scanner'],['/'],))
      else:
        config.loggers["resources"]["logger_anubi_yara"].get_logger().error("Yara scanner enabled but invalid hh:mm param: {}".format(config.conf_anubi['yara_hhmm']))
    else:
      config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Yara scanner not enabled")
  
    if 'hash' in config.conf_anubi and config.conf_anubi['hash'] == 'Y':
      if check_string_time(config.conf_anubi['hash_hhmm']) == True:
        config.threads["hash"] = AnubiThread("hash", hash_scanner_polling, (config.scanners['hash_scanner'],['/'],))
      else:
        config.loggers["resources"]["logger_anubi_hash"].get_logger().error("Hash scanner enabled but invalid hh:mm param: {}".format(config.conf_anubi['hash_hhmm']))
        sys.exit(1)
    else:
      config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Hash scanner not enabled")

    if 'ip' in config.conf_anubi and config.conf_anubi['ip'] == 'Y':
      config.threads["ip"] = AnubiThread("ip", ip_checker_polling, (config.scanners['ip_checker'],config.conf_anubi['eth'],))
    else:
      config.loggers["resources"]["logger_anubi_main"].get_logger().warning("IP checker not enabled")

    if 'live' in config.conf_anubi and config.conf_anubi['live'] == 'Y':
      fs_voyeur = FsVoyeur(config.scanners['yara_scanner'], config.scanners['hash_scanner'])
      #config.jobs['voyeur'] = fs_voyeur_polling(fs_voyeur)
      config.threads["voyeur"] = AnubiThread("voyeur", fs_voyeur_polling, (fs_voyeur,))
    else:
      config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Voyeur checker not enabled")

    config.threads["management"] = AnubiThread("management", start_api, (conf_anubi.management_host,conf_anubi.management_port,))

    start_threads()

    while True:
      config.loggers["resources"]["logger_anubi_main"].get_logger().info("Living Anubi..")
      time.sleep(60)

  except KeyboardInterrupt:
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Stop")

