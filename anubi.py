import sys
import os
import config
import time
import getpass
import conf_anubi

from core.anubi_thread import (
  AnubiThread,
  start_threads,
  join_threads
)
from core.yara_scanner import (
  YaraScanner,
  yara_scanner_polling,
  yara_scanner_periodic_polling,
  start_yara_scanner
)
from core.hash_scanner import (
  HashScanner,
  hash_scanner_polling,
  hash_scanner_periodic_polling,
  start_hash_scanner
)
from core.ip_checker import (
  IpChecker,
  ip_checker_polling
)
from core.fs_voyeur import (
  FsVoyeur,
  fs_voyeur_polling
)
from core.api import (
  start_api,
  refresh_by_api
)
from core.common import (
  first_setup,
  get_anubi_conf,
  init_rules_repo,
  get_current_hours_minutes,
  get_voyeur_dirs,
  check_string_time,
  check_anubi_struct,
  create_anubi_struct,
  is_root,
  id_generator,
  is_sshfs_mounted,
  mount_sshfs
)
from core.external_interactions import analyze_single_file_or_directory

from core.msgbox import MsgBox
from argparse import ArgumentParser
from subprocess import call

parser = ArgumentParser(
                    prog='Anubi',
                    description='List of Anubi command line options, Anubi has to be run as root user unless you want analyze single file')

parser.add_argument('--check-conf', action='store_true', help='Check current configuration')
parser.add_argument('--check-struct', action='store_true', help='Check Anubi directory structure') 
parser.add_argument('--create-struct', action='store_true', help='Create Anubi directory structure') 
parser.add_argument('--init', action='store_true', help='Init configuration')
parser.add_argument('--start', action='store_true', help='Start Anubi with configuration created and rules already present')
parser.add_argument('--start-full', action='store_true', help='Start Anubi with configuration created downloading last rules')
parser.add_argument('--wipe', action='store_true', help='Wipe Anubi logs')
parser.add_argument('--refresh-yara', action='store_true', help='Reload yara rules, this action will use the already present ones, please download the newest before')
parser.add_argument('--refresh-hash', action='store_true', help='Reload hash rules, this action will use the already present ones, please download the newest before')
parser.add_argument('--refresh-ip', action='store_true', help='Reload IP, this action will use the already present ones, please download the newest before')
parser.add_argument('--file', action='store', type=str, help='File to check fullpath')
parser.add_argument('--dir', action='store', type=str, help='Directory to check fullpath')
parser.add_argument('--ip-remote', action='store', type=str, help='Remote IP to check through SSH')
parser.add_argument('--user-remote', action='store', type=str, help='User to use for checking IP remote through SSH')
parser.add_argument('--local-rules', action='store_true', help='Load local rules')

args = parser.parse_args()

if args.check_conf == False and args.check_struct == False and args.create_struct == False and args.init == False and args.start == False and args.start_full == False and args.wipe == False and args.refresh_yara == False and args.refresh_hash == False and args.refresh_ip == False and args.file == None and args.dir == None and args.ip_remote == False and args.user_remote == False:
  print("Run with argument or -h/--help")
  sys.exit(1)

if is_root() == 0 and (args.file == None or args.dir == None):
  print("Run as root")
  sys.exit(1)

if args.refresh_yara == True:
  print(refresh_by_api('yara'))
  sys.exit(0)

if args.refresh_hash == True:
  print(refresh_by_api('hash'))
  sys.exit(0)

if args.refresh_ip == True:
  print(refresh_by_api('ip'))
  sys.exit(0)

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
  create_anubi_struct(args.local_rules)
  sys.exit(1)

if args.wipe == True:
  for logger_name in config.loggers["resources"]:
    config.loggers["resources"][logger_name].wipe()
  sys.exit(1)

if args.start == True and args.start_full == True:
  print("Can not use --start with --start-full, use one")
  sys.exit(1)

if (args.start == True or args.start_full == True) and args.file == True:
  print("Can not use --start or --start-full with --file, use one")
  sys.exit(1)

if args.ip_remote:
  result = call("which sshfs && which sshpass", shell=True)
  if result > 0:
    print("Unable to proceed because sshfs or sshpass commands are not found")
    sys.exit(1)
  if args.user_remote:
    mount_point = "/tmp/remotes/{}".format(args.ip_remote)
    password = getpass.getpass("Insert password for user {} in system {}: ".format(args.user_remote, args.ip_remote))
    mount_sshfs(args.ip_remote, args.user_remote, mount_point, password)
    if is_sshfs_mounted(mount_point) == False:
      print("Unable to mount {} filesystem through SSH with user {}".format(args.ip_remote, args.user_remote))
      sys.exit(1)
    else:
      args.dir = mount_point
      print("{} mounted correctly".format(args.dir))
  else:
    print("Option --user-remote not found, user missed for {}".format(args.ip_remote))
    sys.exit(1)

if args.file or args.dir:
  if args.file:
    r = analyze_single_file_or_directory(args.file, args.local_rules)
  if args.dir:
    r = analyze_single_file_or_directory(args.dir, args.local_rules)
  print(r)
  if args.ip_remote:
    rc = call("ps xa | grep sshfs | grep \"{}\" | grep -v grep | grep -o \"^[0-9 ]\\\+\" | xargs kill -9 && umount -f {}".format(args.dir.replace("/",'\/'), args.dir), shell=True)
    if rc != 0:
      print("Error umounting {}".format(args.dir))
  if r['status'] == True:
    sys.exit(0)
  else:
    sys.exit(1)

if args.start == True or args.start_full == True:

  if args.start_full == True:
    create_anubi_struct(args.local_rules)

  if args.start == True and check_anubi_struct() == False:
    print("Something wrong during structure checks, run --create-struct before")
    sys.exit(1)

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
        config.loggers["resources"]["logger_anubi_main"].get_logger().info("Periodic yara_scanner enabled")
        config.threads["yara_periodic"] = AnubiThread("yara_periodic", yara_scanner_periodic_polling, (config.scanners['yara_scanner'],['/'],))
      else:
        config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Periodic yara_scanner enabled without hours:minutes parameter, skipped")
    else:
      config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Periodic yara_scanner not enabled")

    if 'hash' in config.conf_anubi and config.conf_anubi['hash'] == 'Y':
      if check_string_time(config.conf_anubi['hash_hhmm']) == True:
        config.loggers["resources"]["logger_anubi_main"].get_logger().info("Periodic hash_scanner enabled")
        config.threads["hash_periodic"] = AnubiThread("hash_periodic", hash_scanner_periodic_polling, (config.scanners['hash_scanner'],['/'],))
      else:
        config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Periodic hash_scanner enabled without hours:minutes parameter, skipped")
    else:
      config.loggers["resources"]["logger_anubi_main"].get_logger().warning("Periodic hash_scanner not enabled")

    config.threads["yara"] = AnubiThread("yara", yara_scanner_polling, (config.scanners['yara_scanner'],))
    config.threads["hash"] = AnubiThread("hash", hash_scanner_polling, (config.scanners['hash_scanner'],))

    if 'ip' in config.conf_anubi and config.conf_anubi['ip'] == 'Y':
      config.loggers["resources"]["logger_anubi_main"].get_logger().info("IP checker enabled")
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

    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Starting threads..")
    start_threads()

    counter = 0
    while True:
      if counter == 6:
        counter = 0
      if counter % 6 == 0:
        config.loggers["resources"]["logger_anubi_main"].get_logger().info("Living Anubi..")
      msgbox_managed = []
      try:
        for msg_id in config.msgbox:
          try:
            MsgBox(config.msgbox[msg_id]["title"], config.msgbox[msg_id]["msg"])
          except:
            config.loggers["resources"]["logger_anubi_main"].get_logger().error("Unable to create MsgBox")
          msgbox_managed.append(msg_id)
        for msg_id in msgbox_managed:
          try:
            del config.msgbox[msg_id]
          except Exception as e_:
            config.loggers["resources"]["logger_anubi_main"].get_logger().error("Unable to remove {} from msgbox: {}".format(msg_id, e_))
      except Exception as en:
        config.loggers["resources"]["logger_anubi_main"].get_logger().critical("Unable to manage notification: {}".format(en))
      counter = counter + 1
      time.sleep(10)

  except KeyboardInterrupt:
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Stop")
    sys.exit(0)

