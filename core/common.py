import config
import time
import traceback
import sys
import os
import hashlib
import re
import subprocess
import psutil
import conf_anubi
import socket
import string
import random

from sys import platform as _platform
from datetime import datetime

def wait_for_updating(action):
  config.loggers["resources"]["logger_anubi_" + action].get_logger().debug("Refresh rule checker started")
  if action == 'yara':
    while config.updater_yara.get_updating() == True:
      time.sleep(1)      
  if action == 'hash':
    while config.updater_hash.get_updating() == True:
      time.sleep(1)
  if action == 'ip':
    while config.updater_ip.get_updating() == True:
      time.sleep(1)
  config.loggers["resources"]["logger_anubi_" + action].get_logger().debug("Refresh rule checker ended")

def get_platform():
  os_platform = ""
  if _platform == "linux" or _platform == "linux2":
    os_platform = "linux"
  elif _platform == "darwin":
    os_platform = "macos"
  elif _platform == "win32":
    os_platform = "windows"
  return os_platform

def get_hash_file(file_path):

  md5 = hashlib.md5()
  sha1 = hashlib.sha1()
  sha256 = hashlib.sha256()

  try:
    with open(file_path, 'rb') as f:
      while True:
        data = f.read(config.buf_size_calc_hash)
        if not data:
          break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)

    return (sha1.hexdigest(), sha256.hexdigest(), md5.hexdigest())
  except Exception as e:
    config.loggers["resources"]["logger_anubi_hash"].get_logger().critical("Error during {} hash calc".format(file_path))
  return (None, None, None)

def file_exclusions(file_path):
  if get_platform() == "linux" or get_platform() == "macos":
    for exclusion in conf_anubi.linux_dir_exclusions:
      if file_path.startswith(exclusion) == True:
        return True
  if file_path.startswith(config.application_path):
    return True
  file_extension = re.search('\.[^\/\.]+$', file_path)
  if file_extension:
    if file_extension.group(0) in conf_anubi.extension_exclusions:
      return True
  if os.path.getsize(file_path) > conf_anubi.max_file_size:
    return True
  return False

def loop_until_input(message, accepted):
  r = ""
  while True:
    r = input(message)
    if isinstance(accepted,list):
      if r in accepted:
        break
    if isinstance(accepted,str):
      if re.match(accepted, r):
        break
  return r

def check_string_time(string):
  if string != '':
    if re.match(r'^[0-9][0-9]:[0-9][0-9]$', string):
      hh = string.split(":")[0]
      mm = string.split(":")[1]
      if int(hh) >= 0 and int(hh) <= 23 and int(mm) >= 0 and int(mm) <= 59:
        return True
  return False

def first_setup():
  print("Welcome to the first setup for Anubi!")
  try:
    print("Enter the answers for the following questions in order to build your configuration")
    loop_until_input("Do you want start? (Y/N) ", ['Y','N'])
    ioc_ = loop_until_input("Do you want enable daily passive IOC detection? (Y/N) ", ['Y','N'])
    anubi_conf_str = "yara={}\n".format(ioc_)
    if ioc_ == "Y":
      ioc_scan_ = loop_until_input("Set to time to start daily passive IOC detection: (HH:mm) ", r'^[0-9][0-9]\:[0-9][0-9]$')
      anubi_conf_str = "{}yara_hhmm={}\n".format(anubi_conf_str, ioc_scan_)
    hash_ = loop_until_input("Do you want enable daily passive malware detection? (Y/N) ", ['Y','N'])
    anubi_conf_str = "{}hash={}\n".format(anubi_conf_str, hash_)
    if hash_ == "Y":
      hash_scan_ = loop_until_input("Set to time to start daily passive malware detection: (HH:mm) ", r'^[0-9][0-9]\:[0-9][0-9]$')
      anubi_conf_str = "{}hash_hhmm={}\n".format(anubi_conf_str, hash_scan_)
    ip_ = loop_until_input("Do you want enable suspicious network traffic detection? (Y/N) ", ['Y','N'])
    anubi_conf_str = "{}ip={}\n".format(anubi_conf_str, ip_)
    if ip_ == "Y": 
      addrs = psutil.net_if_addrs()
      list_ens = []
      for ens__ in addrs.keys():
        list_ens.append(ens__)
      ens_ = loop_until_input("Set the interface to be monitored: [{}] ".format(','.join(list_ens)), list_ens)
      anubi_conf_str = "{}eth={}\n".format(anubi_conf_str, ens_)
    live_ = loop_until_input("Do you want enable live directory scan? (Y/N) ", ['Y','N'])
    anubi_conf_str = "{}live={}\n".format(anubi_conf_str, live_)
    if live_ == "Y":
      live_ioc_ = loop_until_input("Do you want enable live active IOC detection? (Y/N) ", ['Y','N'])
      anubi_conf_str = "{}yara_live={}\n".format(anubi_conf_str, live_ioc_)
      live_hash_ = loop_until_input("Do you want enable live active malware detection? (Y/N) ", ['Y','N'])
      anubi_conf_str = "{}hash_live={}\n".format(anubi_conf_str, live_hash_)
    f = open(config.anubi_path['configfile_path'], "w")
    f.write(anubi_conf_str)
    f.close()
    return True
  except Exception as e:
    return False

def get_anubi_conf(type_output):
  c = {}
  try:
    with open(config.anubi_path['configfile_path']) as f:
      for line in f:
        c[line.rstrip().split("=")[0]] = line.rstrip().split("=")[1]
    config.loggers["resources"]["logger_anubi_main"].get_logger().info("Loaded {}".format(config.anubi_path['configfile_path']))
  except Exception as e:
    traceback.print_exc()
    print(e)
    config.loggers["resources"]["logger_anubi_main"].get_logger().critical("Error during {} loading".format(config.anubi_path['configfile_path']))
  if type_output == 'list':
    return c
  else:
    s = ""
    for field in c:
      s = "{}{} = {}\n".format(s, field, c[field])
    return s

def init_rules_repo(thread_name):
  config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Init rules repo")
  p = subprocess.Popen("cd {} && rm -rf anubi-signatures && git clone https://github.com/kavat/anubi-signatures".format(config.anubi_path['conf_path']), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in p.stdout.readlines():
    config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Clone rules repo stdout: {}".format(line.decode('ascii').rstrip()))
  config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Clone rules repo exit_status: {}".format(p.wait()))

def pull_rules_repo(thread_name):
  config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Init pull rules repo")
  p = subprocess.Popen("cd {} && git checkout -- . && git pull".format(config.anubi_path['rule_path']), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  ritorno = ""
  for line in p.stdout.readlines():
    config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Update rules repo stdout: {}".format(line.decode('ascii').rstrip()))
    ritorno = "{}{}".format(ritorno, line.decode('ascii'))
  ritorno = "{}exit_status: {}".format(ritorno, p.wait())
  config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Update rules repo exit_status: {}".format(p.wait()))
  return ritorno

def current_datetime():
  now = datetime.now()
  return now.strftime("%d/%m/%Y %H:%M:%S")

def current_date():
  now = datetime.now()
  return now.strftime("%Y-%m-%d")

def get_current_hours_minutes():
  c = datetime.now()
  return c.strftime('%H:%M')

def get_linux_dirs(dir_):
  r = []
  for top_dir in conf_anubi.voyeur_linux_top_dirs:
    p = subprocess.Popen("find {} -type d -name \"{}\"".format(top_dir, dir_), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
      r.append(line.decode('ascii').rstrip())
  return r

def get_macos_dirs(dir_):
  r = []
  for top_dir in conf_anubi.voyeur_mac_top_dirs:
    p = subprocess.Popen("find /{} -type d -name \"{}\"".format(top_dir, dir_), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
      r.append(line.decode('ascii').rstrip())
  return r

def get_voyeur_dirs():
  d = []
  if conf_anubi.voyeur_dirs_wild != []:
    for dir_ in conf_anubi.voyeur_dirs_wild:
      if get_platform() == "linux":
        for dir_r in get_linux_dirs(dir_):
          d.append(dir_r)
      if get_platform() == "macos":
        for dir_r in get_macos_dirs(dir_): 
          d.append(dir_r)
  if conf_anubi.voyeur_dirs_nowild != []:
    for dir_ in conf_anubi.voyeur_dirs_nowild:
      d.append(dir_)
  return d

def check_anubi_struct():
  ritorno = True
  for dir in config.anubi_path:
    if dir != "configfile_path":
      if os.path.isdir(config.anubi_path[dir]) == True:
        print("Directory {} in path {} exists".format(dir, config.anubi_path[dir]))
      else:
        if os.path.isfile(config.anubi_path[dir]) == True:
          print("File {} in path {} exists".format(dir, config.anubi_path[dir]))
        else:
          print("Directory or file {} in path {} does not exists".format(dir, config.anubi_path[dir]))
          ritorno = False
  return ritorno

def create_anubi_struct():
  if os.path.isdir(config.anubi_path['conf_path']) == False:
    os.mkdir(config.anubi_path['conf_path'], mode=0o755)
  init_rules_repo('main')
  for dir in config.anubi_path:
    if dir != "configfile_path":
      if os.path.isdir(config.anubi_path[dir]) == False:
        os.mkdir(config.anubi_path[dir], mode=0o755)
        if os.path.isdir(config.anubi_path[dir]) == False:
          print("{} in path {} not exists".format(dir, config.anubi_path[dir]))

def is_root(): 
  if os.geteuid()==0:
    return 1
  else:
    return 0

def check_tcp_conn(host, port):
  s = socket.socket()
  try:
    s.connect((host, port))
  except Exception as e: 
    return False
  finally:
    s.close()
  return True

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for _ in range(size))

def write_report(report_filename, msg):
  if report_filename != "":
    try:
      with open(report_filename, "a") as report_file:
        report_file.write("{} - {}\n".format(current_datetime(), msg))
    except Exception as e:
      print("Unable to write {}".format(report_filename))
  return True

def write_stats(func_name, msg):
  report_filename = "{}/{}_{}.stat".format(config.anubi_path['stats_path'], func_name, current_date())
  try:
    with open(report_filename, "a") as report_file:
      report_file.write("{} - {}\n".format(current_datetime(), msg))
  except Exception as e:
    print("Unable to write {}".format(report_filename))
  return True
