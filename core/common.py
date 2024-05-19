import config
import time
import traceback
import sys
import os
import hashlib
import re
import subprocess
import psutil

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

  with open(file_path, 'rb') as f:
    while True:
      data = f.read(config.buf_size_calc_hash)
      if not data:
        break
      md5.update(data)
      sha1.update(data)
      sha256.update(data)

  return (sha1.hexdigest(), sha256.hexdigest(), md5.hexdigest())

def file_exclusions(file_path):
  for exclusion in config.linux_dir_exclusions:
    if file_path.startswith(exclusion) == True:
      return True
  if file_path.startswith(config.application_path):
    return True
  file_extension = re.search('\.[^\/\.]+$', file_path)
  if file_extension:
    if file_extension.group(0) in config.extension_exclusions:
      return True
  if os.path.getsize(file_path) > config.max_file_size:
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
    f = open(config.anubi_path['configfile_path'], "w")
    print("Enter the answers for the following questions in order to build your configuration")
    loop_until_input("Do you want start? (Y/N) ", ['Y','N'])
    ioc_ = loop_until_input("Do you want enable daily passive IOC detection? (Y/N) ", ['Y','N'])
    f.write("yara={}\n".format(ioc_))
    if ioc_ == "Y":
      ioc_scan_ = loop_until_input("Set to time to start daily passive IOC detection: (HH:mm) ", r'^[0-9][0-9]\:[0-9][0-9]$')
      f.write("yara_hhmm={}\n".format(ioc_scan_))
    hash_ = loop_until_input("Do you want enable daily passive malware detection? (Y/N) ", ['Y','N'])
    f.write("hash={}\n".format(hash_))
    if hash_ == "Y":
      hash_scan_ = loop_until_input("Set to time to start daily passive malware detection: (HH:mm) ", r'^[0-9][0-9]\:[0-9][0-9]$')
      f.write("hash_hhmm={}\n".format(hash_scan_))
    ip_ = loop_until_input("Do you want enable suspicious network traffic detection? (Y/N) ", ['Y','N'])
    f.write("ip={}\n".format(ip_))
    if ip_ == "Y": 
      addrs = psutil.net_if_addrs()
      list_ens = []
      for ens__ in addrs.keys():
        list_ens.append(ens__)
      ens_ = loop_until_input("Set the interface to be monitored: [{}] ".format(','.join(list_ens)), list_ens)
      f.write("eth={}\n".format(ens_))
    live_ = loop_until_input("Do you want enable live directory scan? (Y/N) ", ['Y','N'])
    f.write("live={}\n".format(live_))
    if live_ == "Y":
      live_ioc_ = loop_until_input("Do you want enable live active IOC detection? (Y/N) ", ['Y','N'])
      f.write("yara_live={}\n".format(live_ioc_))
      live_hash_ = loop_until_input("Do you want enable live active malware detection? (Y/N) ", ['Y','N'])
      f.write("hash_live={}\n".format(live_hash_))
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
  p = subprocess.Popen("cd {} && git pull".format(config.anubi_path['rule_path']), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in p.stdout.readlines():
    config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Update rules repo stdout: {}".format(line.decode('ascii').rstrip()))
  config.loggers["resources"]["logger_anubi_" + thread_name].get_logger().info("Update rules repo exit_status: {}".format(p.wait()))

def get_current_hours_minutes():
  c = datetime.now()
  return c.strftime('%H:%M')

def get_linux_dirs(dir_):
  r = []
  p = subprocess.Popen("find / -type d -name \"{}\"".format(dir_), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  for line in p.stdout.readlines():
    r.append(line.decode('ascii').rstrip())
  return r

def get_voyeur_dirs():
  d = []
  if config.voyeur_dirs_wild != []:
    for dir_ in config.voyeur_dirs_wild:
      if get_platform() == "linux":
        for dir_r in get_linux_dirs(dir_):
          d.append(dir_r)
  if config.voyeur_dirs_nowild != []:
    for dir_ in config.voyeur_dirs_nowild:
      d.append(dir_)
  return d
