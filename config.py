import logging
import sys
import os

from core.anubi_logger import AnubiLogger
from core.anubi_updater import AnubiUpdater
from core.yara_scanner import YaraScan
from core.hash_scanner import HashScan
from core.ip_checker import IpCheck
from core.fs_voyeur import FsSpy
from core.common import get_platform

def get_application_path():
  try:
    if getattr(sys, 'frozen', False):
      application_path = os.path.dirname(os.path.realpath(sys.executable))
    else:
      application_path = os.path.dirname(os.path.realpath(__file__))
    if "~" in application_path and get_platform() == "windows":
      import win32api
      application_path = win32api.GetLongPathName(application_path)
    return application_path
  except Exception:
    print("Error while evaluation of application path")
    traceback.print_exc()
    sys.exit(1)

application_path = get_application_path()
anubi_path = {
  "conf_path": "{}/conf".format(application_path),
  "rule_path": "{}/conf/anubi-signatures/yara".format(application_path),
  "hash_path": "{}/conf/anubi-signatures/hash".format(application_path),
  "ip_path": "{}/conf/anubi-signatures/ips".format(application_path),
  "custom_rule_path": "{}/conf/custom_rules".format(application_path),
  "custom_hash_path": "{}/conf/custom_hash".format(application_path),
  "custom_ip_path": "{}/conf/custom_ip".format(application_path),
  "log_path": "{}/log".format(application_path),
  "configfile_path": "{}/conf/runtime.dat".format(application_path)
}

log_to_stdout = True

base_log = anubi_path['log_path']
path_logger_anubi_main = "{}/anubi_main.log".format(base_log)
path_logger_anubi_yara = "{}/anubi_yara.log".format(base_log)
path_logger_anubi_hash = "{}/anubi_hash.log".format(base_log)
path_logger_anubi_ip = "{}/anubi_ip.log".format(base_log)
path_logger_anubi_voyeur = "{}/anubi_voyeur.log".format(base_log)
path_logger_anubi_management = "{}/anubi_management.log".format(base_log)
path_logger_anubi_master_exceptions = "{}/anubi_boom.log".format(base_log)

loggers = {}
loggers["resources"] = {}
loggers["resources"]["logger_anubi_main"] = AnubiLogger("anubi_main", path_logger_anubi_main, log_to_stdout, logging.INFO)
loggers["resources"]["logger_anubi_yara"] = AnubiLogger("anubi_yara", path_logger_anubi_yara, log_to_stdout, logging.INFO)
loggers["resources"]["logger_anubi_hash"] = AnubiLogger("anubi_hash", path_logger_anubi_hash, log_to_stdout, logging.INFO)
loggers["resources"]["logger_anubi_ip"] = AnubiLogger("anubi_ip", path_logger_anubi_ip, log_to_stdout, logging.INFO)
loggers["resources"]["logger_anubi_voyeur"] = AnubiLogger("anubi_voyeur", path_logger_anubi_voyeur, log_to_stdout, logging.INFO)
loggers["resources"]["logger_anubi_management"] = AnubiLogger("anubi_management", path_logger_anubi_management, log_to_stdout, logging.INFO)
loggers["resources"]["logger_anubi_master_exceptions"] = AnubiLogger("anubi_master_exceptions", path_logger_anubi_master_exceptions, log_to_stdout, logging.INFO)

loggers["assoc"] = {}
loggers["assoc"]["main"] = "logger_anubi_main"
loggers["assoc"]["yara"] = "logger_anubi_yara"
loggers["assoc"]["hash"] = "logger_anubi_hash"
loggers["assoc"]["ip"] = "logger_anubi_ip"
loggers["assoc"]["voyeur"] = "logger_anubi_voyeur"
loggers["assoc"]["management"] = "logger_anubi_management"

threads = {}
jobs = {}
conf_anubi = {}
scanners = {}

updater_yara = AnubiUpdater()
updater_ip = AnubiUpdater()
updater_hash = AnubiUpdater()
updater_voyeur = AnubiUpdater()

yara_scan = YaraScan()
hash_scan = HashScan()
ip_check = IpCheck()
voyeur_spy = FsSpy()

sleep_thread_restart = 10
sleep_thread_socket_restart = 60

management_host = "127.0.0.1"
management_port = 5000

linux_dir_exclusions = ["/proc/", "/dev/", "/sys/", "/usr/src/linux/", "/opt/yara", "/var/lib/apt/lists/"]
extension_exclusions = [".yar", ".yara", ".h", ".pem", ".crt", ".dat", ".dat-old", ".cache", ".crash", ".db", ".log"]
voyeur_dirs_wild = ["download", "downloads", "Download", "Downloads", "Scaricati"]
voyeur_dirs_nowild = ["/tmp"]

buf_size_calc_hash = 65536
max_file_size = 52428800
