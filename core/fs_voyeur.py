import os
import config
import time
import pathlib
import re
import subprocess
import traceback
import queue
import conf_anubi

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.observers.api import EventDispatcher
from watchdog.events import LoggingEventHandler
from watchdog.utils import BaseThread

from core.common import (
  wait_for_updating,
  file_exclusions,
  get_voyeur_dirs,
  id_generator
)
from core.yara_scanner import yara_scan_file
from core.hash_scanner import hash_scan_file

def new_run(self):
  while self.should_keep_running():
    try:
      self.dispatch_events(self.event_queue)
    except queue.Empty:
      continue
    except Exception as e:
      config.loggers["resources"]["logger_anubi_voyeur"].get_logger().exception(e, traceback.format_exc())
      config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().exception(e, traceback.format_exc())
      continue

EventDispatcher.run = new_run

class FsVoyeurEvent(LoggingEventHandler):

  def __init__(self, yara_scanner, hash_scanner):
    self.yara_scanner = yara_scanner
    self.hash_scanner = hash_scanner

  def dispatch(self, event):
    if event.is_directory == False and (event.event_type == 'created' or event.event_type == 'modified'):
      try:
        if config.conf_anubi['yara_live'] and file_exclusions(event.src_path) == False:
          config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("File {} with action {}".format(event.src_path, event.event_type))
          wait_for_updating('yara')
          config.yara_scan.set(True)
          try:
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("Starting yara scanning on {}".format(event.src_path))
            if yara_scan_file(self.yara_scanner, event.src_path, 'voyeur', ''):
              config.msgbox[id_generator(10)] = {"title": "Voyeur IOC scan", "msg": "IOC detected on {}".format(event.src_path)}
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("Finished yara scanning on {}".format(event.src_path))
          except Exception as e:
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().critical("Exception during yara_voyeur on {}".format(event.src_path))
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().exception(e, traceback.format_exc())
            config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("yara_voyeur() BOOM!!!")
            pass
          config.yara_scan.set(False)
        if config.conf_anubi['hash_live'] and file_exclusions(event.src_path) == False:
          wait_for_updating('hash')
          config.hash_scan.set(True)
          try:
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("Starting hash scanning on {}".format(event.src_path))
            if hash_scan_file(self.hash_scanner, event.src_path, 'voyeur', ''):
              config.msgbox[id_generator(10)] = {"title": "Voyeur Malware scan", "msg": "Malware detected on {}".format(event.src_path)}
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("Finished hash scanning on {}".format(event.src_path))
          except Exception as e:
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().critical("Exception during hash_voyeur scan on {}".format(event.src_path))
            config.loggers["resources"]["logger_anubi_voyeur"].get_logger().exception(e, traceback.format_exc())
            config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("hash_voyeur() BOOM!!!")
            pass
          config.hash_scan.set(False)
      except FileNotFoundError:
        pass

class FsSpy:

    status = False

    def get(self):
      return self.status

    def set(self, status):
      self.status = status

class FsVoyeur:

  def __init__(self, yara_scanner, hash_scanner):
    self.yara_scanner = yara_scanner
    self.hash_scanner = hash_scanner
    config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("Starting directory identification, waiting please")
    self.dirs = get_voyeur_dirs()

  def get_dirs(self):
    return self.dirs

  def get_hash_scanner(self):
    return self.hash_scanner

  def get_yara_scanner(self):
    return self.yara_scanner

def fs_voyeur_polling(fs_voyeur):
  try:
    for dir_ in fs_voyeur.get_dirs(): 
      try:
        #observer = Observer()
        observer = PollingObserver()
        observer.schedule(FsVoyeurEvent(fs_voyeur.get_yara_scanner(), fs_voyeur.get_hash_scanner()), dir_, recursive=True)
        config.loggers["resources"]["logger_anubi_voyeur"].get_logger().info("Voyeur on {}".format(dir_))
        observer.start()
      except Exception as ee:
        config.loggers["resources"]["logger_anubi_voyeur"].get_logger().critical("Exception on {}: {}".format(dir_, ee))      
  except Exception as e:
    config.loggers["resources"]["logger_anubi_voyeur"].get_logger().critical("Error during fs_voyeur_polling")
    config.loggers["resources"]["logger_anubi_voyeur"].get_logger().exception(e, traceback.format_exc())
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("FsVoyeur() BOOM!!!")
    config.loggers["resources"]["logger_anubi_voyeur"].get_logger().critical("VOYEUR: Waiting {} for process restart".format(config.sleep_thread_restart))
    time.sleep(config.sleep_thread_restart)
    config.loggers["resources"]["logger_anubi_voyeur"].get_logger().critical("VOYEUR: Thread restarted")
    fs_voyeur_polling(fs_voyeur)
