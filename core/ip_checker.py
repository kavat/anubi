import os
import config
import time
import pathlib
import re
import subprocess
import traceback
import sys
import ipaddress

from scapy.all import *
from core.common import (
  wait_for_updating,
  file_exclusions,
  pull_rules_repo
)

class IpCheck:

    status = False

    def get(self):
      return self.status

    def set(self, status):
      self.status = status

class IpChecker:

  ip_tables = {}

  def __init__(self):
    if os.path.isdir(config.anubi_path['ip_path']) == False and os.path.isdir(config.anubi_path['custom_ip_path']):
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("{} not found, exit".format(config.anubi_path['ip_path']))
      sys.exit(1)
    #pull_rules_repo('ip')
    self.load_rules()

  def load_rules(self):
    if os.path.isdir(config.anubi_path['ip_path']) == True:
      for file_ip in os.listdir(config.anubi_path['ip_path']):
        full_path_ip = "{}/{}".format(config.anubi_path['ip_path'], file_ip)
        try:
          with open(full_path_ip) as f:
            for line in f:
              self.ip_tables[line.rstrip()] = 1
          config.loggers["resources"]["logger_anubi_ip"].get_logger().info("Loaded {}".format(full_path_ip))
        except Exception as e:
          config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_ip"].get_logger().warning("Skipped {}".format(full_path_ip))
    if os.path.isdir(config.anubi_path['custom_ip_path']) == True:
      for file_ip in os.listdir(config.anubi_path['custom_ip_path']):
        full_path_ip = "{}/{}".format(config.anubi_path['custom_ip_path'], file_ip)
        try:
          with open(full_path_ip) as f:
            for line in f:
              self.ip_tables[line.rstrip()] = 1
          config.loggers["resources"]["logger_anubi_ip"].get_logger().info("Loaded {}".format(full_path_ip))
        except Exception as e:
          config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_ip"].get_logger().warning("Skipped {}".format(full_path_ip))

  def sniff(self, interface):
    try:
      config.loggers["resources"]["logger_anubi_ip"].get_logger().info("Starting sniffer on {}".format(interface))
      scapy.all.sniff(iface=interface, store=False, prn=self.process_sniffed_packet)
    except Exception as e:
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Tra {} riavvio il thread".format(config.sleep_thread_restart))
      config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("Tra {} riavvio il thread".format(config.sleep_thread_restart))
      time.sleep(config.sleep_thread_socket_restart)
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Riavvio thread")
      self.sniff(interface)

  def process_sniffed_packet(self, packet):
    wait_for_updating('ip')
    config.ip_check.set(True)
    try:
      if IP in packet:
        dport = ""
        sport = ""
        proto = ""
        dst = packet[IP].dst 
        src = packet[IP].src
        if TCP in packet:
          proto = "TCP"
          dport = packet[TCP].dport
          sport = packet[TCP].sport
        if UDP in packet:
          proto = "UDP"
          dport = packet[UDP].dport
          sport = packet[UDP].sport
        if proto != "":
          if dst in self.ip_tables and ipaddress.ip_address(dst).is_private == False:    
            config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("dst {}:{}/{} found from src {}:{}".format(dst, dport, proto, src, sport))
          if src in self.ip_tables and ipaddress.ip_address(src).is_private == False:
            config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("src {}:{}/{} found to dst {}:{}".format(src, sport, proto, dst, dport))
    except Exception as e:
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
      config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Exception during network packet inspection")
    config.ip_check.set(False)

def start_ip_checker(ip_checker, iface):
  ip_checker.sniff(iface)

def ip_checker_polling(ip_checker, iface):
  try:
    start_ip_checker(ip_checker, iface)
  except Exception as e:
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Waiting {} for process restart".format(config.sleep_thread_restart))
    time.sleep(config.sleep_thread_restart)
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Restarting process")
    ip_checker_polling(ip_checker, iface)

