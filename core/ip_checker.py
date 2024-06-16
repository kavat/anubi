import os
import config
import time
import pathlib
import re
import subprocess
import traceback
import sys
import ipaddress
import conf_anubi

from scapy.all import *
from core.common import (
  wait_for_updating,
  file_exclusions,
  id_generator,
  write_stats
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
    self.load_rules()

  def load_rules(self):
    if os.path.isdir(config.anubi_path['ip_path']) == True:
      for file_ip in os.listdir(config.anubi_path['ip_path']):
        full_path_ip = "{}/{}".format(config.anubi_path['ip_path'], file_ip)
        try:
          with open(full_path_ip) as f:
            for line in f:
              try:
                ip_tag_name = line.rstrip().split(":")[1]
                ip_risk = line.rstrip().split(":")[3]
                if ip_tag_name != "NoTag":
                  ip_risk = 100
                self.ip_tables[line.rstrip().split(":")[0]] = { "tag_name": ip_tag_name, "risk": ip_risk }
              except Exception as ee:
                config.loggers["resources"]["logger_anubi_ip"].get_logger().warning("Error on {}".format(line.rstrip()))
                config.loggers["resources"]["logger_anubi_ip"].get_logger().warning(ee, exc_info=True)
          config.loggers["resources"]["logger_anubi_ip"].get_logger().info("Loaded {}".format(full_path_ip))
        except Exception as e:
          config.loggers["resources"]["logger_anubi_ip"].get_logger().warning("Skipped {}".format(full_path_ip))
          config.loggers["resources"]["logger_anubi_ip"].get_logger().warning(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("ip load_rules() BOOM!!!")
    if os.path.isdir(config.anubi_path['custom_ip_path']) == True:
      for file_ip in os.listdir(config.anubi_path['custom_ip_path']):
        full_path_ip = "{}/{}".format(config.anubi_path['custom_ip_path'], file_ip)
        try:
          with open(full_path_ip) as f:
            for line in f:
              ip_tag_name = line.rstrip().split(":")[1]
              ip_risk = line.rstrip().split(":")[3]
              self.ip_tables[line.rstrip().split(":")[0]] = { "tag_name": ip_tag_name, "risk": ip_risk }
          config.loggers["resources"]["logger_anubi_ip"].get_logger().info("Loaded {}".format(full_path_ip))
        except Exception as e:
          config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical(e, exc_info=True)
          config.loggers["resources"]["logger_anubi_ip"].get_logger().warning("Skipped {}".format(full_path_ip))

  def sniff(self, interface):
    config.loggers["resources"]["logger_anubi_ip"].get_logger().info("Starting sniffer on {}".format(interface))
    scapy.all.sniff(iface=interface, store=False, prn=self.process_sniffed_packet)

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
            if dst not in conf_anubi.ip_whitelist:
              config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("dst {}:{}/{} found from src {}:{} ({} with risk {})".format(dst, dport, proto, src, sport, self.ip_tables[dst]["tag_name"], self.ip_tables[dst]["risk"]))
              write_stats('ips', "src={}:{}/{} -> dst={}:{}/{} (name: {}, risk: {})".format(src, sport, proto, dst, dport, proto, self.ip_tables[dst]["tag_name"], self.ip_tables[dst]["risk"]))
              config.msgbox[id_generator(10)] = {"title": "Evil IP destination detected", "msg": "Traffic to {} ({}) with risk {} detected, check logs".format(dst, self.ip_tables[dst]["tag_name"], self.ip_tables[dst]["risk"])}
            else:
              config.loggers["resources"]["logger_anubi_ip"].get_logger().debug("dst {}:{}/{} found from src {}:{} ({} with risk {} but whitelisted)".format(dst, dport, proto, src, sport, self.ip_tables[dst]["tag_name"], self.ip_tables[dst]["risk"]))
          if src in self.ip_tables and ipaddress.ip_address(src).is_private == False:
            if src not in conf_anubi.ip_whitelist:
              config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("src {}:{}/{} found to dst {}:{} ({} with risk {})".format(src, sport, proto, dst, dport, self.ip_tables[src]["tag_name"], self.ip_tables[src]["risk"]))
              write_stats('ips', "src={}:{}/{} -> dst={}:{}/{} (name: {}, risk: {})".format(src, sport, proto, dst, dport, proto, self.ip_tables[src]["tag_name"], self.ip_tables[src]["risk"]))
              config.msgbox[id_generator(10)] = {"title": "Evil IP source detected", "msg": "Traffic from {} ({}) with risk {} detected, check logs".format(src, self.ip_tables[src]["tag_name"], self.ip_tables[src]["risk"])}
            else:
              config.loggers["resources"]["logger_anubi_ip"].get_logger().debug("src {}:{}/{} found to dst {}:{} ({} with risk {} but whitelisted)".format(src, sport, proto, dst, dport, self.ip_tables[src]["tag_name"], self.ip_tables[src]["risk"]))
    except Exception as e:
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Error during process_sniffed_packet")
      config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
      config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("process_sniffed_packet() BOOM!!!")
    config.ip_check.set(False)

def start_ip_checker(ip_checker, iface):
  ip_checker.sniff(iface)

def ip_checker_polling(ip_checker, iface):
  try:
    start_ip_checker(ip_checker, iface)
  except Exception as e:
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("Error during ip_checker_polling")
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical(e, exc_info=True)
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("ip_checker_polling() BOOM!!!")
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("SNIFFER: Waiting {} for process restart".format(config.sleep_thread_restart))
    time.sleep(config.sleep_thread_restart)
    config.loggers["resources"]["logger_anubi_ip"].get_logger().critical("SNIFFER: Thread restarted")
    ip_checker_polling(ip_checker, iface)

