import config
import time
import conf_anubi
import os

from flask import (
  Flask,
  request,
  render_template
)
from core.common import pull_rules_repo, check_tcp_conn

app = Flask(__name__)

@app.route("/", methods=['GET'])
def index():
  return render_template('index.html', host=conf_anubi.management_host, port=conf_anubi.management_port)

@app.route("/api", methods=['GET'])
def api():
  if request.method == 'GET':
    if request.args.get('func'):
      if request.args.get('func') == 'test':
        return "AM I LORD VOLDEMORT"
      if request.args.get('func') == 'refresh_yara':
        if config.yara_scan.get() == True:
          return "Yara scan in progress, can not update"
        else:
          config.updater_yara.set_updating(True)
          config.scanners['yara_scanner'].load_rules()
          config.updater_yara.set_updating(False)
          return "Reloaded"
      if request.args.get('func') == 'refresh_hash':
        if config.hash_scan.get() == True:
          return "Hash scan in progress, can not update"
        else:
          config.updater_hash.set_updating(True)
          config.scanners['hash_scanner'].load_rules()
          config.updater_hash.set_updating(False)
          return "Reloaded"
      if request.args.get('func') == 'refresh_ip':
        if config.ip_check.get() == True:
          return "Ip analysis in progress, can not update"
        else:
          config.updater_ip.set_updating(True)
          config.scanners['ip_checker'].load_rules()
          config.updater_ip.set_updating(False)
          return "Reloaded"
      if request.args.get('func') == 'download_signatures':
        return pull_rules_repo('management')
      if request.args.get('func') == "force_yara_scan":
        if request.args.get('dir') is not None:
          if os.path.isdir(request.args.get('dir')):
            config.force_yara_scan = True
            config.force_yara_scan_dirs = request.args.get('dir')
            return "Queued, waiting for start"
          else:
            return "Directory {} not available".format(request.args.get('dir'))
        else:
          return "Parameter directory missed"
      if request.args.get('func') == "force_hash_scan":
        if request.args.get('dir') is not None:
          if os.path.isdir(request.args.get('dir')):
            config.force_hash_scan = True
            config.force_hash_scan_dirs = request.args.get('dir')
            return "Queued, waiting for start"
          else:
            return "Directory {} not available".format(request.args.get('dir'))
        else:
          return "Parameter directory missed"
    else:
      return "test|force_yara_scan|force_hash_scan|download_signatures|refresh_yara|refresh_hash|refresh_ip"
  else:
    return "no_get_method"

def start_api(host, port):
  try:
    config.loggers["resources"]["logger_anubi_management"].get_logger().info("Starting API..")
    app.run(host, port)
  except Exception as e:
    config.loggers["resources"]["logger_anubi_management"].get_logger().critical("Error during start_api")
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("start_api() BOOM!!!")
    config.loggers["resources"]["logger_anubi_management"].get_logger().critical(e, exc_info=True)
    if check_tcp_conn(host, port) == False: 
      config.loggers["resources"]["logger_anubi_management"].get_logger().critical("API: Waiting {} for process restart".format(config.sleep_thread_restart))
      time.sleep(config.sleep_thread_socket_restart)
      config.loggers["resources"]["logger_anubi_management"].get_logger().critical("API: Thread restarted")
      start_api(host, port)
    else:
      config.loggers["resources"]["logger_anubi_management"].get_logger().info("Server reachable, thread restart not needed")
