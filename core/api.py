import config
import time
import conf_anubi
import os

from flask import (
  Flask,
  request,
  render_template
)
from core.common import (
  init_rules_repo, 
  check_tcp_conn, 
  current_date
)
from pathlib import Path

app = Flask(__name__)

def refresh_by_api(func):
  return "ciao"

def get_api_list():
  return "report|test|force_yara_scan|force_hash_scan|download_signatures|refresh_yara|refresh_hash|refresh_ip"

class AnubiApi:
  def _handle_refresh_yara(self, data):
    if config.yara_scan.get() == True:
      return "Yara scan in progress, can not update"
    else:
      config.updater_yara.set_updating(True)
      config.scanners['yara_scanner'].load_rules()
      config.updater_yara.set_updating(False)
      return "Reloaded"

  def _handle_refresh_hash(self, data):
    if config.hash_scan.get() == True:
      return "Hash scan in progress, can not update"
    else:
      config.updater_hash.set_updating(True)
      config.scanners['hash_scanner'].load_rules()
      config.updater_hash.set_updating(False)
      return "Reloaded"

  def _handle_refresh_ip(self, data):
    if config.ip_check.get() == True:
      return "Ip analysis in progress, can not update"
    else:
      config.updater_ip.set_updating(True)
      config.scanners['ip_checker'].load_rules()
      config.updater_ip.set_updating(False)
      return "Reloaded"

  def _handle_test(self, data):
    return "Alive"

  def _handle_download_signatures(self, data):
    if init_rules_repo('management') is not None:
      return "Download triggered"
    else:
      return "Error during download, check logs"

  def _handle_force_yara_scan(self, data):
    if data['dir'] is not None:
      if config.force_yara_scan == False:
        if os.path.isdir(data['dir']):
          config.force_yara_scan = True
          config.force_yara_scan_dirs = data['dir']
          return "Queued, waiting for start"
        else:
          return "Directory {} not available".format(data['dir'])
      else:
        return "Forced scan already in progress, wait until end"
    else:
      return "Parameter directory missed"

  def _handle_force_hash_scan(self, data):
    if data['dir'] is not None:
      if config.force_hash_scan == False:
        if os.path.isdir(data['dir']):
          config.force_hash_scan = True
          config.force_hash_scan_dirs = data['dir']
          return "Queued, waiting for start"
        else:
          return "Directory {} not available".format(data['dir'])
      else:
        return "Forced scan already in progress, wait until end"
    else:
      return "Parameter directory missed"

  def _handle_report(self, data):
    if data['type'] is not None:
      try:
        report_filename = "{}/{}_{}.stat".format(config.anubi_path['stats_path'], data['type'], current_date())
        return Path(report_filename).read_text().replace('\n', '<br>')
      except FileNotFoundError:
        return "No stats returned for {}".format(data['type'])
      except Exception as e:
        return e
    else:
      return "Parameter type missed"

  def _handle_list(self, data):
    return get_api_list()

  def handle_action(self, data):
    func = data.get("func")
    if not func:
      return "No function provided"
    
    handler_name = f"_handle_{func}"
    if hasattr(self, handler_name):
      handler = getattr(self, handler_name)
      return handler(data)
    else:
      return "no_handler for func {}".format(func)


@app.route("/", methods=['GET'])
def index():
  return render_template('index.html', host=conf_anubi.management_host, port=conf_anubi.management_port)

@app.route("/api", methods=["GET", "POST"])
def api():
  if request.method == "POST":
    rcv_data = json.loads(request.data.decode("utf-8")) if request.data else {}
    return AnubiApi().handle_action(rcv_data)
    
  if request.method == "GET":
    rcv_data = request.args.to_dict(flat=True)
    return AnubiApi().handle_action(rcv_data)

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
