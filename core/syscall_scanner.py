import platform
import sys
import time
import config
import conf_anubi
import traceback
import psutil

from core.common import (
  wait_for_updating,
  file_exclusions,
  get_current_hours_minutes,
  id_generator,
  write_report,
  write_stats,
  test_file
)


class SysCallScan:

  status = False

  def get(self):
    return self.status

  def set(self, status):
    self.status = status

class SysCallScanner:

  def __init__(self):
    self.platform = platform.system()
    if self.platform == "Linux":
      from ptrace.debugger import PtraceDebugger
      self.debugger = PtraceDebugger()
    if self.platform == "Windows":
      self.debugger = None

  def monitor_linux(self, pid):
    print(f"Monitoring process {pid} on Linux...")

    try:
      process = self.debugger.addProcess(pid, False)
      syscall = process.syscall()
      if syscall:
        print(f"Syscall: {syscall.name}({syscall.arguments})")
    except Exception as e:
      print(e)
      pass

  def monitor_windows(self, pid):
    import win32api
    import win32process
    import win32security
    print(f"Monitoring process {pid} on Windows...")
    handle = win32api.OpenProcess(win32process.PROCESS_QUERY_INFORMATION | win32process.PROCESS_VM_READ, False, pid)

    try:
      mem_counters = win32process.GetProcessMemoryInfo(handle)
      print(f"Memory Usage: {mem_counters['WorkingSetSize']} bytes")
    except Exception as e:
      print(e)
      pass
    win32api.CloseHandle(handle)

  def get_active_processes(self):
    active_processes = []
    
    for proc in psutil.process_iter(['pid', 'name']):
      try:
        active_processes.append({'pid': proc.info['pid'], 'name': proc.info['name']})
      except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    
    return active_processes

  def analyze_pid(self, pid):
    if self.platform == "Linux":
      self.monitor_linux(pid)
    elif self.platform == "Windows":
      self.monitor_windows(pid)
    else:
      config.loggers["resources"]["logger_anubi_syscall"].get_logger().warning("Unsupported platform: {}".format(self.platform))

def syscall_scanner_polling(syscall_scanner):
  try:
    while True:
      report_filename = "{}/{}_{}.report".format(config.anubi_path['report_path'], conf_anubi.syscall_report_suffix, id_generator(10))
      for process in syscall_scanner.get_active_processes():
        syscall_scanner.analyze_pid(process['pid'])
  except Exception as e:
    config.loggers["resources"]["logger_anubi_syscall"].get_logger().critical("Error during syscall_scanner_polling")
    config.loggers["resources"]["logger_anubi_syscall"].get_logger().exception(e, traceback.format_exc())
    config.loggers["resources"]["logger_anubi_master_exceptions"].get_logger().critical("syscall_scanner_polling() BOOM!!!")
    config.loggers["resources"]["logger_anubi_syscall"].get_logger().critical("SYSCALL: Waiting {} for process restart".format(config.sleep_thread_restart))
    time.sleep(config.sleep_thread_restart)
    config.loggers["resources"]["logger_anubi_syscall"].get_logger().critical("SYSCALL: Thread restarted")
    syscall_scanner_polling(syscall_scanner)
