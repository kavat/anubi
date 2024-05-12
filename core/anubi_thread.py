import config
import threading

class AnubiThreadException:
  pass

class AnubiThread:

  def __init__(self, nome_thread, target, args):
    self.nome_thread = nome_thread
    self.target = target
    self.args = args
    self.thread = threading.Thread(target=self.target, args=self.args)
    self.stato = ""

  def get_thread(self):
    return self.thread

  def start(self):
    self.thread.start()
    self.stato = "started"

  def join(self):
    self.thread.join()

  def stop(self):
    self.stato = "stopped"

def start_threads():
  for thread_name in config.threads:
    config.threads[thread_name].start()

def join_threads():
  for thread_name in config.threads:
    config.threads[thread_name].join()
