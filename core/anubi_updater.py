import config

class AnubiUpdater:

  updating = False

  def __init__(self):
    self.updating = False

  def get_updating(self):
    return self.updating

  def set_updating(self, updating):
    self.updating = updating
