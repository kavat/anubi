import config
import pynotifier

from pynotifier.backends import platform
from config import get_application_path

class MsgBox:

  def __init__(self, title, message):
    c = pynotifier.NotificationClient()
    c.register_backend(platform.Backend())

    notification = pynotifier.Notification(
        title=title,
        icon_path="{}/anubi.ico".format(get_application_path()),
        message=message,
        keep_alive=True,  # keep toast alive in System Tray whether it was clicked or not
        threaded=True     # spawns a separate thread inorder not to block the main app thread
    )

    c.notify_all(notification)
