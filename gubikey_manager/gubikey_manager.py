# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import gi
gi.require_version('Adw', '1')
from gi.repository import Adw

from gubikey_manager.gubikey_manager_window import GubikeyManagerWindow

class GubikeyManagerApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id='io.furios.Gubikey')
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        self.win = GubikeyManagerWindow(application=app)
        self.win.present()
