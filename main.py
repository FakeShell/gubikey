#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import gi
from gi.repository import GLib, Gio
from sys import exit
from gubikey_manager.gubikey_manager import GubikeyManagerApp
from asyncio import run, sleep

async def pump_gtk_events():
    main_context = GLib.MainContext.default()
    app = GubikeyManagerApp()
    app.connect('shutdown', lambda _: exit(0))

    Gio.Application.set_default(app)
    app.register()
    app.activate()

    while True:
        while main_context.pending():
            main_context.iteration(False)
        await sleep(1 / 160)

if __name__ == '__main__':
    run(pump_gtk_events())
