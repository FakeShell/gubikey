# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import threading
from gi.repository import GLib
from typing import Callable, Optional
from .camera import CameraQRScanner

class QRCodeProcessor:
    def __init__(self, callback_handler):
        self.callback_handler = callback_handler
        self.qr_scanner = None

    def initialize_scanner(self):
        try:
            self.qr_scanner = CameraQRScanner()
            return True
        except Exception as e:
            print(f"Failed to initialize QR scanner: {e}")
            return False

    def get_available_cameras(self):
        if not self.qr_scanner:
            if not self.initialize_scanner():
                return []
        return self.qr_scanner.get_available_cameras()

    def start_scanning(self, qr_detected_callback):
        if not self.qr_scanner:
            if not self.initialize_scanner():
                return False

        def on_qr_detected(result):
            print(f"QR detected: {result.data}")
            GLib.idle_add(qr_detected_callback, result)

        return self.qr_scanner.start_scanning(on_qr_detected)

    def stop_scanning(self):
        if self.qr_scanner:
            self.qr_scanner.stop_scanning()

    def switch_camera(self):
        if self.qr_scanner:
            return self.qr_scanner.switch_camera()
        return False

    def get_current_camera(self):
        if self.qr_scanner:
            return self.qr_scanner.get_current_camera()
        return None

    def save_current_frame(self):
        if self.qr_scanner:
            return self.qr_scanner.save_current_frame()
        return None

    def cleanup(self):
        if self.qr_scanner:
            self.qr_scanner.cleanup()
            self.qr_scanner = None
