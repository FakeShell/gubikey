# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import threading
from gi.repository import GLib
from typing import Callable, Optional
import pyudev

class USBUdev:
    def __init__(self, device_callback: Callable[[str, str, str], None]):
        self.device_callback = device_callback
        self.udev_monitor = None
        self.udev_monitor_thread = None
        self.is_monitoring = False
        self.connected_devices = set()

    def start_monitoring(self, vendor_id: str = "1050") -> bool:
        print("Starting USB device monitoring...")

        if self._setup_udev_monitoring(vendor_id):
            print("Using udev for real-time USB device monitoring")
            self.is_monitoring = True

            # Scan for existing devices with the target vendor ID
            self._scan_existing_devices(vendor_id)
            return True
        else:
            print("udev monitoring failed to start")
            return False

    def _scan_existing_devices(self, vendor_id: str):
        try:
            context = pyudev.Context()

            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                try:
                    device_vendor_id = device.get('ID_VENDOR_ID')
                    if device_vendor_id == vendor_id:
                        device_path = device.device_path or device.sys_path
                        product_id = device.get('ID_PRODUCT_ID', 'unknown')
                        print(f"Found existing target device: VID={device_vendor_id}, "
                              f"PID={product_id}, path={device_path}")

                        self.connected_devices.add(device_path)
                except Exception as e:
                    print(f"Error scanning existing device: {e}")
                    continue
            print(f"Tracking {len(self.connected_devices)} existing target devices")
        except Exception as e:
            print(f"Error scanning for existing devices: {e}")

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.udev_monitor:
            try:
                print("Stopping udev monitoring")
                # Note: pyudev doesn't have a clean stop method
                # The monitor thread will exit when the main process exits
            except Exception as e:
                print(f"Error stopping udev monitor: {e}")
        print("Stopped USB device monitoring")

    def _setup_udev_monitoring(self, vendor_id: str) -> bool:
        try:
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)

            monitor.filter_by('usb', 'usb_device')

            self.udev_monitor = monitor

            self.connected_devices = set()

            # Start monitoring thread
            def monitor_thread():
                try:
                    print("Starting udev monitor thread...")
                    print(f"Monitoring for USB devices with vendor ID: {vendor_id}")

                    for device in iter(monitor.poll, None):
                        if not self.is_monitoring:
                            break

                        try:
                            action = device.action
                            subsystem = device.subsystem

                            if subsystem == 'usb':
                                device_vendor_id = device.get('ID_VENDOR_ID')
                                product_id = device.get('ID_PRODUCT_ID')
                                device_type = device.device_type
                                device_path = device.device_path or device.sys_path

                                print(f"USB Event: {action} - subsystem={subsystem}, "
                                      f"type={device_type}, VID={device_vendor_id}, PID={product_id}, path={device_path}")

                                # Only handle usb_device events to avoid duplicates
                                if device_type == 'usb_device':
                                    if action == 'add':
                                        if device_vendor_id == vendor_id:
                                            print(f"Target device {action}: VID={device_vendor_id}, "
                                                  f"PID={product_id}, type={device_type}")

                                            self.connected_devices.add(device_path)

                                            print(f"Processing USB device event: {action}")

                                            GLib.idle_add(self.device_callback, action, device_vendor_id, product_id)
                                    elif action in ('remove', 'unbind'):
                                        # For remove/unbind, check if this device was one of ours
                                        if device_path in self.connected_devices:
                                            print(f"Target device {action}: path={device_path} (was tracked)")

                                            self.connected_devices.discard(device_path)

                                            print(f"Processing USB device event: {action}")

                                            GLib.idle_add(self.device_callback, 'remove', vendor_id, 'unknown')
                        except Exception as e:
                            print(f"Error processing udev event: {e}")
                            continue
                except Exception as e:
                    print(f"udev monitor thread error: {e}")
                finally:
                    print("udev monitor thread exiting")

            self.udev_monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
            self.udev_monitor_thread.start()
            monitor.start()

            print("udev monitoring started successfully")
            return True
        except ImportError:
            print("pyudev not available - install with: pip install pyudev")
            return False
        except Exception as e:
            print(f"Failed to setup udev monitoring: {e}")
            return False

class YubikeyUSBMonitor:
    def __init__(self, device_callback: Callable[[str, str, str], None]):
        self.device_callback = device_callback
        self.usb_monitor = USBUdev(device_callback)

    def start_monitoring(self) -> bool:
        return self.usb_monitor.start_monitoring("1050")

    def stop_monitoring(self) -> None:
        """Stop all monitoring"""
        self.usb_monitor.stop_monitoring()
