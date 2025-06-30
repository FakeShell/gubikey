# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import gi
import signal
import os
from sys import exit

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio

from gubikey_manager.gubikey_controller import GubikeyController
from gubikey_manager.udev import YubikeyUSBMonitor
from gubikey_manager.window_manager import (
    WindowManager, DeviceInfoManager, AccountsManager,
    ConfigurationManager, DialogManager
)
from gubikey_manager.credential_manager import (
    CredentialManager, DeviceManager
)
from gubikey_manager.qr_scanner import QRCodeProcessor
from ykman.device import list_all_devices, scan_devices

class GubikeyManagerWindow(Adw.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connect("close-request", lambda _: self.cleanup_and_exit())
        self.set_default_size(600, 800)

        self.yk_controller = GubikeyController()
        self.current_device_info = None
        self.device_present = False

        self.window_manager = WindowManager(self)
        self.device_info_manager = DeviceInfoManager(self.window_manager)
        self.accounts_manager = AccountsManager(self.window_manager)
        self.config_manager = ConfigurationManager(self.window_manager)
        self.dialog_manager = DialogManager(self)

        self.credential_manager = CredentialManager(self.yk_controller, self)
        self.device_manager = DeviceManager(self.yk_controller, self)
        self.qr_processor = QRCodeProcessor(self)

        self.usb_monitor = None

        self.current_qr_dialog = None
        self.current_qr_dialog_widgets = None

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.setup_ui()

        self.usb_monitor = YubikeyUSBMonitor(self.handle_usb_event)
        self.start_device_monitoring()

    def setup_ui(self):
        content, header = self.window_manager.setup_window_layout()
        self.set_content(content)

        self.setup_actions()

        self.setup_initial_content()

    def setup_actions(self):
        refresh_action = Gio.SimpleAction.new("refresh", None)
        refresh_action.connect("activate", lambda action, param: self.refresh_device())
        self.add_action(refresh_action)

        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self.on_about_action)
        self.add_action(about_action)

    def setup_initial_content(self):
        self.device_info_manager.update_status("Checking for YubiKey...", "emblem-system-symbolic")
        self.device_info_manager.show_no_device()
        self.accounts_manager.show_no_device()
        self.config_manager.show_no_device()

    def start_device_monitoring(self):
        print("Starting YubiKey device monitoring...")

        try:
            pids, state = scan_devices()
            device_count = sum(pids.values())

            if device_count > 0:
                print(f"Found {device_count} YubiKey(s) at startup")
                self.device_present = True
                GLib.timeout_add(100, self.initialize_device)
            else:
                print("No YubiKey detected at startup")
                self.device_present = False
                self.on_no_device()
        except Exception as e:
            print(f"Error during initial device scan: {e}")
            self.on_device_error(str(e))

        if not self.usb_monitor.start_monitoring():
            print("USB monitoring failed to start - manual refresh required")
            self.window_manager.show_toast("USB monitoring unavailable - use manual refresh")

    def handle_usb_event(self, action: str, vendor_id: str, product_id: str):
        print(f"Handling USB event: {action} for VID={vendor_id}, PID={product_id}")

        if action == 'add':
            print(f"YubiKey added (PID: {product_id}) - refreshing device info")
            self.window_manager.show_toast("YubiKey detected")
            self.device_present = True
            GLib.timeout_add(2000, self.initialize_device)
        elif action == 'remove':
            print(f"YubiKey removed (PID: {product_id})")
            self.window_manager.show_toast("YubiKey disconnected")
            self.device_present = False
            self.current_device_info = None
            self.yk_controller.raw_device = None
            self.on_no_device()

    def stop_device_monitoring(self):
        if self.usb_monitor:
            self.usb_monitor.stop_monitoring()
            print("Stopped YubiKey device monitoring")

    def initialize_device(self):
        self.device_manager.load_device_info()
        return False

    def refresh_device(self):
        self.device_info_manager.update_status("Refreshing...", "emblem-system-symbolic")
        GLib.timeout_add(100, self.initialize_device)

    def on_device_info_loaded(self, device_info):
        self.current_device_info = device_info

        self.device_info_manager.update_status(
            f"{device_info.get('device_type', 'Unknown')} connected",
            "starred-symbolic",
            f"Serial: {device_info.get('serial', 'Unknown')}"
        )

        self.device_info_manager.update_device_details(device_info)
        self.device_info_manager.update_applications(device_info)

        self.credential_manager.load_credentials()
        self.device_manager.load_piv_info()
        self.device_manager.load_fido_info()

        self.config_manager.setup_configuration_actions()

        self.device_present = True

    def on_no_device(self):
        self.device_info_manager.show_no_device()
        self.accounts_manager.show_no_device()
        self.config_manager.show_no_device()
        self.device_present = False

    def on_device_error(self, error):
        self.device_info_manager.show_error(error)
        self.window_manager.show_toast(f"Error: {error}")

    def on_credentials_loaded(self, credentials):
        self.accounts_manager.update_credentials(credentials)

    def on_credentials_error(self, error):
        self.accounts_manager.show_error(error)

    def on_code_generated(self, credential_name, code):
        self.dialog_manager.show_oath_code_dialog(
            credential_name, code, self.handle_oath_dialog_response
        )

    def on_code_error(self, error):
        self.window_manager.show_toast(error)

    def on_credential_added(self, name):
        self.window_manager.show_toast(f"Added account: {name}")
        self.credential_manager.load_credentials()

    def on_credential_deleted(self, name):
        self.window_manager.show_toast(f"Deleted account: {name}")
        self.credential_manager.load_credentials()

    def on_credentials_reset(self):
        self.window_manager.show_toast("All accounts reset successfully")
        self.credential_manager.load_credentials()

    def on_credential_error(self, error):
        self.window_manager.show_toast(error)

    def on_piv_info_loaded(self, piv_info):
        self.device_info_manager.update_piv_info(piv_info)

    def on_piv_error(self, error):
        print(f"PIV Error: {error}")

    def on_fido_info_loaded(self, fido_info):
        self.device_info_manager.update_fido_info(fido_info)

    def on_fido_error(self, error):
        print(f"FIDO Error: {error}")

    def on_application_config_loaded(self, config):
        self.window_manager.show_application_config_bottom_sheet(
            config, self.apply_application_config
        )

    def on_application_config_applied(self):
        self.window_manager.show_toast("Application configuration applied. Device will reboot.")
        GLib.timeout_add_seconds(3, self.initialize_device)

    def on_application_config_error(self, error):
        self.window_manager.show_toast(error)

    def generate_oath_code(self, credential_name: str):
        self.credential_manager.generate_code(credential_name)

    def delete_oath_credential_confirm(self, credential_name: str):
        self.dialog_manager.show_confirmation_dialog(
            "Delete Account?",
            f"Are you sure you want to delete '{credential_name}'? This action cannot be undone.",
            lambda d, r: self.handle_delete_credential_response(d, r, credential_name)
        )

    def handle_delete_credential_response(self, dialog, response, credential_name):
        if response == "confirm":
            self.credential_manager.delete_credential(credential_name)
        dialog.close()

    def reset_oath(self):
        self.dialog_manager.show_confirmation_dialog(
            "Reset All Accounts?",
            "This will permanently delete all OATH credentials from your YubiKey. This action cannot be undone.",
            self.handle_reset_oath_response
        )

    def handle_reset_oath_response(self, dialog, response):
        if response == "confirm":
            self.credential_manager.reset_all_credentials()
        dialog.close()

    def show_add_credential_dialog(self):
        self.window_manager.show_add_credential_bottom_sheet(self.handle_add_credential_choice)

    def handle_add_credential_choice(self, choice):
        if choice == "manual":
            self.show_manual_credential_dialog()
        elif choice == "qr":
            self.show_qr_scan_dialog()
        elif choice == "uri":
            self.show_uri_credential_dialog()

    def show_manual_credential_dialog(self):
        self.dialog_manager.show_manual_credential_dialog(self.add_manual_credential)

    def add_manual_credential(self, dialog, widgets):
        account_name = widgets['account_row'].get_text().strip()
        issuer = widgets['issuer_row'].get_text().strip()
        secret = widgets['secret_row'].get_text().strip()
        oath_type = "TOTP" if widgets['type_row'].get_selected() == 0 else "HOTP"
        digits = int(widgets['digits_row'].get_value())
        period = int(widgets['period_row'].get_value())

        if not account_name or not secret:
            self.window_manager.show_toast("Account name and secret key are required")
            return

        self.credential_manager.add_credential(
            name=account_name,
            secret=secret,
            issuer=issuer,
            oath_type=oath_type,
            digits=digits,
            period=period
        )
        dialog.close()

    def show_uri_credential_dialog(self):
        self.dialog_manager.show_uri_credential_dialog(self.handle_uri_credential_response)

    def handle_uri_credential_response(self, dialog, response, entry):
        if response == "add":
            uri = entry.get_text().strip()
            if not uri:
                self.window_manager.show_toast("URI cannot be empty")
                return
            self.credential_manager.add_from_uri(uri)
        dialog.close()

    def show_qr_scan_dialog(self):
        cameras = self.qr_processor.get_available_cameras()
        if not cameras:
            self.window_manager.show_toast("No cameras found for QR scanning")
            return

        dialog, widgets = self.dialog_manager.show_camera_dialog(cameras)
        self.current_qr_dialog_widgets = widgets
        self.current_qr_dialog = dialog

        def on_dialog_closed(*args):
            print("Dialog closed, cleaning up camera resources")
            self.close_camera_dialog(dialog)
            if hasattr(self, 'current_qr_dialog'):
                self.current_qr_dialog = None

        dialog.connect('closed', on_dialog_closed)

        def cancel_clicked(btn):
            print("Cancel button clicked")
            self.close_camera_dialog(dialog)

        widgets['cancel_button'].connect('clicked', cancel_clicked)

        if len(cameras) > 1:
            for i, camera in enumerate(cameras):
                if f'camera_row_{i}' in widgets:
                    widgets[f'camera_row_{i}'].connect('activated',
                        lambda row, idx=i: self.switch_to_camera(idx))

        def qr_detected_callback(result):
            if result.is_otpauth():
                print(f"QR code detected: {result.data[:50]}...")
                GLib.idle_add(self.close_camera_dialog, dialog)
                GLib.idle_add(self.process_qr_code, result.data)
            else:
                GLib.idle_add(self.update_camera_qr_status, "QR code found but not an OTP auth URI")

        if self.qr_processor.start_scanning(qr_detected_callback):
            viewfinder_widget = self.qr_processor.qr_scanner.get_viewfinder_widget()
            if viewfinder_widget:
                widgets['viewfinder_frame'].set_child(viewfinder_widget)
        else:
            self.window_manager.show_toast("Failed to start camera")
            # Don't call dialog.close() immediately, let the user see the error
            GLib.timeout_add_seconds(2, lambda: self.close_camera_dialog(dialog))

    def switch_to_camera(self, camera_index: int):
        cameras = self.qr_processor.get_available_cameras()
        if camera_index < len(cameras):
            if hasattr(self, 'current_qr_dialog_widgets'):
                widgets = self.current_qr_dialog_widgets

                for i in range(len(cameras)):
                    if f'selected_icon_{i}' in widgets:
                        try:
                            old_icon = widgets[f'selected_icon_{i}']
                            parent = old_icon.get_parent()
                            if parent:
                                parent.remove(old_icon)
                            del widgets[f'selected_icon_{i}']
                        except Exception as e:
                            print(f"Error removing tracked icon {i}: {e}")

                for i in range(len(cameras)):
                    row = widgets[f'camera_row_{i}']
                    widgets_to_remove = []

                    # Walk through all children and find Images with selection icon
                    def find_selection_icons(widget):
                        if isinstance(widget, Gtk.Image):
                            try:
                                if widget.get_icon_name() == "object-select-symbolic":
                                    widgets_to_remove.append(widget)
                            except:
                                pass

                        if hasattr(widget, 'get_first_child'):
                            child = widget.get_first_child()
                            while child:
                                find_selection_icons(child)
                                child = child.get_next_sibling()

                    find_selection_icons(row)

                    # Remove all found selection icons
                    for widget in widgets_to_remove:
                        try:
                            parent = widget.get_parent()
                            if parent:
                                parent.remove(widget)
                        except Exception as e:
                            print(f"Error removing selection icon: {e}")

                # Add selection to new camera only
                try:
                    selected_icon = Gtk.Image()
                    selected_icon.set_from_icon_name("object-select-symbolic")
                    widgets[f'camera_row_{camera_index}'].add_suffix(selected_icon)
                    widgets[f'selected_icon_{camera_index}'] = selected_icon
                except Exception as e:
                    print(f"Error adding new selection icon: {e}")

                if 'camera_expander' in widgets:
                    widgets['camera_expander'].set_subtitle(f"Current: {cameras[camera_index].name}")

            # Switch camera in processor
            if self.qr_processor.switch_camera():
                current_camera = self.qr_processor.get_current_camera()
                self.window_manager.show_toast(f"Switched to: {current_camera.name}")

                viewfinder_widget = self.qr_processor.qr_scanner.get_viewfinder_widget()
                if viewfinder_widget and hasattr(self, 'current_qr_dialog_widgets'):
                    self.current_qr_dialog_widgets['viewfinder_frame'].set_child(viewfinder_widget)

    def close_camera_dialog(self, dialog):
        print("Closing camera dialog and stopping QR processor")

        try:
            self.qr_processor.stop_scanning()
        except Exception as e:
            print(f"Error stopping QR processor: {e}")

        if hasattr(self, 'current_qr_dialog_widgets'):
            self.current_qr_dialog_widgets = None
        if hasattr(self, 'current_qr_dialog'):
            self.current_qr_dialog = None

        try:
            if dialog and dialog.get_parent() is not None:
                dialog.close()
        except Exception as e:
            print(f"Error closing dialog: {e}")

    def update_camera_qr_status(self, message: str):
        if hasattr(self, 'current_qr_dialog_widgets') and self.current_qr_dialog_widgets:
            self.current_qr_dialog_widgets['qr_status_row'].set_subtitle(message)

    def process_qr_code(self, qr_data):
        try:
            if qr_data.startswith('otpauth://'):
                self.credential_manager.add_from_uri(qr_data)
            else:
                self.window_manager.show_toast("QR code is not a valid 2FA credential")
        except Exception as e:
            self.window_manager.show_toast(f"Error processing QR code: {str(e)}")

    def configure_interfaces(self):
        self.device_manager.load_application_config()

    def apply_application_config(self, otp_enabled: bool, fido_enabled: bool, ccid_enabled: bool):
        self.device_manager.apply_application_config(otp_enabled, fido_enabled, ccid_enabled)

    def factory_reset(self):
        self.dialog_manager.show_confirmation_dialog(
            "Factory Reset Device?",
            "This will completely reset your YubiKey to factory defaults. All data, credentials, and configurations will be permanently lost. This action cannot be undone.",
            self.handle_factory_reset_response
        )

    def handle_factory_reset_response(self, dialog, response):
        if response == "confirm":
            self.window_manager.show_toast("Factory reset not implemented yet")
        dialog.close()

    def handle_oath_dialog_response(self, dialog, response, code):
        if response == "copy":
            clipboard = self.get_clipboard()
            clipboard.set(code)
            self.window_manager.show_toast("Code copied to clipboard")
        dialog.close()

    def on_about_action(self, action, parameter):
        self.dialog_manager.show_about_dialog()

    def cleanup_and_exit(self):
        print("Cleaning up application resources...")

        try:
            self.qr_processor.cleanup()
        except Exception as e:
            print(f"Error cleaning up QR processor: {e}")

        try:
            self.stop_device_monitoring()
        except Exception as e:
            print(f"Error stopping device monitoring: {e}")

        if hasattr(self, 'current_qr_dialog') and self.current_qr_dialog:
            try:
                self.current_qr_dialog.close()
            except Exception as e:
                print(f"Error closing current dialog: {e}")
        print("Application cleanup complete")
        exit(0)

    def signal_handler(self, signum, frame):
        self.cleanup_and_exit()
