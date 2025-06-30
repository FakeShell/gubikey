# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import re
import base64
import threading
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Any, Callable
from gi.repository import GLib

class CredentialManager:
    def __init__(self, controller, callback_handler):
        self.controller = controller
        self.callback_handler = callback_handler

    def load_credentials(self):
        def load_thread():
            try:
                credentials = self.controller.get_oath_credentials()
                GLib.idle_add(self.callback_handler.on_credentials_loaded, credentials)
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_credentials_error, str(e))

        thread = threading.Thread(target=load_thread)
        thread.daemon = True
        thread.start()

    def generate_code(self, credential_name: str):
        def generate_thread():
            try:
                code = self.controller.generate_oath_code(credential_name)
                if code:
                    GLib.idle_add(self.callback_handler.on_code_generated, credential_name, code)
                else:
                    GLib.idle_add(self.callback_handler.on_code_error,
                                  f"Failed to generate code for {credential_name}")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_code_error,
                              f"Error generating code: {str(e)}")

        thread = threading.Thread(target=generate_thread)
        thread.daemon = True
        thread.start()

    def add_credential(self, name: str, secret: str, issuer: str = "",
                       oath_type: str = "TOTP", digits: int = 6, period: int = 30):
        def add_thread():
            try:
                success = self.controller.add_oath_credential(
                    name=name,
                    secret=secret,
                    issuer=issuer,
                    oath_type=oath_type,
                    digits=digits,
                    period=period
                )
                if success:
                    GLib.idle_add(self.callback_handler.on_credential_added, name)
                else:
                    GLib.idle_add(self.callback_handler.on_credential_error, "Failed to add account")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_credential_error, f"Error adding account: {str(e)}")

        thread = threading.Thread(target=add_thread)
        thread.daemon = True
        thread.start()

    def delete_credential(self, credential_name: str):
        def delete_thread():
            try:
                success = self.controller.delete_oath_credential(credential_name)
                if success:
                    GLib.idle_add(self.callback_handler.on_credential_deleted, credential_name)
                else:
                    GLib.idle_add(self.callback_handler.on_credential_error, "Failed to delete account")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_credential_error, f"Error deleting account: {str(e)}")

        thread = threading.Thread(target=delete_thread)
        thread.daemon = True
        thread.start()

    def reset_all_credentials(self):
        def reset_thread():
            try:
                success = self.controller.reset_oath()
                if success:
                    GLib.idle_add(self.callback_handler.on_credentials_reset)
                else:
                    GLib.idle_add(self.callback_handler.on_credential_error, "Failed to reset accounts")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_credential_error, f"Error resetting accounts: {str(e)}")

        thread = threading.Thread(target=reset_thread)
        thread.daemon = True
        thread.start()

    def add_from_uri(self, uri: str):
        def add_thread():
            try:
                cred_info = self.parse_otpauth_uri(uri)
                if not cred_info:
                    GLib.idle_add(self.callback_handler.on_credential_error, "Invalid otpauth URI")
                    return

                success = self.controller.add_oath_credential(**cred_info)
                if success:
                    GLib.idle_add(self.callback_handler.on_credential_added, cred_info['name'])
                else:
                    GLib.idle_add(self.callback_handler.on_credential_error, "Failed to add account")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_credential_error, f"Error adding account: {str(e)}")

        thread = threading.Thread(target=add_thread)
        thread.daemon = True
        thread.start()

    def parse_otpauth_uri(self, uri: str) -> Optional[Dict[str, Any]]:
        try:
            if not uri.startswith('otpauth://'):
                return None

            parsed = urlparse(uri)
            params = parse_qs(parsed.query)

            oath_type = parsed.netloc.upper()
            if oath_type not in ['TOTP', 'HOTP']:
                return None

            label = parsed.path.lstrip('/')
            if ':' in label:
                issuer, account = label.split(':', 1)
            else:
                issuer = params.get('issuer', [''])[0]
                account = label

            secret = params.get('secret', [''])[0]
            if not secret:
                return None

            digits = int(params.get('digits', ['6'])[0])
            period = int(params.get('period', ['30'])[0]) if oath_type == 'TOTP' else 30

            return {
                'name': account,
                'secret': secret,
                'issuer': issuer,
                'oath_type': oath_type,
                'digits': digits,
                'period': period
            }
        except Exception as e:
            print(f"Error parsing otpauth URI: {e}")
            return None

class DeviceManager:
    def __init__(self, controller, callback_handler):
        self.controller = controller
        self.callback_handler = callback_handler

    def load_device_info(self):
        def load_thread():
            try:
                device_info = self.controller.get_device_info()
                if device_info:
                    GLib.idle_add(self.callback_handler.on_device_info_loaded, device_info)
                else:
                    GLib.idle_add(self.callback_handler.on_no_device)
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_device_error, str(e))

        thread = threading.Thread(target=load_thread)
        thread.daemon = True
        thread.start()

    def load_piv_info(self):
        def load_thread():
            try:
                piv_info = self.controller.get_piv_info()
                GLib.idle_add(self.callback_handler.on_piv_info_loaded, piv_info)
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_piv_error, str(e))

        thread = threading.Thread(target=load_thread)
        thread.daemon = True
        thread.start()

    def load_fido_info(self):
        def load_thread():
            try:
                fido_info = self.controller.get_fido_info()
                GLib.idle_add(self.callback_handler.on_fido_info_loaded, fido_info)
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_fido_error, str(e))

        thread = threading.Thread(target=load_thread)
        thread.daemon = True
        thread.start()

    def load_application_config(self):
        def load_thread():
            try:
                config = self.controller.get_application_config()
                if config:
                    GLib.idle_add(self.callback_handler.on_application_config_loaded, config)
                else:
                    GLib.idle_add(self.callback_handler.on_application_config_error,
                                  "Failed to read application configuration")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_application_config_error,
                              f"Error reading application config: {str(e)}")

        thread = threading.Thread(target=load_thread)
        thread.daemon = True
        thread.start()

    def apply_application_config(self, otp_enabled: bool, fido_enabled: bool, ccid_enabled: bool):
        def apply_thread():
            try:
                success = self.controller.set_application_config(
                    otp_enabled, fido_enabled, ccid_enabled
                )
                if success:
                    GLib.idle_add(self.callback_handler.on_application_config_applied)
                else:
                    GLib.idle_add(self.callback_handler.on_application_config_error,
                                  "Failed to apply application configuration")
            except Exception as e:
                GLib.idle_add(self.callback_handler.on_application_config_error,
                              f"Error applying configuration: {str(e)}")

        thread = threading.Thread(target=apply_thread)
        thread.daemon = True
        thread.start()
