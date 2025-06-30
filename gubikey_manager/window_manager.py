# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import gi
from typing import Dict, List, Optional, Any, Callable

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib
from . import ui

class WindowManager:
    def __init__(self, parent_window):
        self.parent = parent_window
        self.stack = None
        self.pages = {}
        self.lists = {}
        self.bottom_sheet = None
        self.toast_overlay = None

    def setup_window_layout(self) -> tuple[Adw.ToastOverlay, Adw.HeaderBar]:
        self.toast_overlay, self.header, self.stack, self.bottom_sheet = ui.create_main_window_layout()
        self._create_all_pages()
        return self.toast_overlay, self.header

    def _create_all_pages(self):
        self._create_info_page()
        self._create_accounts_page()
        self._create_configure_page()

    def _create_info_page(self):
        scrolled, content_box = ui.create_scrolled_content_page()

        content_box.append(ui.create_section_header("Device Status"))
        status_list = ui.create_boxed_list()
        content_box.append(status_list)
        self.lists['status'] = status_list

        content_box.append(ui.create_section_header("Device Information"))
        info_list = ui.create_boxed_list()
        content_box.append(info_list)
        self.lists['info'] = info_list

        content_box.append(ui.create_section_header("Applications"))
        apps_list = ui.create_boxed_list()
        content_box.append(apps_list)
        self.lists['apps'] = apps_list

        content_box.append(ui.create_section_header("PIV (Smart Card)"))
        piv_list = ui.create_boxed_list()
        content_box.append(piv_list)
        self.lists['piv'] = piv_list

        content_box.append(ui.create_section_header("FIDO/WebAuthn"))
        fido_list = ui.create_boxed_list()
        content_box.append(fido_list)
        self.lists['fido'] = fido_list

        self.stack.add_titled_with_icon(scrolled, "info", "Info", "dialog-information-symbolic")
        self.pages['info'] = scrolled

    def _create_accounts_page(self):
        scrolled, content_box = ui.create_scrolled_content_page()

        add_callback = getattr(self.parent, 'show_add_credential_dialog', None)
        header_box = ui.create_accounts_header_with_add_button(add_callback)
        content_box.append(header_box)

        accounts_list = ui.create_boxed_list()
        content_box.append(accounts_list)
        self.lists['accounts'] = accounts_list

        content_box.append(ui.create_section_header("Actions"))
        accounts_actions_list = ui.create_boxed_list()
        content_box.append(accounts_actions_list)
        self.lists['accounts_actions'] = accounts_actions_list

        self.stack.add_titled_with_icon(scrolled, "accounts", "Accounts", "system-users-symbolic")
        self.pages['accounts'] = scrolled

    def _create_configure_page(self):
        scrolled, content_box = ui.create_scrolled_content_page()

        content_box.append(ui.create_section_header("Enable/Disable Applications"))
        configure_apps_list = ui.create_boxed_list()
        content_box.append(configure_apps_list)
        self.lists['configure_apps'] = configure_apps_list

        content_box.append(ui.create_section_header("PIN & Password Management"))
        pin_management_list = ui.create_boxed_list()
        content_box.append(pin_management_list)
        self.lists['pin_management'] = pin_management_list

        content_box.append(ui.create_section_header("Reset Operations"))
        reset_actions_list = ui.create_boxed_list()
        content_box.append(reset_actions_list)
        self.lists['reset_actions'] = reset_actions_list

        content_box.append(ui.create_section_header("Other Actions"))
        other_actions_list = ui.create_boxed_list()
        content_box.append(other_actions_list)
        self.lists['other_actions'] = other_actions_list

        self.stack.add_titled_with_icon(scrolled, "configure", "Configure", "emblem-system-symbolic")
        self.pages['configure'] = scrolled

    def get_list(self, list_name: str) -> Optional[Gtk.ListBox]:
        return self.lists.get(list_name)

    def clear_list(self, list_name: str):
        list_widget = self.get_list(list_name)
        if list_widget:
            ui.clear_list_widget(list_widget)

    def add_to_list(self, list_name: str, row: Gtk.Widget):
        list_widget = self.get_list(list_name)
        if list_widget:
            list_widget.append(row)

    def show_toast(self, message: str):
        print(f"Toast: {message}")
        toast = Adw.Toast(title=message)
        self.toast_overlay.add_toast(toast)

    def show_application_config_bottom_sheet(self, current_config: Dict[str, Any], apply_callback: Callable):
        def handle_apply(widgets):
            otp_enabled = widgets['otp_switch'].get_active()
            fido_enabled = widgets['fido_switch'].get_active()
            ccid_enabled = widgets['ccid_switch'].get_active()

            if not (otp_enabled or fido_enabled or ccid_enabled):
                self.show_toast("Error: At least one application must be enabled")
                return

            apply_callback(otp_enabled, fido_enabled, ccid_enabled)
            self.bottom_sheet.set_open(False)

        def handle_cancel():
            self.bottom_sheet.set_open(False)

        return ui.create_application_config_bottom_sheet(
            self.bottom_sheet, current_config, handle_apply, handle_cancel
        )

    def show_add_credential_bottom_sheet(self, choice_callback: Callable):
        def handle_choice(choice):
            self.bottom_sheet.set_open(False)
            choice_callback(choice)

        def handle_cancel():
            self.bottom_sheet.set_open(False)

        return ui.create_add_credential_bottom_sheet(
            self.bottom_sheet, handle_choice, handle_cancel
        )

class DeviceInfoManager:
    def __init__(self, window_manager: WindowManager):
        self.wm = window_manager

    def update_status(self, title: str, icon_name: str, subtitle: str = None):
        self.wm.clear_list('status')
        row = ui.create_status_row(title, icon_name, subtitle)
        self.wm.add_to_list('status', row)

    def update_device_details(self, device_info: Dict[str, Any]):
        self.wm.clear_list('info')
        self.wm.add_to_list('info', ui.create_info_row(
            "Device Type",
            device_info.get('device_type', 'Unknown'),
            "computer-symbolic"
        ))
        self.wm.add_to_list('info', ui.create_info_row(
            "Serial Number",
            device_info.get('serial', 'Unknown'),
            "preferences-system-symbolic"
        ))
        self.wm.add_to_list('info', ui.create_info_row(
            "Firmware Version",
            device_info.get('version', 'Unknown'),
            "system-software-install-symbolic"
        ))

        if device_info.get('form_factor'):
            self.wm.add_to_list('info', ui.create_info_row(
                "Form Factor",
                device_info['form_factor'],
                "multimedia-player-symbolic"
            ))

    def update_applications(self, device_info: Dict[str, Any]):
        self.wm.clear_list('apps')

        applications = device_info.get('applications', {})
        if not applications:
            self.wm.add_to_list('apps', ui.create_placeholder_row(
                "No applications found",
                "Applications not detected",
                "application-x-executable-symbolic"
            ))
            return

        for app_name, app_info in applications.items():
            enabled = app_info.get('enabled', False)
            icon_name = "object-select-symbolic" if enabled else "dialog-warning-symbolic"
            status = "Enabled" if enabled else "Disabled"

            self.wm.add_to_list('apps', ui.create_info_row(
                f"{app_name.upper()}",
                status,
                icon_name
            ))

    def update_piv_info(self, piv_info: Optional[Dict[str, Any]]):
        self.wm.clear_list('piv')

        if not piv_info:
            self.wm.add_to_list('piv', ui.create_placeholder_row(
                "PIV not initialized",
                "Initialize PIV application for smart card features",
                "security-medium-symbolic"
            ))
            return

        self.wm.add_to_list('piv', ui.create_info_row(
            "PIV Version",
            piv_info.get('version', 'Unknown'),
            "security-medium-symbolic"
        ))

        pin_attempts = piv_info.get('pin_attempts', 'Unknown')
        self.wm.add_to_list('piv', ui.create_info_row(
            "PIN Attempts Remaining",
            pin_attempts,
            "dialog-password-symbolic"
        ))

        certificates = piv_info.get('certificates', {})
        for slot, cert_info in certificates.items():
            if cert_info and cert_info.get('installed'):
                self.wm.add_to_list('piv', ui.create_info_row(
                    f"Certificate Slot {slot}",
                    cert_info.get('subject', 'Installed'),
                    "security-high-symbolic"
                ))

    def update_fido_info(self, fido_info: Optional[Dict[str, Any]]):
        self.wm.clear_list('fido')

        if not fido_info:
            self.wm.add_to_list('fido', ui.create_placeholder_row(
                "FIDO not available",
                "FIDO/WebAuthn not supported or configured",
                "security-high-symbolic"
            ))
            return

        self.wm.add_to_list('fido', ui.create_info_row(
            "FIDO2 Version",
            fido_info.get('version', 'Unknown'),
            "security-high-symbolic"
        ))

        pin_set = fido_info.get('pin_set', False)
        pin_status = "Set" if pin_set else "Not Set"
        self.wm.add_to_list('fido', ui.create_info_row(
            "PIN Status",
            pin_status,
            "dialog-password-symbolic"
        ))

        cred_count = fido_info.get('credential_count', 0)
        self.wm.add_to_list('fido', ui.create_info_row(
            "Resident Keys",
            f"{cred_count} stored",
            "preferences-system-symbolic"
        ))

    def show_no_device(self):
        self.update_status("No YubiKey detected", "dialog-warning-symbolic", "Please insert your YubiKey")

        for list_name in ['info', 'apps', 'piv', 'fido']:
            self.wm.clear_list(list_name)

        self.wm.add_to_list('info', ui.create_placeholder_row(
            "No device detected", "Insert your YubiKey", "dialog-information-symbolic"
        ))
        self.wm.add_to_list('apps', ui.create_placeholder_row(
            "No applications", "Connect YubiKey to see available applications", "application-x-executable-symbolic"
        ))
        self.wm.add_to_list('piv', ui.create_placeholder_row(
            "PIV not configured", "Setup PIV for smart card functionality", "security-medium-symbolic"
        ))
        self.wm.add_to_list('fido', ui.create_placeholder_row(
            "FIDO not configured", "Setup FIDO for WebAuthn", "security-high-symbolic"
        ))

    def show_error(self, error_message: str):
        self.update_status("Error", "dialog-error-symbolic", error_message)

class AccountsManager:
    def __init__(self, window_manager: WindowManager):
        self.wm = window_manager

    def update_credentials(self, credentials: List[Dict[str, Any]]):
        self.wm.clear_list('accounts')
        self.wm.clear_list('accounts_actions')

        if not credentials:
            self.wm.add_to_list('accounts', ui.create_placeholder_row(
                "No accounts",
                "Add TOTP/HOTP accounts to your YubiKey",
                "system-users-symbolic"
            ))
        else:
            generate_callback = getattr(self.wm.parent, 'generate_oath_code', None)
            delete_callback = getattr(self.wm.parent, 'delete_oath_credential_confirm', None)

            for cred in credentials:
                row = ui.create_account_row(cred, generate_callback, delete_callback)
                self.wm.add_to_list('accounts', row)

        reset_callback = getattr(self.wm.parent, 'reset_oath', None)
        if reset_callback:
            self.wm.add_to_list('accounts_actions', ui.create_action_row(
                "Reset All Accounts",
                "Remove all OATH credentials (cannot be undone)",
                "edit-delete-symbolic",
                lambda row: reset_callback()
            ))

    def show_error(self, error: str):
        self.wm.clear_list('accounts')
        self.wm.clear_list('accounts_actions')
        self.wm.add_to_list('accounts', ui.create_placeholder_row(
            "OATH Error", error, "dialog-error-symbolic"
        ))

    def show_no_device(self):
        self.wm.clear_list('accounts')
        self.wm.clear_list('accounts_actions')
        self.wm.add_to_list('accounts', ui.create_placeholder_row(
            "No accounts", "Add accounts to see TOTP/HOTP codes", "system-users-symbolic"
        ))

class ConfigurationManager:
    def __init__(self, window_manager: WindowManager):
        self.wm = window_manager

    def setup_configuration_actions(self):
        self.wm.clear_list('configure_apps')
        self.wm.clear_list('pin_management')
        self.wm.clear_list('reset_actions')
        self.wm.clear_list('other_actions')

        # Application Configuration
        configure_callback = getattr(self.wm.parent, 'configure_interfaces', None)
        if configure_callback:
            self.wm.add_to_list('configure_apps', ui.create_action_row(
                "Configure Applications",
                "Enable/disable YubiKey applications",
                "preferences-system-symbolic",
                lambda row: configure_callback()
            ))

        # PIN & Password Management
        self.wm.add_to_list('pin_management', ui.create_action_row(
            "Set OATH Password",
            "Protect OATH credentials with a password",
            "dialog-password-symbolic",
            lambda row: self.show_oath_password_dialog()
        ))

        self.wm.add_to_list('pin_management', ui.create_action_row(
            "Change PIV PIN",
            "Change PIV application PIN",
            "dialog-password-symbolic",
            lambda row: self.show_piv_pin_dialog()
        ))

        self.wm.add_to_list('pin_management', ui.create_action_row(
            "Change PIV PUK",
            "Change PIV application PUK",
            "dialog-password-symbolic",
            lambda row: self.show_piv_puk_dialog()
        ))

        self.wm.add_to_list('pin_management', ui.create_action_row(
            "Set FIDO PIN",
            "Set FIDO/WebAuthn PIN",
            "dialog-password-symbolic",
            lambda row: self.show_fido_set_pin_dialog()
        ))

        self.wm.add_to_list('pin_management', ui.create_action_row(
            "Change FIDO PIN",
            "Change FIDO/WebAuthn PIN",
            "dialog-password-symbolic",
            lambda row: self.show_fido_change_pin_dialog()
        ))

        # Reset Operations
        self.wm.add_to_list('reset_actions', ui.create_action_row(
            "Reset PIV",
            "Reset PIV application to factory defaults",
            "edit-delete-symbolic",
            lambda row: self.show_reset_piv_dialog()
        ))

        self.wm.add_to_list('reset_actions', ui.create_action_row(
            "Reset FIDO",
            "Reset FIDO application to factory defaults",
            "edit-delete-symbolic",
            lambda row: self.show_reset_fido_dialog()
        ))

        # Other Actions
        factory_reset_callback = getattr(self.wm.parent, 'factory_reset', None)
        if factory_reset_callback:
            self.wm.add_to_list('other_actions', ui.create_action_row(
                "Factory Reset",
                "Reset entire device to factory defaults (destructive)",
                "edit-delete-symbolic",
                lambda row: factory_reset_callback()
            ))

    def show_oath_password_dialog(self):
        self.wm.parent.dialog_manager.show_oath_password_dialog()

    def show_piv_pin_dialog(self):
        self.wm.parent.dialog_manager.show_piv_pin_dialog(is_change_pin=True)

    def show_piv_puk_dialog(self):
        self.wm.parent.dialog_manager.show_piv_puk_dialog()

    def show_reset_piv_dialog(self):
        self.wm.parent.dialog_manager.show_reset_piv_dialog()

    def show_fido_set_pin_dialog(self):
        self.wm.parent.dialog_manager.show_fido_pin_dialog(is_change_pin=False)

    def show_fido_change_pin_dialog(self):
        self.wm.parent.dialog_manager.show_fido_pin_dialog(is_change_pin=True)

    def show_reset_fido_dialog(self):
        self.wm.parent.dialog_manager.show_reset_fido_dialog()

    def show_no_device(self):
        self.wm.clear_list('configure_apps')
        self.wm.clear_list('pin_management')
        self.wm.clear_list('reset_actions')
        self.wm.clear_list('other_actions')

        self.wm.add_to_list('configure_apps', ui.create_placeholder_row(
            "No applications", "Connect YubiKey to configure applications", "emblem-system-symbolic"
        ))
        self.wm.add_to_list('pin_management', ui.create_placeholder_row(
            "No PIN management", "Connect YubiKey to manage PINs and passwords", "dialog-password-symbolic"
        ))
        self.wm.add_to_list('reset_actions', ui.create_placeholder_row(
            "No reset actions", "Connect YubiKey to access reset operations", "edit-delete-symbolic"
        ))
        self.wm.add_to_list('other_actions', ui.create_placeholder_row(
            "No actions available", "Connect YubiKey to see available actions", "system-run-symbolic"
        ))

class DialogManager:
    def __init__(self, parent_window):
        self.parent = parent_window

    def show_add_credential_choice(self, callback: Callable):
        dialog = ui.create_message_dialog(
            self.parent,
            "Add Account",
            "Choose how to add your 2FA account",
            [
                ("cancel", "Cancel", None),
                ("manual", "Manual Entry", None),
                ("qr", "Scan QR Code", Adw.ResponseAppearance.SUGGESTED),
                ("uri", "From URI", None)
            ]
        )
        dialog.connect("response", lambda d, r: callback(d, r))
        dialog.present()
        return dialog

    def show_manual_credential_dialog(self, add_callback: Callable):
        dialog, widgets = ui.create_manual_credential_dialog(self.parent)
        widgets['cancel_button'].connect('clicked', lambda btn: dialog.close())
        widgets['add_button'].connect('clicked', lambda btn: add_callback(dialog, widgets))
        dialog.present()
        return dialog, widgets

    def show_uri_credential_dialog(self, add_callback: Callable):
        dialog, entry = ui.create_uri_credential_dialog(self.parent)
        dialog.connect("response", lambda d, r: add_callback(d, r, entry))
        dialog.present()
        return dialog, entry

    def show_camera_dialog(self, cameras: List):
        dialog, widgets = ui.create_camera_dialog(self.parent, cameras)

        dialog.present(self.parent)

        widgets['cancel_button'].connect('clicked', lambda btn: dialog.close())

        if len(cameras) > 1:
            for i, camera in enumerate(cameras):
                if f'camera_row_{i}' in widgets:
                    widgets[f'camera_row_{i}'].connect('activated',
                        lambda row, idx=i: print(f"Camera {idx} selected"))
        return dialog, widgets

    def show_confirmation_dialog(self, heading: str, body: str, confirm_callback: Callable):
        dialog = ui.create_message_dialog(
            self.parent,
            heading,
            body,
            [
                ("cancel", "Cancel", None),
                ("confirm", "Confirm", Adw.ResponseAppearance.DESTRUCTIVE)
            ]
        )
        dialog.connect("response", lambda d, r: confirm_callback(d, r))
        dialog.present()
        return dialog

    def show_oath_code_dialog(self, credential_name: str, code: str, copy_callback: Callable):
        dialog = ui.create_oath_code_dialog(self.parent, credential_name, code)
        dialog.connect("response", lambda d, r: copy_callback(d, r, code))
        dialog.present()
        return dialog

    def show_about_dialog(self):
        about_dialog = ui.create_about_dialog(self.parent)
        about_dialog.present(self.parent)
        return about_dialog

    def show_fido_pin_dialog(self, is_change_pin: bool = False):
        title = "Change FIDO PIN" if is_change_pin else "Set FIDO PIN"
        dialog, widgets = ui.create_pin_dialog(self.parent, title, is_change_pin)

        def validate_and_submit():
            new_pin = widgets['new_pin_row'].get_text()
            confirm_pin = widgets['confirm_pin_row'].get_text()

            if len(new_pin) < 4 or len(new_pin) > 63:
                self.parent.window_manager.show_toast("FIDO PIN must be 4-63 characters")
                return

            if new_pin != confirm_pin:
                self.parent.window_manager.show_toast("PIN confirmation does not match")
                return

            if is_change_pin:
                current_pin = widgets['current_pin_row'].get_text()
                if not current_pin:
                    self.parent.window_manager.show_toast("Current PIN is required")
                    return
                success = self.parent.yk_controller.change_fido_pin(current_pin, new_pin)
            else:
                success = self.parent.yk_controller.set_fido_pin(new_pin)

            if success:
                self.parent.window_manager.show_toast("FIDO PIN " + ("changed" if is_change_pin else "set") + " successfully")
                dialog.close()
                self.parent.device_manager.load_fido_info()
            else:
                self.parent.window_manager.show_toast("Failed to " + ("change" if is_change_pin else "set") + " FIDO PIN")

        widgets['set_button'].connect('clicked', lambda btn: validate_and_submit())
        widgets['cancel_button'].connect('clicked', lambda btn: dialog.close())

        dialog.present()
        return dialog

    def show_piv_pin_dialog(self, is_change_pin: bool = False):
        title = "Change PIV PIN" if is_change_pin else "Set PIV PIN"
        dialog, widgets = ui.create_pin_dialog(self.parent, title, is_change_pin)

        def validate_and_submit():
            new_pin = widgets['new_pin_row'].get_text()
            confirm_pin = widgets['confirm_pin_row'].get_text()

            if len(new_pin) < 6 or len(new_pin) > 8 or not new_pin.isdigit():
                self.parent.window_manager.show_toast("PIV PIN must be 6-8 digits")
                return

            if new_pin != confirm_pin:
                self.parent.window_manager.show_toast("PIN confirmation does not match")
                return

            if is_change_pin:
                current_pin = widgets['current_pin_row'].get_text()
                if not current_pin:
                    self.parent.window_manager.show_toast("Current PIN is required")
                    return
                success = self.parent.yk_controller.change_piv_pin(current_pin, new_pin)
            else:
                self.parent.window_manager.show_toast("PIV PIN can only be changed, not set initially")
                return

            if success:
                self.parent.window_manager.show_toast("PIV PIN changed successfully")
                dialog.close()
                self.parent.device_manager.load_piv_info()
            else:
                self.parent.window_manager.show_toast("Failed to change PIV PIN")

        widgets['set_button'].connect('clicked', lambda btn: validate_and_submit())
        widgets['cancel_button'].connect('clicked', lambda btn: dialog.close())

        dialog.present()
        return dialog

    def show_piv_puk_dialog(self):
        dialog, widgets = ui.create_pin_dialog(self.parent, "Change PIV PUK", True)

        def validate_and_submit():
            current_puk = widgets['current_pin_row'].get_text()
            new_puk = widgets['new_pin_row'].get_text()
            confirm_puk = widgets['confirm_pin_row'].get_text()

            if len(new_puk) != 8 or not new_puk.isdigit():
                self.parent.window_manager.show_toast("PIV PUK must be exactly 8 digits")
                return

            if new_puk != confirm_puk:
                self.parent.window_manager.show_toast("PUK confirmation does not match")
                return

            if not current_puk:
                self.parent.window_manager.show_toast("Current PUK is required")
                return

            success = self.parent.yk_controller.change_piv_puk(current_puk, new_puk)
            if success:
                self.parent.window_manager.show_toast("PIV PUK changed successfully")
                dialog.close()
                self.parent.device_manager.load_piv_info()
            else:
                self.parent.window_manager.show_toast("Failed to change PIV PUK")

        widgets['set_button'].set_label("Change PUK")
        widgets['current_pin_row'].set_title("Current PUK")
        widgets['new_pin_row'].set_title("New PUK")
        widgets['confirm_pin_row'].set_title("Confirm PUK")

        widgets['set_button'].connect('clicked', lambda btn: validate_and_submit())
        widgets['cancel_button'].connect('clicked', lambda btn: dialog.close())

        dialog.present()
        return dialog

    def show_oath_password_dialog(self):
        dialog, widgets = ui.create_password_dialog(self.parent)

        def validate_and_submit():
            password = widgets['password_row'].get_text()
            confirm_password = widgets['confirm_password_row'].get_text()

            if len(password) < 1:
                self.parent.window_manager.show_toast("Password cannot be empty")
                return

            if password != confirm_password:
                self.parent.window_manager.show_toast("Password confirmation does not match")
                return

            success = self.parent.yk_controller.set_oath_password(password)
            if success:
                self.parent.window_manager.show_toast("OATH password set successfully")
                dialog.close()
            else:
                self.parent.window_manager.show_toast("Failed to set OATH password")

        widgets['set_button'].connect('clicked', lambda btn: validate_and_submit())
        widgets['cancel_button'].connect('clicked', lambda btn: dialog.close())

        dialog.present()
        return dialog

    def show_reset_piv_dialog(self):
        dialog = ui.create_reset_confirmation_dialog(
            self.parent,
            "PIV",
            "All PIV certificates, keys, and PIN will be reset to defaults."
        )

        def handle_response(dialog, response):
            if response == "reset":
                success = self.parent.yk_controller.reset_piv()
                if success:
                    self.parent.window_manager.show_toast("PIV application reset successfully")
                    self.parent.device_manager.load_device_info()
                    self.parent.device_manager.load_piv_info()
                else:
                    self.parent.window_manager.show_toast("Failed to reset PIV application")
            dialog.close()

        dialog.connect("response", handle_response)
        dialog.present()
        return dialog

    def show_reset_fido_dialog(self):
        dialog = ui.create_reset_confirmation_dialog(
            self.parent,
            "FIDO",
            "All FIDO credentials and PIN will be permanently deleted."
        )

        def handle_response(dialog, response):
            if response == "reset":
                success = self.parent.yk_controller.reset_fido()
                if success:
                    self.parent.window_manager.show_toast("FIDO application reset successfully")
                    self.parent.device_manager.load_device_info()
                    self.parent.device_manager.load_fido_info()
                else:
                    self.parent.window_manager.show_toast("Failed to reset FIDO application")
            dialog.close()

        dialog.connect("response", handle_response)
        dialog.present()
        return dialog
