# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import gi
from typing import Callable, Optional, List, Dict, Any

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Pango, Gio

def create_header_bar(title: str = "Gubikey Manager") -> Adw.HeaderBar:
    header = Adw.HeaderBar()
    header.set_title_widget(Adw.WindowTitle(title=title))

    menu_button = Gtk.MenuButton()
    menu_button.set_icon_name("open-menu-symbolic")
    menu_model = Gio.Menu()
    menu_model.append("Refresh Device", "win.refresh")
    menu_model.append("About", "win.about")
    menu_button.set_menu_model(menu_model)
    header.pack_end(menu_button)

    return header

def create_view_stack() -> Adw.ViewStack:
    return Adw.ViewStack()

def create_view_switcher_bar(stack: Adw.ViewStack) -> Adw.ViewSwitcherBar:
    view_switcher_bar = Adw.ViewSwitcherBar()
    view_switcher_bar.set_stack(stack)
    view_switcher_bar.set_reveal(True)
    view_switcher_bar.set_margin_top(6)
    view_switcher_bar.set_margin_bottom(6)
    return view_switcher_bar

def create_scrolled_content_page() -> tuple[Gtk.ScrolledWindow, Gtk.Box]:
    scrolled = Gtk.ScrolledWindow()
    scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scrolled.set_vexpand(True)
    scrolled.set_hexpand(True)

    content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content_box.set_margin_top(12)
    content_box.set_margin_bottom(12)
    content_box.set_margin_start(12)
    content_box.set_margin_end(12)
    content_box.set_vexpand(False)
    content_box.set_valign(Gtk.Align.START)

    scrolled.set_child(content_box)
    return scrolled, content_box

def create_section_header(title: str) -> Gtk.Label:
    label = Gtk.Label(label=title)
    label.set_halign(Gtk.Align.START)
    label.set_margin_bottom(6)
    label.set_margin_top(12)
    attr_list = Pango.AttrList()
    attr_list.insert(Pango.attr_weight_new(Pango.Weight.BOLD))
    label.set_attributes(attr_list)
    return label

def create_boxed_list() -> Gtk.ListBox:
    list_box = Gtk.ListBox()
    list_box.set_selection_mode(Gtk.SelectionMode.NONE)
    list_box.add_css_class("boxed-list")
    return list_box

def create_status_row(title: str, icon_name: str, subtitle: str = None) -> Adw.ActionRow:
    row = Adw.ActionRow()
    row.set_title(title)
    if subtitle:
        row.set_subtitle(subtitle)

    icon = Gtk.Image()
    icon.set_from_icon_name(icon_name)
    row.add_prefix(icon)

    return row

def create_placeholder_row(title: str, subtitle: str, icon_name: str) -> Adw.ActionRow:
    row = Adw.ActionRow()
    row.set_title(title)
    row.set_subtitle(subtitle)

    icon = Gtk.Image()
    icon.set_from_icon_name(icon_name)
    row.add_prefix(icon)

    return row

def create_info_row(title: str, value: str, icon_name: str) -> Adw.ActionRow:
    row = Adw.ActionRow()
    row.set_title(title)
    row.set_subtitle(str(value))

    icon = Gtk.Image()
    icon.set_from_icon_name(icon_name)
    row.add_prefix(icon)

    return row

def create_action_row(title: str, subtitle: str, icon_name: str, callback: Callable = None) -> Adw.ActionRow:
    row = Adw.ActionRow()
    row.set_title(title)
    row.set_subtitle(subtitle)

    if callback:
        row.set_activatable(True)
        row.connect('activated', callback)

    icon = Gtk.Image()
    icon.set_from_icon_name(icon_name)
    row.add_prefix(icon)

    arrow = Gtk.Image()
    arrow.set_from_icon_name("go-next-symbolic")
    row.add_suffix(arrow)

    return row

def create_account_row(credential: Dict[str, Any],
                       generate_callback: Callable = None,
                       delete_callback: Callable = None) -> Adw.ActionRow:
    name = credential.get('name', 'Unknown')
    oath_type = credential.get('oath_type', 'TOTP')
    issuer = credential.get('issuer', '')

    subtitle = f"{oath_type}"
    if issuer:
        subtitle += f" - {issuer}"

    row = Adw.ActionRow()
    row.set_title(name)
    row.set_subtitle(subtitle)

    if generate_callback:
        row.set_activatable(True)
        row.connect('activated', lambda r: generate_callback(name))

    icon = Gtk.Image()
    icon.set_from_icon_name("preferences-system-time-symbolic")
    row.add_prefix(icon)

    if delete_callback:
        delete_button = Gtk.Button()
        delete_button.set_icon_name("user-trash-symbolic")
        delete_button.add_css_class("flat")
        delete_button.set_tooltip_text("Delete account")
        delete_button.connect('clicked', lambda btn: delete_callback(name))
        row.add_suffix(delete_button)

    if generate_callback:
        generate_button = Gtk.Button()
        generate_button.set_icon_name("media-playlist-repeat-symbolic")
        generate_button.add_css_class("flat")
        generate_button.set_tooltip_text("Generate code")
        generate_button.connect('clicked', lambda btn: generate_callback(name))
        row.add_suffix(generate_button)

    return row

def create_accounts_header_with_add_button(add_callback: Callable = None) -> Gtk.Box:
    header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    header_box.set_margin_bottom(6)

    accounts_label = Gtk.Label(label="Accounts")
    accounts_label.set_halign(Gtk.Align.START)
    accounts_label.set_hexpand(True)
    attr_list = Pango.AttrList()
    attr_list.insert(Pango.attr_weight_new(Pango.Weight.BOLD))
    accounts_label.set_attributes(attr_list)
    header_box.append(accounts_label)

    if add_callback:
        add_button = Gtk.Button()
        add_button.set_icon_name("list-add-symbolic")
        add_button.set_tooltip_text("Add new account")
        add_button.connect('clicked', lambda btn: add_callback())
        header_box.append(add_button)

    return header_box

def create_message_dialog(parent, heading: str, body: str, responses: List[tuple]) -> Adw.MessageDialog:
    dialog = Adw.MessageDialog(
        transient_for=parent,
        heading=heading,
        body=body
    )

    for response_id, response_text, appearance in responses:
        dialog.add_response(response_id, response_text)
        if appearance:
            dialog.set_response_appearance(response_id, appearance)

    return dialog

def create_manual_credential_dialog(parent) -> tuple[Adw.Window, Dict[str, Gtk.Widget]]:
    dialog = Adw.Window()
    dialog.set_title("Add Account Manually")
    dialog.set_transient_for(parent)
    dialog.set_modal(True)
    dialog.set_default_size(400, 500)

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content.set_margin_top(24)
    content.set_margin_bottom(24)
    content.set_margin_start(24)
    content.set_margin_end(24)

    header = Adw.HeaderBar()
    header.set_title_widget(Adw.WindowTitle(title="Add Account Manually"))

    cancel_button = Gtk.Button(label="Cancel")
    header.pack_start(cancel_button)

    add_button = Gtk.Button(label="Add")
    add_button.add_css_class("suggested-action")
    header.pack_end(add_button)

    form_group = Adw.PreferencesGroup()
    form_group.set_title("Account Information")

    account_row = Adw.EntryRow()
    account_row.set_title("Account Name")
    account_row.set_text("")
    form_group.add(account_row)

    issuer_row = Adw.EntryRow()
    issuer_row.set_title("Issuer (Optional)")
    issuer_row.set_text("")
    form_group.add(issuer_row)

    secret_row = Adw.PasswordEntryRow()
    secret_row.set_title("Secret Key")
    secret_row.set_text("")
    form_group.add(secret_row)

    type_row = Adw.ComboRow()
    type_row.set_title("Type")
    type_model = Gtk.StringList()
    type_model.append("TOTP (Time-based)")
    type_model.append("HOTP (Counter-based)")
    type_row.set_model(type_model)
    type_row.set_selected(0)
    form_group.add(type_row)

    content.append(form_group)

    advanced_group = Adw.PreferencesGroup()
    advanced_group.set_title("Advanced Settings")

    digits_row = Adw.SpinRow()
    digits_row.set_title("Digits")
    digits_adjustment = Gtk.Adjustment(value=6, lower=6, upper=8, step_increment=1)
    digits_row.set_adjustment(digits_adjustment)
    advanced_group.add(digits_row)

    period_row = Adw.SpinRow()
    period_row.set_title("Period (seconds)")
    period_adjustment = Gtk.Adjustment(value=30, lower=15, upper=300, step_increment=15)
    period_row.set_adjustment(period_adjustment)
    advanced_group.add(period_row)

    content.append(advanced_group)

    main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    main_box.append(header)
    main_box.append(content)
    dialog.set_content(main_box)

    widgets = {
        'dialog': dialog,
        'cancel_button': cancel_button,
        'add_button': add_button,
        'account_row': account_row,
        'issuer_row': issuer_row,
        'secret_row': secret_row,
        'type_row': type_row,
        'digits_row': digits_row,
        'period_row': period_row
    }

    return dialog, widgets

def create_uri_credential_dialog(parent) -> tuple[Adw.MessageDialog, Gtk.Entry]:
    dialog = Adw.MessageDialog(
        transient_for=parent,
        heading="Add from URI",
        body="Paste the otpauth:// URI from your QR code:"
    )

    entry = Gtk.Entry()
    entry.set_placeholder_text("otpauth://totp/Example:user@example.com?secret=...")
    entry.set_margin_top(12)
    entry.set_margin_bottom(12)
    entry.set_margin_start(12)
    entry.set_margin_end(12)

    dialog.set_extra_child(entry)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("add", "Add")
    dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

    return dialog, entry

def create_camera_dialog(parent, cameras: List) -> tuple[Adw.Dialog, Dict[str, Gtk.Widget]]:
    dialog = Adw.Dialog()
    dialog.set_title("QR Code Scanner")

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content.set_margin_top(12)
    content.set_margin_bottom(12)
    content.set_margin_start(12)
    content.set_margin_end(12)

    header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    header_box.set_margin_bottom(12)

    cancel_button = Gtk.Button(label="Cancel")
    cancel_button.add_css_class("destructive-action")
    header_box.append(cancel_button)

    content.append(header_box)

    viewfinder_group = Adw.PreferencesGroup()
    viewfinder_group.set_title("Camera Preview")

    viewfinder_frame = Gtk.Frame()
    viewfinder_frame.set_size_request(320, 240)
    viewfinder_frame.set_halign(Gtk.Align.CENTER)
    viewfinder_frame.set_margin_top(6)
    viewfinder_frame.set_margin_bottom(6)

    viewfinder_placeholder = Gtk.Label()
    viewfinder_placeholder.set_text("Starting camera...")
    viewfinder_placeholder.set_halign(Gtk.Align.CENTER)
    viewfinder_placeholder.set_valign(Gtk.Align.CENTER)
    viewfinder_frame.set_child(viewfinder_placeholder)

    viewfinder_group.add(viewfinder_frame)
    content.append(viewfinder_group)

    camera_widgets = {}
    if len(cameras) > 1:
        camera_group = Adw.PreferencesGroup()
        camera_group.set_title("Camera Selection")

        camera_expander = Adw.ExpanderRow()
        camera_expander.set_title("Switch Camera")
        camera_expander.set_subtitle(f"Current: {cameras[0].name}")

        for i, camera in enumerate(cameras):
            camera_row = Adw.ActionRow()
            camera_row.set_title(camera.name)
            camera_row.set_subtitle(f"Object ID: {camera.object_id}")
            camera_row.set_activatable(True)

            camera_icon = Gtk.Image()
            camera_icon.set_from_icon_name("camera-web-symbolic")
            camera_row.add_prefix(camera_icon)

            if i == 0:
                selected_icon = Gtk.Image()
                selected_icon.set_from_icon_name("object-select-symbolic")
                camera_row.add_suffix(selected_icon)
                camera_widgets[f'selected_icon_{i}'] = selected_icon

            camera_expander.add_row(camera_row)
            camera_widgets[f'camera_row_{i}'] = camera_row

        camera_group.add(camera_expander)
        content.append(camera_group)
        camera_widgets['camera_expander'] = camera_expander

    status_group = Adw.PreferencesGroup()
    status_group.set_title("Status")

    qr_status_row = Adw.ActionRow()
    qr_status_row.set_title("QR Detection")
    qr_status_row.set_subtitle("Point a QR code at the camera")
    qr_icon = Gtk.Image()
    qr_icon.set_from_icon_name("find-location-symbolic")
    qr_status_row.add_prefix(qr_icon)
    status_group.add(qr_status_row)

    content.append(status_group)

    dialog.set_child(content)

    widgets = {
        'dialog': dialog,
        'cancel_button': cancel_button,
        'viewfinder_frame': viewfinder_frame,
        'viewfinder_placeholder': viewfinder_placeholder,
        'qr_status_row': qr_status_row,
        **camera_widgets
    }

    return dialog, widgets

def create_pin_dialog(parent, title: str, is_change_pin: bool = False) -> tuple[Adw.Window, Dict[str, Gtk.Widget]]:
    """Create a dialog for setting or changing PINs"""
    dialog = Adw.Window()
    dialog.set_title(title)
    dialog.set_transient_for(parent)
    dialog.set_modal(True)
    dialog.set_default_size(400, 300)

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content.set_margin_top(24)
    content.set_margin_bottom(24)
    content.set_margin_start(24)
    content.set_margin_end(24)

    header = Adw.HeaderBar()
    header.set_title_widget(Adw.WindowTitle(title=title))

    cancel_button = Gtk.Button(label="Cancel")
    header.pack_start(cancel_button)

    set_button = Gtk.Button(label="Change" if is_change_pin else "Set")
    set_button.add_css_class("suggested-action")
    header.pack_end(set_button)

    form_group = Adw.PreferencesGroup()
    form_group.set_title("PIN Management")

    if is_change_pin:
        current_pin_row = Adw.PasswordEntryRow()
        current_pin_row.set_title("Current PIN")
        form_group.add(current_pin_row)

    new_pin_row = Adw.PasswordEntryRow()
    new_pin_row.set_title("New PIN" if is_change_pin else "PIN")
    form_group.add(new_pin_row)

    confirm_pin_row = Adw.PasswordEntryRow()
    confirm_pin_row.set_title("Confirm PIN")
    form_group.add(confirm_pin_row)

    content.append(form_group)

    info_group = Adw.PreferencesGroup()
    info_group.set_title("Requirements")

    info_row = Adw.ActionRow()
    info_row.set_title("PIN Requirements")
    info_row.set_subtitle("FIDO PIN: 4-63 characters\nPIV PIN: 6-8 digits")
    info_icon = Gtk.Image()
    info_icon.set_from_icon_name("dialog-information-symbolic")
    info_row.add_prefix(info_icon)
    info_group.add(info_row)

    content.append(info_group)

    main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    main_box.append(header)
    main_box.append(content)
    dialog.set_content(main_box)

    widgets = {
        'dialog': dialog,
        'cancel_button': cancel_button,
        'set_button': set_button,
        'new_pin_row': new_pin_row,
        'confirm_pin_row': confirm_pin_row
    }

    if is_change_pin:
        widgets['current_pin_row'] = current_pin_row

    return dialog, widgets

def create_password_dialog(parent, title: str = "Set OATH Password") -> tuple[Adw.Window, Dict[str, Gtk.Widget]]:
    dialog = Adw.Window()
    dialog.set_title(title)
    dialog.set_transient_for(parent)
    dialog.set_modal(True)
    dialog.set_default_size(400, 250)

    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content.set_margin_top(24)
    content.set_margin_bottom(24)
    content.set_margin_start(24)
    content.set_margin_end(24)

    header = Adw.HeaderBar()
    header.set_title_widget(Adw.WindowTitle(title=title))

    cancel_button = Gtk.Button(label="Cancel")
    header.pack_start(cancel_button)

    set_button = Gtk.Button(label="Set Password")
    set_button.add_css_class("suggested-action")
    header.pack_end(set_button)

    form_group = Adw.PreferencesGroup()
    form_group.set_title("OATH Password")

    password_row = Adw.PasswordEntryRow()
    password_row.set_title("Password")
    form_group.add(password_row)

    confirm_password_row = Adw.PasswordEntryRow()
    confirm_password_row.set_title("Confirm Password")
    form_group.add(confirm_password_row)

    content.append(form_group)

    info_group = Adw.PreferencesGroup()
    info_group.set_title("Information")

    info_row = Adw.ActionRow()
    info_row.set_title("Password Protection")
    info_row.set_subtitle("Once set, you'll need this password to access OATH credentials")
    info_icon = Gtk.Image()
    info_icon.set_from_icon_name("dialog-information-symbolic")
    info_row.add_prefix(info_icon)
    info_group.add(info_row)

    content.append(info_group)

    main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    main_box.append(header)
    main_box.append(content)
    dialog.set_content(main_box)

    widgets = {
        'dialog': dialog,
        'cancel_button': cancel_button,
        'set_button': set_button,
        'password_row': password_row,
        'confirm_password_row': confirm_password_row
    }

    return dialog, widgets

def create_reset_confirmation_dialog(parent, app_name: str, warning_text: str) -> Adw.MessageDialog:
    dialog = Adw.MessageDialog(
        transient_for=parent,
        heading=f"Reset {app_name}?",
        body=f"This will completely reset the {app_name} application.\n\n{warning_text}\n\nThis action cannot be undone."
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("reset", "Reset")
    dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
    return dialog

def create_application_config_content(current_config: Dict[str, Any]) -> tuple[Gtk.Box, Dict[str, Gtk.Widget]]:
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content.set_margin_top(24)
    content.set_margin_bottom(24)
    content.set_margin_start(24)
    content.set_margin_end(24)

    apps_group = Adw.PreferencesGroup()
    apps_group.set_title("Applications")
    apps_group.set_description("Enable or disable YubiKey applications.")

    interfaces = current_config.get('interfaces', {})

    otp_row = Adw.ActionRow()
    otp_row.set_title("OTP (One-Time Password)")
    otp_row.set_subtitle("Yubico OTP and static passwords")
    otp_switch = Gtk.Switch()
    otp_switch.set_active(interfaces.get('otp', False))
    otp_switch.set_valign(Gtk.Align.CENTER)
    otp_row.add_suffix(otp_switch)
    otp_row.set_activatable_widget(otp_switch)
    apps_group.add(otp_row)

    fido_row = Adw.ActionRow()
    fido_row.set_title("FIDO U2F/FIDO2")
    fido_row.set_subtitle("WebAuthn and U2F authentication")
    fido_switch = Gtk.Switch()
    fido_switch.set_active(interfaces.get('fido', False))
    fido_switch.set_valign(Gtk.Align.CENTER)
    fido_row.add_suffix(fido_switch)
    fido_row.set_activatable_widget(fido_switch)
    apps_group.add(fido_row)

    ccid_row = Adw.ActionRow()
    ccid_row.set_title("Smart Card (CCID)")
    ccid_row.set_subtitle("PIV, OATH, OpenPGP applications")
    ccid_switch = Gtk.Switch()
    ccid_switch.set_active(interfaces.get('ccid', False))
    ccid_switch.set_valign(Gtk.Align.CENTER)
    ccid_row.add_suffix(ccid_switch)
    ccid_row.set_activatable_widget(ccid_switch)
    apps_group.add(ccid_row)

    content.append(apps_group)

    widgets = {
        'otp_switch': otp_switch,
        'fido_switch': fido_switch,
        'ccid_switch': ccid_switch
    }

    return content, widgets

def create_add_credential_content() -> tuple[Gtk.Box, Dict[str, Gtk.Widget]]:
    content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    content.set_margin_top(24)
    content.set_margin_bottom(24)
    content.set_margin_start(24)
    content.set_margin_end(24)

    options_group = Adw.PreferencesGroup()
    options_group.set_title("Add Account")
    options_group.set_description("Choose how to add your 2FA account")

    manual_row = Adw.ActionRow()
    manual_row.set_title("Manual Entry")
    manual_row.set_subtitle("Enter account details manually")
    manual_row.set_activatable(True)
    manual_icon = Gtk.Image()
    manual_icon.set_from_icon_name("document-edit-symbolic")
    manual_row.add_prefix(manual_icon)
    arrow1 = Gtk.Image()
    arrow1.set_from_icon_name("go-next-symbolic")
    manual_row.add_suffix(arrow1)
    options_group.add(manual_row)

    qr_row = Adw.ActionRow()
    qr_row.set_title("Scan QR Code")
    qr_row.set_subtitle("Use camera to scan QR code")
    qr_row.set_activatable(True)
    qr_icon = Gtk.Image()
    qr_icon.set_from_icon_name("view-reveal-symbolic")
    qr_row.add_prefix(qr_icon)
    arrow2 = Gtk.Image()
    arrow2.set_from_icon_name("go-next-symbolic")
    qr_row.add_suffix(arrow2)
    options_group.add(qr_row)

    uri_row = Adw.ActionRow()
    uri_row.set_title("From URI")
    uri_row.set_subtitle("Paste otpauth:// URI")
    uri_row.set_activatable(True)
    uri_icon = Gtk.Image()
    uri_icon.set_from_icon_name("insert-text-symbolic")
    uri_row.add_prefix(uri_icon)
    arrow3 = Gtk.Image()
    arrow3.set_from_icon_name("go-next-symbolic")
    uri_row.add_suffix(arrow3)
    options_group.add(uri_row)

    content.append(options_group)

    widgets = {
        'manual_row': manual_row,
        'qr_row': qr_row,
        'uri_row': uri_row
    }

    return content, widgets

def create_main_window_layout() -> tuple[Adw.ToastOverlay, Adw.HeaderBar, Adw.ViewStack, Adw.BottomSheet]:
    toast_overlay = Adw.ToastOverlay()
    header = create_header_bar()
    stack = create_view_stack()

    bottom_sheet = Adw.BottomSheet()
    bottom_sheet.set_can_open(True)
    bottom_sheet.set_modal(True)
    bottom_sheet.set_show_drag_handle(False)

    view_switcher_bar = create_view_switcher_bar(stack)

    main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    main_box.append(header)
    main_box.append(stack)
    main_box.append(view_switcher_bar)

    bottom_sheet.set_content(main_box)
    toast_overlay.set_child(bottom_sheet)

    return toast_overlay, header, stack, bottom_sheet

def create_application_config_bottom_sheet(bottom_sheet: Adw.BottomSheet, current_config: Dict[str, Any],
                                           apply_callback: Callable, cancel_callback: Callable) -> Dict[str, Gtk.Widget]:
    content, widgets = create_application_config_content(current_config)

    header_bar = Adw.HeaderBar()
    header_bar.set_title_widget(Adw.WindowTitle(title="Application Configuration"))

    cancel_button = Gtk.Button(label="Cancel")
    cancel_button.connect('clicked', lambda btn: cancel_callback())
    header_bar.pack_start(cancel_button)

    apply_button = Gtk.Button(label="Apply")
    apply_button.add_css_class("suggested-action")
    apply_button.connect('clicked', lambda btn: apply_callback(widgets))
    header_bar.pack_end(apply_button)

    main_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    main_content.append(header_bar)
    main_content.append(content)

    bottom_sheet.set_sheet(main_content)
    bottom_sheet.set_open(True)

    return widgets

def create_add_credential_bottom_sheet(bottom_sheet: Adw.BottomSheet, choice_callback: Callable,
                                       cancel_callback: Callable) -> Dict[str, Gtk.Widget]:
    content, widgets = create_add_credential_content()

    header_bar = Adw.HeaderBar()
    header_bar.set_title_widget(Adw.WindowTitle(title="Add Account"))

    cancel_button = Gtk.Button(label="Cancel")
    cancel_button.connect('clicked', lambda btn: cancel_callback())
    header_bar.pack_start(cancel_button)

    widgets['manual_row'].connect('activated', lambda row: choice_callback('manual'))
    widgets['qr_row'].connect('activated', lambda row: choice_callback('qr'))
    widgets['uri_row'].connect('activated', lambda row: choice_callback('uri'))

    main_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    main_content.append(header_bar)
    main_content.append(content)

    bottom_sheet.set_sheet(main_content)
    bottom_sheet.set_open(True)

    return widgets

def create_about_dialog(parent) -> Adw.AboutDialog:
    about_dialog = Adw.AboutDialog(
        application_name="Gubikey Manager",
        application_icon="security-high-symbolic",
        developer_name="Bardia Moshiri",
        version="1.0.0",
        website="https://github.com/fakeshell/gubikey",
        issue_url="https://github.com/fakeshell/gubikey/issues",
        copyright="© 2025 Bardia Moshiri",
        license_type=Gtk.License.GPL_2_0
    )
    about_dialog.set_comments("A GTK4/Libadwaita YubiKey management application")
    about_dialog.add_link("GitHub", "https://github.com/fakeshell/gubikey")
    return about_dialog

def create_oath_code_dialog(parent, credential_name: str, code: str) -> Adw.MessageDialog:
    dialog = Adw.MessageDialog(
        transient_for=parent,
        heading=f"OATH Code for {credential_name}",
        body=f"Generated code: {code}"
    )
    dialog.add_response("close", "Close")
    dialog.add_response("copy", "Copy Code")
    dialog.set_response_appearance("copy", Adw.ResponseAppearance.SUGGESTED)
    return dialog

def clear_list_widget(list_widget: Gtk.ListBox):
    child = list_widget.get_first_child()
    while child is not None:
        next_child = child.get_next_sibling()
        list_widget.remove(child)
        child = next_child
