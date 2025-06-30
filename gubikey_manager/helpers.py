# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

from yubikit.management import CAPABILITY, TRANSPORT
from yubikit.core.smartcard import SmartCardConnection, ApduError, SW
from yubikit.core.otp import OtpConnection
from ykman.oath import OathSession
from ykman.piv import PivSession
from fido2.hid import CtapHidDevice
from typing import Dict, Any

def parse_capabilities(capabilities: CAPABILITY) -> Dict[str, bool]:
    return {
        'otp': bool(capabilities & CAPABILITY.OTP),
        'u2f': bool(capabilities & CAPABILITY.U2F),
        'fido2': bool(capabilities & CAPABILITY.FIDO2),
        'oath': bool(capabilities & CAPABILITY.OATH),
        'piv': bool(capabilities & CAPABILITY.PIV),
        'openpgp': bool(capabilities & CAPABILITY.OPENPGP),
        'hsmauth': bool(capabilities & CAPABILITY.HSMAUTH)
    }

def check_all_applications(device) -> Dict[str, Dict[str, Any]]:
    applications = {
        'otp': {'enabled': False, 'version': 'Unknown'},
        'fido_u2f': {'enabled': False, 'version': 'Unknown'},
        'fido2': {'enabled': False, 'version': 'Unknown'},
        'smartcard': {'enabled': False, 'version': 'Unknown'},
        'oath': {'enabled': False, 'version': 'Unknown'},
        'piv': {'enabled': False, 'version': 'Unknown'},
        'openpgp': {'enabled': False, 'version': 'Unknown'}
    }

    try:
        with device.open_connection(SmartCardConnection) as conn:
            applications['smartcard'] = {'enabled': True, 'version': 'Available'}

            try:
                oath_session = OathSession(conn)
                applications['oath'] = {
                    'enabled': True,
                    'version': str(oath_session.version)
                }
            except Exception as e:
                print(f"OATH check failed: {e}")

            try:
                piv_session = PivSession(conn)
                applications['piv'] = {
                    'enabled': True,
                    'version': str(piv_session.version)
                }
            except Exception as e:
                print(f"PIV check failed: {e}")
    except Exception as e:
        print(f"Could not check smartcard applications: {e}")

    try:
        fido_devices = list(CtapHidDevice.list_devices())
        if fido_devices:
            applications['fido2'] = {'enabled': True, 'version': 'FIDO2'}
            applications['fido_u2f'] = {'enabled': True, 'version': 'U2F'}
    except Exception as e:
        print(f"FIDO check error: {e}")

    try:
        with device.open_connection(OtpConnection) as otp_conn:
            applications['otp'] = {'enabled': True, 'version': 'Available'}
    except Exception as e:
        print(f"OTP check failed: {e}")

    return applications

def validate_pin_format(pin: str, pin_type: str = "piv") -> bool:
    if pin_type.lower() == "piv":
        return 6 <= len(pin) <= 8
    elif pin_type.lower() == "fido":
        return 4 <= len(pin) <= 63
    return False

def is_error_retryable(error: Exception) -> bool:
    if isinstance(error, ApduError):
        return error.sw in [SW.CONDITIONS_NOT_SATISFIED, SW.COMMAND_NOT_ALLOWED]
    return False
