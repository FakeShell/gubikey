# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

from typing import Dict, List, Optional, Any, Tuple
import re
import base64
import time
import logging
import secrets

from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection, ApduError, SW
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.management import (
    USB_INTERFACE, ManagementSession, DeviceConfig, CAPABILITY,
    DeviceInfo, Mode
)
from yubikit.support import get_name
from ykman.device import list_all_devices, YkmanDevice
from ykman.oath import OathSession
from ykman.piv import PivSession
from yubikit.yubiotp import YubiOtpSession, SLOT as OTP_SLOT
from yubikit.oath import CredentialData, OATH_TYPE, HASH_ALGORITHM
from yubikit.piv import SLOT, KEY_TYPE, TOUCH_POLICY, PIN_POLICY
from yubikit.core.smartcard import ApduError, SW
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap import CtapError

from .helpers import (
    parse_capabilities, check_all_applications,
    validate_pin_format, is_error_retryable
)

class GubikeyController:
    def __init__(self):
        self.device = None
        self.device_info = None
        self.raw_device = None
        self._device_cache = {}
        self._last_scan = 0
        self._scan_interval = 2.0

    def _get_cached_device(self) -> Optional[Tuple[YkmanDevice, DeviceInfo]]:
        current_time = time.time()
        if current_time - self._last_scan > self._scan_interval:
            try:
                devices = list_all_devices()
                if devices:
                    device, info = devices[0]
                    self._device_cache = {'device': device, 'info': info}
                    self.raw_device = device
                    self.device_info = info
                else:
                    self._device_cache = {}
                    self.raw_device = None
                    self.device_info = None
                self._last_scan = current_time
            except Exception as e:
                print(f"Error scanning devices: {e}")
                return None

        if 'device' in self._device_cache:
            return self._device_cache['device'], self._device_cache['info']
        return None

    def get_device_info(self) -> Optional[Dict[str, Any]]:
        try:
            device_data = self._get_cached_device()
            if not device_data:
                return None

            device, info = device_data
            device_name = get_name(info, device.pid.yubikey_type if device.pid else None)
            device_info = {
                'device_type': device_name,
                'serial': info.serial or 'Unknown',
                'version': str(info.version),
                'form_factor': str(info.form_factor).split('.')[-1] if info.form_factor else 'Unknown',
                'applications': {},
                'supported_capabilities': {},
                'enabled_capabilities': {}
            }

            try:
                with device.open_connection(SmartCardConnection) as conn:
                    mgmt = ManagementSession(conn)
                    mgmt_info = mgmt.read_device_info()

                    supported_usb = mgmt_info.supported_capabilities.get(TRANSPORT.USB, CAPABILITY(0))
                    supported_nfc = mgmt_info.supported_capabilities.get(TRANSPORT.NFC, CAPABILITY(0))

                    enabled_usb = mgmt_info.config.enabled_capabilities.get(TRANSPORT.USB, CAPABILITY(0))
                    enabled_nfc = mgmt_info.config.enabled_capabilities.get(TRANSPORT.NFC, CAPABILITY(0))

                    device_info['supported_capabilities'] = {
                        'usb': parse_capabilities(supported_usb),
                        'nfc': parse_capabilities(supported_nfc)
                    }

                    device_info['enabled_capabilities'] = {
                        'usb': parse_capabilities(enabled_usb),
                        'nfc': parse_capabilities(enabled_nfc)
                    }
            except Exception as e:
                print(f"Could not read management info: {e}")

            device_info['applications'] = check_all_applications(device)
            return device_info

        except Exception as e:
            print(f"Error getting device info: {e}")
            return None

    def get_application_config(self) -> Optional[Dict[str, Any]]:
        device_data = self._get_cached_device()
        if not device_data:
            return None

        device, _ = device_data
        connection_types = [SmartCardConnection, FidoConnection, OtpConnection]
        for conn_type in connection_types:
            try:
                if not device.supports_connection(conn_type):
                    continue

                with device.open_connection(conn_type) as conn:
                    mgmt = ManagementSession(conn)
                    device_info = mgmt.read_device_info()
                    enabled_over_usb = device_info.config.enabled_capabilities.get(TRANSPORT.USB, CAPABILITY(0))
                    interfaces = {
                        'otp': bool(enabled_over_usb & CAPABILITY.OTP),
                        'fido': bool(enabled_over_usb & (CAPABILITY.U2F | CAPABILITY.FIDO2)),
                        'ccid': bool(enabled_over_usb & (CAPABILITY.OATH | CAPABILITY.PIV | CAPABILITY.OPENPGP)),
                    }
                    return {
                        'interfaces': interfaces,
                        'device_flags': device_info.config.device_flags or 0,
                        'nfc_restricted': device_info.config.nfc_restricted or False
                    }
            except Exception as e:
                print(f"Failed to connect via {conn_type.__name__}: {e}")
                continue

        print("Error: Could not connect to YubiKey via any supported connection type")
        return None

    def set_application_config(self, otp_enabled: bool, fido_enabled: bool, ccid_enabled: bool,
                               lock_code: bytes = None) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        if lock_code is None:
            lock_code = b'\x00' * 16

        connection_types = [SmartCardConnection, FidoConnection, OtpConnection]

        for conn_type in connection_types:
            try:
                if not device.supports_connection(conn_type):
                    continue

                with device.open_connection(conn_type) as conn:
                    mgmt = ManagementSession(conn)

                    device_info = mgmt.read_device_info()
                    current_config = device_info.config

                    usb_capabilities = CAPABILITY(0)

                    if otp_enabled:
                        usb_capabilities |= CAPABILITY.OTP
                    if fido_enabled:
                        usb_capabilities |= CAPABILITY.U2F | CAPABILITY.FIDO2
                    if ccid_enabled:
                        usb_capabilities |= (CAPABILITY.OATH | CAPABILITY.PIV |
                                             CAPABILITY.OPENPGP | CAPABILITY.HSMAUTH)

                    new_enabled_capabilities = current_config.enabled_capabilities.copy()
                    new_enabled_capabilities[TRANSPORT.USB] = usb_capabilities

                    new_config = DeviceConfig(
                        enabled_capabilities=new_enabled_capabilities,
                        auto_eject_timeout=current_config.auto_eject_timeout,
                        challenge_response_timeout=current_config.challenge_response_timeout,
                        device_flags=current_config.device_flags,
                        nfc_restricted=current_config.nfc_restricted
                    )

                    mgmt.write_device_config(new_config, reboot=True, cur_lock_code=lock_code)
                    return True
            except Exception as e:
                print(f"Failed to connect via {conn_type.__name__}: {e}")
                continue
        return False

    def get_oath_credentials(self) -> List[Dict[str, Any]]:
        device_data = self._get_cached_device()
        if not device_data:
            return []

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                oath_session = OathSession(conn)
                credentials = oath_session.list_credentials()

                result = []
                for cred in credentials:
                    issuer = cred.issuer or ""
                    account = cred.name
                    display_name = f"{issuer}:{account}" if issuer else account

                    result.append({
                        'name': display_name,
                        'issuer': issuer,
                        'account': account,
                        'oath_type': 'TOTP' if cred.oath_type == OATH_TYPE.TOTP else 'HOTP',
                        'period': getattr(cred, 'period', 30),
                        'digits': getattr(cred, 'digits', 6),
                        'algorithm': str(getattr(cred, 'hash_algorithm', HASH_ALGORITHM.SHA1)).split('.')[-1],
                        'touch_required': getattr(cred, 'touch_required', False)
                    })
                return result
        except Exception as e:
            print(f"Error getting OATH credentials: {e}")
            return []

    def generate_oath_code(self, credential_name: str, timestamp: int = None) -> Optional[str]:
        device_data = self._get_cached_device()
        if not device_data:
            return None

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                oath_session = OathSession(conn)
                credentials = oath_session.list_credentials()

                target_cred = None
                for cred in credentials:
                    issuer = cred.issuer or ""
                    account = cred.name
                    display_name = f"{issuer}:{account}" if issuer else account

                    if display_name == credential_name:
                        target_cred = cred
                        break

                if not target_cred:
                    return None

                if target_cred.oath_type == OATH_TYPE.TOTP:
                    if timestamp:
                        response = oath_session.calculate_code(target_cred, timestamp)
                    else:
                        response = oath_session.calculate_code(target_cred)
                    return response.value
                else:
                    response = oath_session.calculate_code(target_cred)
                    return response.value
        except Exception as e:
            print(f"Error generating OATH code: {e}")
            return None

    def add_oath_credential(self, name: str, secret: str, issuer: str = "",
                            oath_type: str = "TOTP", digits: int = 6, period: int = 30,
                            algorithm: str = "SHA1", require_touch: bool = False) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                oath_session = OathSession(conn)

                if not name or not name.strip():
                    print("Error: Account name cannot be empty")
                    return False

                if not secret or not secret.strip():
                    print("Error: Secret cannot be empty")
                    return False

                name = name.strip()
                issuer = issuer.strip() if issuer else ""

                if digits is None or digits < 6 or digits > 8:
                    digits = 6

                if period is None or period < 15:
                    period = 30 if oath_type == "TOTP" else None

                try:
                    secret = secret.replace(' ', '').upper()
                    padding_needed = (8 - len(secret) % 8) % 8
                    secret_padded = secret + ('=' * padding_needed)
                    secret_bytes = base64.b32decode(secret_padded)
                except Exception as e:
                    print(f"Error decoding secret: {e}")
                    return False

                hash_algorithm = HASH_ALGORITHM.SHA1
                if algorithm and algorithm.upper() == "SHA256":
                    hash_algorithm = HASH_ALGORITHM.SHA256
                elif algorithm and algorithm.upper() == "SHA512":
                    hash_algorithm = HASH_ALGORITHM.SHA512

                # Map oath_type string to enum
                oath_type_enum = OATH_TYPE.TOTP if oath_type == "TOTP" else OATH_TYPE.HOTP

                try:
                    if oath_type == "TOTP":
                        cred_data = CredentialData(
                            name=name,
                            oath_type=oath_type_enum,
                            hash_algorithm=hash_algorithm,
                            secret=secret_bytes,
                            digits=digits,
                            period=period,
                            counter=0,  # Not used for TOTP, but ensure it's not None
                            issuer=issuer if issuer else None
                        )
                    else:  # HOTP
                        cred_data = CredentialData(
                            name=name,
                            oath_type=oath_type_enum,
                            hash_algorithm=hash_algorithm,
                            secret=secret_bytes,
                            digits=digits,
                            period=None,  # Not used for HOTP
                            counter=0,    # Start counter at 0 for HOTP
                            issuer=issuer if issuer else None
                        )

                    oath_session.put_credential(cred_data)
                    print(f"Successfully added credential: {name}")
                    return True
                except Exception as e:
                    print(f"Error creating credential data: {e}")
                    return False
        except Exception as e:
            print(f"Error adding OATH credential: {e}")
            return False

    def delete_oath_credential(self, credential_name: str) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                oath_session = OathSession(conn)
                credentials = oath_session.list_credentials()

                target_cred = None
                for cred in credentials:
                    issuer = cred.issuer or ""
                    account = cred.name
                    display_name = f"{issuer}:{account}" if issuer else account

                    if display_name == credential_name:
                        target_cred = cred
                        break

                if not target_cred:
                    return False

                oath_session.delete_credential(target_cred.id)
                return True
        except Exception as e:
            print(f"Error deleting OATH credential: {e}")
            return False

    def reset_oath(self) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                oath_session = OathSession(conn)
                oath_session.reset()
                return True
        except Exception as e:
            print(f"Error resetting OATH: {e}")
            return False

    def set_oath_password(self, password: str) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                oath_session = OathSession(conn)
                oath_session.set_password(password)
                return True
        except Exception as e:
            print(f"Error setting OATH password: {e}")
            return False

    def get_piv_info(self) -> Optional[Dict[str, Any]]:
        device_data = self._get_cached_device()
        if not device_data:
            return None

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                piv_session = PivSession(conn)

                piv_info = {
                    'version': str(piv_session.version),
                    'pin_attempts': 'Unknown',
                    'puk_attempts': 'Unknown',
                    'management_key_algorithm': 'Unknown',
                    'certificates': {},
                    'pin_complexity': False,
                    'fips_mode': False
                }

                try:
                    pin_attempts = piv_session.get_pin_attempts()
                    piv_info['pin_attempts'] = pin_attempts
                except Exception:
                    pass

                for slot in SLOT:
                    try:
                        cert = piv_session.get_certificate(slot)
                        if cert:
                            subject = cert.subject.rfc4514_string()
                            issuer = cert.issuer.rfc4514_string()
                            try:
                                not_before = cert.not_valid_before_utc.isoformat()
                            except AttributeError:
                                not_before = cert.not_valid_before.isoformat()
                            try:
                                not_after = cert.not_valid_after_utc.isoformat()
                            except AttributeError:
                                not_after = cert.not_valid_after.isoformat()

                            piv_info['certificates'][slot.name] = {
                                'subject': subject,
                                'issuer': issuer,
                                'not_before': not_before,
                                'not_after': not_after,
                                'installed': True
                            }
                    except Exception:
                        piv_info['certificates'][slot.name] = {
                            'subject': 'Empty',
                            'installed': False
                        }
                return piv_info
        except ApduError as e:
            if e.sw == SW.COMMAND_NOT_ALLOWED:
                print("PIV application not available or not configured")
                return None
            else:
                print(f"PIV APDU error: {e}")
                return None
        except Exception as e:
            print(f"Error getting PIV info: {e}")
            return None

    def reset_piv(self) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                piv_session = PivSession(conn)
                piv_session.reset()
                return True
        except Exception as e:
            print(f"Error resetting PIV: {e}")
            return False

    def change_piv_pin(self, old_pin: str, new_pin: str) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                piv_session = PivSession(conn)
                piv_session.change_pin(old_pin, new_pin)
                return True
        except Exception as e:
            print(f"Error changing PIV PIN: {e}")
            return False

    def change_piv_puk(self, old_puk: str, new_puk: str) -> bool:
        device_data = self._get_cached_device()
        if not device_data:
            return False

        device, _ = device_data

        try:
            with device.open_connection(SmartCardConnection) as conn:
                piv_session = PivSession(conn)
                piv_session.change_puk(old_puk, new_puk)
                return True
        except Exception as e:
            print(f"Error changing PIV PUK: {e}")
            return False

    def get_fido_info(self) -> Optional[Dict[str, Any]]:
        try:
            fido_devices = list(CtapHidDevice.list_devices())
            if not fido_devices:
                return None

            fido_device = fido_devices[0]
            client = Fido2Client(fido_device, "https://example.com")
            ctap2 = Ctap2(fido_device)

            fido_info = {
                'version': 'FIDO2',
                'pin_set': False,
                'pin_attempts': 0,
                'credential_count': 0,
                'aaguid': None,
                'max_credential_count': 0,
                'max_credential_id_length': 0,
                'algorithms': [],
                'extensions': [],
                'options': {}
            }

            try:
                info = ctap2.get_info()
                if hasattr(info, 'aaguid'):
                    fido_info['aaguid'] = info.aaguid.hex()
                if hasattr(info, 'versions'):
                    fido_info['version'] = ', '.join(info.versions)
                if hasattr(info, 'max_credential_count_in_list'):
                    fido_info['max_credential_count'] = info.max_credential_count_in_list
                if hasattr(info, 'max_credential_id_length'):
                    fido_info['max_credential_id_length'] = info.max_credential_id_length
                if hasattr(info, 'algorithms'):
                    fido_info['algorithms'] = [str(alg) for alg in info.algorithms]
                if hasattr(info, 'extensions'):
                    fido_info['extensions'] = info.extensions
                if hasattr(info, 'options'):
                    fido_info['options'] = dict(info.options)
            except Exception as e:
                print(f"Error getting FIDO info: {e}")

            try:
                if ctap2.info.options.get("clientPin"):
                    pin_protocol = ClientPin(ctap2)
                    retries = pin_protocol.get_pin_retries()
                    fido_info['pin_attempts'] = retries
                    fido_info['pin_set'] = retries is not None and retries >= 0
            except Exception as e:
                print(f"Error checking PIN status: {e}")

            return fido_info
        except Exception as e:
            print(f"Error getting FIDO info: {e}")
            return None

    def reset_fido(self) -> bool:
        try:
            fido_devices = list(CtapHidDevice.list_devices())
            if not fido_devices:
                return False

            fido_device = fido_devices[0]
            ctap2 = Ctap2(fido_device)

            ctap2.reset()
            return True
        except Exception as e:
            print(f"Error resetting FIDO: {e}")
            return False

    def set_fido_pin(self, pin: str) -> bool:
        try:
            fido_devices = list(CtapHidDevice.list_devices())
            if not fido_devices:
                return False

            fido_device = fido_devices[0]
            ctap2 = Ctap2(fido_device)

            pin_protocol = ClientPin(ctap2)
            pin_protocol.set_pin(pin)
            return True
        except Exception as e:
            print(f"Error setting FIDO PIN: {e}")
            return False

    def change_fido_pin(self, old_pin: str, new_pin: str) -> bool:
        try:
            fido_devices = list(CtapHidDevice.list_devices())
            if not fido_devices:
                return False

            fido_device = fido_devices[0]
            ctap2 = Ctap2(fido_device)

            pin_protocol = ClientPin(ctap2)
            pin_protocol.change_pin(old_pin, new_pin)
            return True
        except Exception as e:
            print(f"Error changing FIDO PIN: {e}")
            return False

    def clear_cache(self):
        self._device_cache = {}
        self._last_scan = 0
        self.raw_device = None
        self.device_info = None
