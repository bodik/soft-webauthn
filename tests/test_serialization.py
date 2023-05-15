"""SoftWebauthnDevice serialization tests, mostly adapted from test_class.py"""

import pytest

from soft_webauthn import SoftWebauthnDevice

from .test_class import PKCCO, PKCRO, _device_assertions


def test_create_and_serialize_without_password():
    """test create"""

    device = SoftWebauthnDevice()
    device.create(PKCCO, 'https://example.org')

    serialized = device.to_bytes()
    deserialized = SoftWebauthnDevice.from_bytes(serialized)

    assert deserialized.private_key
    assert deserialized.rp_id == 'example.org'


def test_create_and_serialize_with_password():
    """test create"""

    device = SoftWebauthnDevice()
    device.create(PKCCO, 'https://example.org')
    password = "password"

    serialized = device.to_bytes(password)
    deserialized = SoftWebauthnDevice.from_bytes(serialized, password)

    assert deserialized.private_key
    assert deserialized.rp_id == 'example.org'


def test_create_and_serialize_no_or_incorrect_password():
    """test create"""

    device = SoftWebauthnDevice()
    device.create(PKCCO, 'https://example.org')

    serialized = device.to_bytes("password")

    with pytest.raises(TypeError):
        SoftWebauthnDevice.from_bytes(serialized)
    with pytest.raises(ValueError):
        SoftWebauthnDevice.from_bytes(serialized, "wrongpassword")


def test_get_after_deserialize():
    """test get"""

    device = SoftWebauthnDevice()
    device.cred_init(PKCRO['publicKey']['rpId'], b'randomhandle')
    serialized = device.to_bytes()
    deserialized = SoftWebauthnDevice.from_bytes(serialized)

    _device_assertions(deserialized)
