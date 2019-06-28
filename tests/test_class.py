"""SoftWebauthnDevice class tests"""

import pytest

from soft_webauthn import SoftWebauthnDevice


def test_create():
    """test create"""

    pkcco = {
        'publicKey': {
            'rp': {
                'name': 'example org',
                'id': 'example.org'
            },
            'user': {
                'id': b'randomhandle',
                'name': 'username',
                'displayName': 'user name'
            },
            'challenge': b'arandomchallenge',
            'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
            'attestation': 'none'
        }
    }

    device = SoftWebauthnDevice()
    public_key_credential = device.create(pkcco, 'https://example.org')

    assert public_key_credential
    assert device.rp_id == 'example.org'
    assert device.private_key


def test_create_not_supported_type():
    """test for internal class check"""

    device = SoftWebauthnDevice()
    pkcco = {'publicKey': {'pubKeyCredParams': [{'alg': -8, 'type': 'public-key'}]}}

    with pytest.raises(ValueError):
        device.create(pkcco, 'https://example.org')


def test_create_not_supported_attestation():
    """test for internal class check"""

    device = SoftWebauthnDevice()
    pkcco = {
        'publicKey': {
            'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
            'attestation': 'direct'
        }
    }

    with pytest.raises(ValueError):
        device.create(pkcco, 'https://example.org')
