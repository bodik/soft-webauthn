"""SoftWebauthnDevice class tests"""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.utils import sha256

from soft_webauthn import SoftWebauthnDevice


# PublicKeyCredentialCreationOptions
PKCCO = {
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

# PublicKeyCredentialRequestOptions
PKCRO = {
    'publicKey': {
        'challenge': b'arandomchallenge',
        'rpId': 'example.org',
    }
}


def test_create():
    """test create"""

    device = SoftWebauthnDevice()
    public_key_credential = device.create(PKCCO, 'https://example.org')

    assert public_key_credential
    assert device.private_key
    assert device.rp_id == 'example.org'


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


def test_get():
    """test get"""

    device = SoftWebauthnDevice()
    device.create(PKCCO, 'https://example.org')

    assertion = device.get(PKCRO, 'https://example.org')

    assert assertion
    device.private_key.public_key().verify(
        assertion['response']['signature'],
        assertion['response']['authenticatorData'] + sha256(assertion['response']['clientDataJSON']),
        ec.ECDSA(hashes.SHA256()))


def test_get_not_matching_rpid():
    """test get not mathcing rpid"""

    device = SoftWebauthnDevice()
    device.create(PKCCO, 'https://example.org')

    tmp = PKCRO
    tmp['publicKey']['rpId'] = 'another.example.org'
    with pytest.raises(ValueError):
        device.get(tmp, 'https://example.org')
