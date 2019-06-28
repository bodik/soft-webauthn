"""SoftWebauthnDevice class tests"""

from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server, RelyingParty

from soft_webauthn import SoftWebauthnDevice


USER_DICT = {
    'id': b'randomhandle',
    'name': 'username',
    'displayName': 'User Name'
}


def test_register():
    """test registering generated credential"""

    server = Fido2Server(RelyingParty('example.org'))
    device = SoftWebauthnDevice()

    credentials_options, state = server.register_begin(USER_DICT, [])
    credential = device.create(credentials_options, 'https://example.org')
    auth_data = server.register_complete(
        state,
        ClientData(credential['response']['clientDataJSON']),
        AttestationObject(credential['response']['attestationObject']))

    assert isinstance(auth_data, AuthenticatorData)


def test_authenticate():
    """test authentication"""

    server = Fido2Server(RelyingParty('example.org'))
    device = SoftWebauthnDevice()
    credentials_options, state = server.register_begin(USER_DICT, [])
    credential = device.create(credentials_options, 'https://example.org')
    auth_data = server.register_complete(
        state,
        ClientData(credential['response']['clientDataJSON']),
        AttestationObject(credential['response']['attestationObject']))
    registered_credential = auth_data.credential_data

    credential_options, state = server.authenticate_begin([registered_credential])
    assertion = device.get(credential_options, 'https://example.org')

    server.authenticate_complete(
        state,
        [registered_credential],
        assertion['rawId'],
        ClientData(assertion['response']['clientDataJSON']),
        AuthenticatorData(assertion['response']['authenticatorData']),
        assertion['response']['signature'])
