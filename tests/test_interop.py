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

    device = SoftWebauthnDevice()
    server = Fido2Server(RelyingParty('example.org'))

    options, state = server.register_begin(USER_DICT, [])
    attestation = device.create(options, 'https://example.org')
    auth_data = server.register_complete(
        state,
        ClientData(attestation['response']['clientDataJSON']),
        AttestationObject(attestation['response']['attestationObject']))

    assert isinstance(auth_data, AuthenticatorData)


def test_authenticate():
    """test authentication"""

    device = SoftWebauthnDevice()
    device.cred_init('example.org', b'randomhandle')
    server = Fido2Server(RelyingParty('example.org'))
    registered_credential = device.cred_as_attested()

    options, state = server.authenticate_begin([registered_credential])
    assertion = device.get(options, 'https://example.org')
    server.authenticate_complete(
        state,
        [registered_credential],
        assertion['rawId'],
        ClientData(assertion['response']['clientDataJSON']),
        AuthenticatorData(assertion['response']['authenticatorData']),
        assertion['response']['signature'])
