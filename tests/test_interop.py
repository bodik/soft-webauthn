"""SoftWebauthnDevice class tests"""

from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

from soft_webauthn import SoftWebauthnDevice


def test_register():
    """test registering generated credential"""

    device = SoftWebauthnDevice()

    server = Fido2Server(PublicKeyCredentialRpEntity('example.org', 'test server'))
    exclude_credentials = []
    options, state = server.register_begin(
        {'id': b'randomhandle', 'name': 'username', 'displayName': 'User Name'},
        exclude_credentials
    )
    attestation = device.create(options, 'https://example.org')
    auth_data = server.register_complete(
        state,
        ClientData(attestation['response']['clientDataJSON']),
        AttestationObject(attestation['response']['attestationObject'])
    )

    assert isinstance(auth_data, AuthenticatorData)


def test_authenticate():
    """test authentication"""

    device = SoftWebauthnDevice()
    device.cred_init('example.org', b'randomhandle')
    registered_credential = device.cred_as_attested()

    server = Fido2Server(PublicKeyCredentialRpEntity('example.org', 'test server'))
    options, state = server.authenticate_begin([registered_credential])
    assertion = device.get(options, 'https://example.org')
    server.authenticate_complete(
        state,
        [registered_credential],
        assertion['rawId'],
        ClientData(assertion['response']['clientDataJSON']),
        AuthenticatorData(assertion['response']['authenticatorData']),
        assertion['response']['signature']
    )
