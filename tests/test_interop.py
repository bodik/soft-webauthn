"""SoftWebauthnDevice class tests"""

from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server, RelyingParty

from soft_webauthn import SoftWebauthnDevice


def test_register():
    """test registering generated credential"""

    server = Fido2Server(RelyingParty('example.org'))
    device = SoftWebauthnDevice()

    user_dict = {
        'id': b'randomhandle',
        'name': 'username',
        'displayName': 'User Name'
    }
    credentials_options, state = server.register_begin(user_dict, [])
    credential = device.create(credentials_options, 'https://example.org')
    auth_data = server.register_complete(
        state,
        ClientData(credential['response']['clientDataJSON']),
        AttestationObject(credential['response']['attestationObject']))

    assert isinstance(auth_data, AuthenticatorData)
