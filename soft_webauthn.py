"""
Module implementing software webauthn token for testing webauthn enabled
applications
"""

import json
import os
from base64 import urlsafe_b64encode
from struct import pack

from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import sha256


class SoftWebauthnDevice():
    """
    This simulates the Webauthn browser API with a authenticator device
    connected. It's primary use-case is testing, device can hold only
    one credential.
    """

    def __init__(self):
        self.private_key = None
        self.cred_id = None
        self.aaguid = None
        self.sign_count = 0
        self.rp_id = None

    def create(self, credential_options, origin):
        """create credential and return PublicKeyCredential object"""

        if {'alg': -7, 'type': 'public-key'} not in credential_options['publicKey']['pubKeyCredParams']:
            raise ValueError('Requested pubKeyCredParams does not contain supported type')

        if credential_options['publicKey']['attestation'] != 'none':
            raise ValueError('Only none attestation supported')

        # generate new key
        self.cred_id = os.urandom(32)
        self.rp_id = credential_options['publicKey']['rp']['id']
        self.aaguid = b'\x00'*16
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        # generate response
        client_data = {
            'type': 'webauthn.create',
            'challenge': urlsafe_b64encode(
                credential_options['publicKey']['challenge']).decode('ascii'),
            'origin': origin
        }

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x41'  # attested_data + user_present
        sign_count = pack('>I', self.sign_count)
        cred_id_length = pack('>H', len(self.cred_id))
        cose_key = cbor.encode(ES256.from_cryptography_key(self.private_key.public_key()))
        attestation_object = {
            'authData': rp_id_hash + flags + sign_count + self.aaguid + cred_id_length + self.cred_id + cose_key,
            'fmt': 'packed',
            'attStmt': {}
        }

        return {
            'id': urlsafe_b64encode(self.cred_id),
            'rawId': self.cred_id,
            'response': {
                'clientDataJSON': json.dumps(client_data).encode('utf-8'),
                'attestationObject': cbor.encode(attestation_object)
            },
            'type': 'public-key'
        }
