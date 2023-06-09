"""
Module implementing software webauthn token for testing webauthn enabled
applications
"""

import datetime
import json
import os
from base64 import urlsafe_b64encode
from struct import pack
from typing import Dict, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import sha256
from fido2.webauthn import AttestedCredentialData, CredentialCreationOptions, CredentialRequestOptions


class SoftWebauthnDevice():
    """
    This simulates the Webauthn browser API with a authenticator device
    connected. It's primary use-case is testing, device can hold only
    one credential.
    """

    def __init__(self):
        self.credential_id = None
        self.private_key = None
        self.aaguid = b'\x00'*16
        self.rp_id = None
        self.user_handle = None
        self.sign_count = 0

    def cred_init(self, rp_id, user_handle):
        """initialize credential for rp_id under user_handle"""

        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.rp_id = rp_id
        self.user_handle = user_handle

    def cred_as_attested(self):
        """return current credential as AttestedCredentialData"""

        return AttestedCredentialData.create(
            self.aaguid,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key())
        )

    def create(self, options: Union[CredentialCreationOptions, Dict], origin: str):
        """create credential and return PublicKeyCredential object aka attestation"""

        if {'alg': -7, 'type': 'public-key'} not in options['publicKey']['pubKeyCredParams']:
            raise ValueError('Requested pubKeyCredParams does not contain supported type')

        attestation_type = options['publicKey'].get('attestation', 'none')
        if attestation_type not in ['none', 'direct', 'indirect']:
            raise ValueError('Only none, direct, and indirect attestation supported')

        # prepare new key
        self.cred_init(options['publicKey']['rp']['id'], options['publicKey']['user']['id'])

        # generate credential response
        client_data = {
            'type': 'webauthn.create',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x41'  # attested_data + user_present
        sign_count = pack('>I', self.sign_count)
        credential_id_length = pack('>H', len(self.credential_id))
        cose_key = cbor.encode(ES256.from_cryptography_key(self.private_key.public_key()))
        authenticator_data = rp_id_hash + flags + sign_count + self.aaguid \
            + credential_id_length + self.credential_id + cose_key
        attestation_object = self._get_attestation_object(attestation_type, client_data, authenticator_data)

        return {
            'id': urlsafe_b64encode(self.credential_id),
            'rawId': self.credential_id,
            'response': {
                'clientDataJSON': json.dumps(client_data).encode('utf-8'),
                'attestationObject': cbor.encode(attestation_object)
            },
            'type': 'public-key'
        }

    def _get_attestation_object(self, attestation_type, client_data, authenticator_data):
        """get attestation object for attestation_type, also supports direct/indirect with Chromium published key"""

        # indirect is allowed to return same as direct
        if attestation_type in ['direct', 'indirect']:
            # Generate attestation certificate and private key
            att_cert, att_priv_key = self._generate_attestation_certificate_and_key()

            # Create a signature using the attestation private key
            client_data_hash = sha256(json.dumps(client_data).encode('utf-8'))
            signature = att_priv_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

            # Update the attestation object with packed attestation format
            attestation_object = {
                'authData': authenticator_data,
                'fmt': 'packed',
                'attStmt': {
                    'alg': -7,  # ES256
                    'sig': signature,
                    'x5c': [att_cert.public_bytes(serialization.Encoding.DER)]
                }
            }
        else:
            # 'none' attestation
            attestation_object = {
                'authData': authenticator_data,
                'fmt': 'none',
                'attStmt': {}
            }

        return attestation_object

    @staticmethod
    def _generate_attestation_certificate_and_key():
        """Get a private key for the attestation certificate"""

        # Using the example attestation private key from the U2F spec at
        # https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-example
        # As used by Chromium: https://github.com/chromium/chromium/blob/22fb7b6/device/fido/virtual_fido_device.cc#L37
        # If you would like to instead generate your own private key, you can use the following code:
        # attestation_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        key_hex = "f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664"
        attestation_private_key = ec.derive_private_key(int(key_hex, 16), ec.SECP256R1())

        # Generate a self-signed attestation certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Soft-WebAuthn"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            x509.NameAttribute(NameOID.COMMON_NAME, "softwebauthn.example.com"),
        ])
        attestation_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            attestation_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365*20)
        ).sign(attestation_private_key, hashes.SHA256(), default_backend())

        return attestation_certificate, attestation_private_key

    def get(self, options: Union[CredentialRequestOptions, Dict], origin: str):
        """get authentication credential aka assertion"""

        if self.rp_id != options['publicKey']['rpId']:
            raise ValueError('Requested rpID does not match current credential')

        self.sign_count += 1

        # prepare signature
        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }).encode('utf-8')
        client_data_hash = sha256(client_data)

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        flags = b'\x01'
        sign_count = pack('>I', self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        signature = self.private_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

        # generate assertion
        return {
            'id': urlsafe_b64encode(self.credential_id),
            'rawId': self.credential_id,
            'response': {
                'authenticatorData': authenticator_data,
                'clientDataJSON': client_data,
                'signature': signature,
                'userHandle': self.user_handle
            },
            'type': 'public-key'
        }
