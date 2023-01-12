import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .token import Token


class Actor(object):
    def __init__(self, actor_id, public_key=None, private_key=None):
        if public_key:
            self.public_key = public_key

            if private_key:
                self.private_key = Ed25519PrivateKey.from_private_bytes(private_key)

                assert self.private_key.public_key() == self.public_key, f"{actor_id} has an invalid keypair"
            else:
                self.private_key = None

        elif private_key:
            raise ValueError(f"{actor_id} is missing a public key")

        else:
            self.private_key = Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

        self.id = actor_id

    def sign_token(self, token):
        if not self.private_key:
            raise RuntimeError(f"{self.actor_id} private key must be known in order to sign a message")

        headers = _base64_json_encode(token.headers())
        claims = _base64_json_encode(token.claims())

        signature = self.private_key.sign(f"{headers}.{claims}".encode("ascii"))
        signature = _base64_encode(signature)

        signed = f"{headers}.{claims}.{signature}"
        assert self.verify(signed) == token
        return signed

    def verify(self, encoded_token):
        [headers, claims, signature] = encoded_token.split('.')

        signature = _base64_decode(signature)

        self.public_key.verify(signature, f"{headers}.{claims}".encode("ascii"))

        headers = _base64_json_decode(headers)
        if headers != Token.headers():
            raise ValueError(f"unsupported token type: {headers}")

        claims = _base64_json_decode(claims)
        token = Token.with_claims(**claims)

        if token.actor_id == self.id:
            return token
        else:
            raise ValueError("the token passed validation but has an unexpected actor ID " +
                             f"{token.actor_id} (expected {self.id})")


def public_pem_encode(public_key):
    if not hasattr(public_key, "public_bytes"):
        raise TypeError(f"expected a public key, not {public_key}")

    return public_key.public_bytes(
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
        encoding=serialization.Encoding.PEM,
    )


def public_pem_decode(pem_string):
    return serialization.load_pem_public_key(pem_string)


def _base64_decode(ascii_string):
    return base64.b64decode(ascii_string)


def _base64_encode(data):
    return base64.b64encode(data).decode("ascii")


def _base64_json_encode(data):
    return _base64_encode(json.dumps(data).encode("utf8"))


def _base64_json_decode(ascii_string):
    json_string = _base64_decode(ascii_string)
    return json.loads(json_string)
