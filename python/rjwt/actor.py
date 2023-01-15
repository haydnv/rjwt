"""An :class:`Actor` with a public and (optional) private key which can sign a :class:`Token`."""

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from .token import Token


class Actor(object):
    """An :class:`Actor` with a public and (optional) private key which can sign a :class:`Token`."""

    def __init__(self, actor_id, public_key=None, private_key=None):
        if public_key:
            self._public_key = Ed25519PublicKey.from_public_bytes(public_key)

            if private_key:
                self._private_key = Ed25519PrivateKey.from_private_bytes(private_key)

                if self._private_key.public_key() != self._public_key:
                    raise ValueError(f"{actor_id} has an invalid keypair")
            else:
                self._private_key = None

        elif private_key:
            raise ValueError(f"{actor_id} is missing a public key")

        else:
            self._private_key = Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()

        self._id = actor_id

    @property
    def id(self):
        """The ID of this :class:`Actor`"""

        return self._id

    @property
    def public_key(self):
        """The public key of this :class:`Actor`"""

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign_token(self, token):
        """Sign and encode the given `token`"""

        if not self._private_key:
            raise RuntimeError(f"{self.actor_id} private key must be known in order to sign a message")

        headers = _base64_json_encode(token.HEADERS)
        claims = _base64_json_encode(token.claims)

        signature = self._private_key.sign(f"{headers}.{claims}".encode("ascii"))
        signature = _base64_encode(signature)

        signed = f"{headers}.{claims}.{signature}"
        assert self.verify(signed) == token
        return signed

    def verify(self, encoded_token):
        """Decode the given `encoded_token` and verify that it was signed by this :class:`Actor`."""

        [headers, claims, signature] = encoded_token.split('.')

        signature = _base64_decode(signature)

        self._public_key.verify(signature, f"{headers}.{claims}".encode("ascii"))

        headers = _base64_json_decode(headers)
        if headers != Token.HEADERS:
            raise ValueError(f"unsupported token type: {headers}")

        claims = _base64_json_decode(claims)
        token = Token(**claims)

        if token.actor_id == self._id:
            return token
        else:
            raise ValueError("the token passed validation but has an unexpected actor ID " +
                             f"{token.actor_id} (expected {self._id})")


def _base64_decode(ascii_string):
    return base64.b64decode(ascii_string)


def _base64_encode(data):
    return base64.b64encode(data).decode("ascii")


def _base64_json_encode(data):
    return _base64_encode(json.dumps(data).encode("utf8"))


def _base64_json_decode(ascii_string):
    json_string = _base64_decode(ascii_string)
    return json.loads(json_string)
