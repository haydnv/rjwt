from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


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

        self.actor_id = actor_id

    def sign(self, message):
        if self.private_key:
            return self.private_key.sign(message)
        else:
            raise RuntimeError(f"{self.actor_id} private key must be known in order to sign a message")

    def verify(self, signature, message):
        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
