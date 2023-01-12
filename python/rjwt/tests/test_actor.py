import rjwt
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


class TokenTests(unittest.TestCase):
    def testSignAndValidate(self):
        actor_one = rjwt.Actor("áctor १")
        actor_two = rjwt.Actor("áctor २")
        token = rjwt.Token.issue(actor_one.id, "unit test", 30)
        signed = actor_one.sign_token(token)

        self.assertEqual(actor_one.verify(signed), token)
        self.assertRaises(InvalidSignature, lambda: actor_two.verify(signed))

    def testPublicPEM(self):
        actor = rjwt.Actor("actor")
        encoded = rjwt.public_pem_encode(actor.public_key)
        decoded = rjwt.public_pem_decode(encoded)
        self.assertEqual(
            decoded.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            actor.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )


if __name__ == "__main__":
    unittest.main()
