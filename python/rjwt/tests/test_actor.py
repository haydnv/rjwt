import rjwt
import unittest

from cryptography.exceptions import InvalidSignature


class TokenTests(unittest.TestCase):
    def testSignAndValidate(self):
        actor_one = rjwt.Actor("áctor १")
        actor_two = rjwt.Actor("áctor २")
        token = rjwt.Token.issue("unit test", actor_one.id, 30)
        signed = actor_one.sign_token(token)

        self.assertEqual(actor_one.verify(signed), token)
        self.assertRaises(InvalidSignature, lambda: actor_two.verify(signed))

    def testPublicKey(self):
        actor_one = rjwt.Actor("one")
        encoded = actor_one.public_key.hex()

        decoded = bytes.fromhex(encoded)
        actor_two = rjwt.Actor("two", decoded)

        self.assertEqual(actor_one.public_key, actor_two.public_key)


if __name__ == "__main__":
    unittest.main()
