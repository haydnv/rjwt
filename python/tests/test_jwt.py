import rjwt
import unittest

from cryptography.exceptions import InvalidSignature


class TokenTests(unittest.TestCase):
    def testSignAndValidate(self):
        actor_one = rjwt.Actor("áctor १")
        actor_two = rjwt.Actor("áctor २")
        token = rjwt.Token.issue(actor_one.id, "unit test", 30)
        signed = actor_one.sign_token(token)

        self.assertEqual(actor_one.verify(signed), token)
        self.assertRaises(InvalidSignature, lambda: actor_two.verify(signed))


if __name__ == "__main__":
    unittest.main()
