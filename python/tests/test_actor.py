import rjwt
import unittest


class TokenTests(unittest.TestCase):
    def testSigning(self):
        actor = rjwt.Actor("test actor")
        message = b"hello world"
        signature = actor.sign(message)

        self.assertTrue(actor.verify(signature, message))
        self.assertFalse(actor.verify(signature, b"some other message"))


if __name__ == "__main__":
    unittest.main()
