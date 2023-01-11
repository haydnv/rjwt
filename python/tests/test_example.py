import rjwt
import unittest


class TokenTests(unittest.TestCase):
    def testPackageSetup(self):
        self.assertEqual(rjwt.example.hello(), "Hello, World!")


if __name__ == "__main__":
    unittest.main()
