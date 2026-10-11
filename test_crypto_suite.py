import os, tempfile, unittest
from unittest import mock
import crypto_suite as cs

class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = lambda n: os.path.join(self.d, n)
        open(self.p("a.txt"), "w").write("hello")

    def test_aes_roundtrip(self):
        with mock.patch("getpass.getpass", return_value="pw1"):
            cs.aes_encrypt(self.p("a.txt"), self.p("a.enc"))
            cs.aes_decrypt(self.p("a.enc"), self.p("b.txt"))
        self.assertEqual(open(self.p("b.txt")).read(), "hello")

    def test_aes_wrong_password(self):
        with mock.patch("getpass.getpass", return_value="pw1"):
            cs.aes_encrypt(self.p("a.txt"), self.p("a.enc"))
        with mock.patch("getpass.getpass", return_value="bad"):
            with self.assertRaises(SystemExit):
                cs.aes_decrypt(self.p("a.enc"), self.p("b.txt"))

    def test_rsa_roundtrip(self):
        k = self.p("k")
        with mock.patch("getpass.getpass", return_value="pw2"):
            cs.rsa_keygen(k)
            cs.rsa_encrypt(k + "_public.pem", self.p("a.txt"), self.p("r.enc"))
            cs.rsa_decrypt(k + "_private.pem", self.p("r.enc"), self.p("r.txt"))
        self.assertEqual(open(self.p("r.txt")).read(), "hello")

if __name__ == "__main__":
    unittest.main()
