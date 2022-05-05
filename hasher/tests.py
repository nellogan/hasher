import unittest
from md5 import md5
from sha1 import sha1
from sha224 import sha224
from sha256 import sha256
from sha384 import sha384
from sha512 import sha512
from sha512_t import sha512_t


class TestMD5(unittest.TestCase):

    def setUp(self):
        self.f = md5

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True).hexdigest(),
                         'd41d8cd98f00b204e9800998ecf8427e')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True).hexdigest(),
                         '900150983cd24fb0d6963f7d28e17f72')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*64, string=True).hexdigest(),
                         'c1bb4f81d892b2d57947682aeb252456')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True).hexdigest(),
                         '38ebb7657e0b48f47a76fece544ebd3a')


class TestSHA1(unittest.TestCase):
    def setUp(self):
        self.f = sha1

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True).hexdigest(),
                         'da39a3ee5e6b4b0d3255bfef95601890afd80709')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True).hexdigest(),
                         'a9993e364706816aba3e25717850c26c9cd0d89d')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*64, string=True).hexdigest(),
                         'bb2fa3ee7afb9f54c6dfb5d021f14b1ffe40c163')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True).hexdigest(),
                         '832af88ead51622a76b777eec75641d49f6201f6')


class TestSHA224(unittest.TestCase):
    def setUp(self):
        self.f = sha224

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True).hexdigest(),
                         'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True).hexdigest(),
                         '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*64, string=True).hexdigest(),
                         '08c3050e95fe11eacb9dc7824bf6a92bcf2d59c21701321fba0e62c5')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True).hexdigest(),
                         'c0f74690b134929fe1a93faed6b117cee52f9ed14d0dac4423900c2b')


class TestSHA256(unittest.TestCase):
    def setUp(self):
        self.f = sha256

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True).hexdigest(),
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True).hexdigest(),
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*64, string=True).hexdigest(),
                         '7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True).hexdigest(),
                         '6516d38f2a2c8f5e8b58ac18bb02b85fe92ee261f099a248b14d21ba3b1159a1')

class TestSHA384(unittest.TestCase):
    def setUp(self):
        self.f = sha384

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True).hexdigest(),
                         '38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743' +
                         '4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True).hexdigest(),
                         'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163' +
                         '1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*128, string=True).hexdigest(),
                         'e660584956c8b1df44c92acb7c8eccfe0dca5255627c9fb4' +
                         '4637c15363b772e5709edcf35b07bf43531951ab2fd51130')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True).hexdigest(),
                         'ead21eb75474257dc50d71edb0fe48ade19c6629baa05f32' +
                         'db2422aa73476669cb666d69c5ddfd4cdb524a42240c0bdf')

class TestSHA512(unittest.TestCase):
    def setUp(self):
        self.f = sha512

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True).hexdigest(),
                         'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
                         '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True).hexdigest(),
                         'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
                         '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*128, string=True).hexdigest(),
                         'e2e22f8422b54b06e35c3ea30a383d1de7a8fbc27992923074103117020d8dd7' +
                         '024c3ecf7d6d1a15a6de5a75ff32fb486b9e8ced4c02ffe05822bf2cb734d0e0')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True).hexdigest(),
                         '024dc23fb03143e7db69a7b4500920bfdac2b25cdd49cd55a2654370314d84d9' +
                         '6f485d25018ce94bb8c9465748a1b7b7e255e7d5e98456f804791ce922304ba1')

class TestSHA512_224(unittest.TestCase):
    def setUp(self):
        self.f = sha512_t

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True, t=224).hexdigest(),
                         '6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True, t=224).hexdigest(),
                         '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*128, string=True, t=224).hexdigest(),
                         '89433771840172fc885ae35fc7f086fbcd0e74f98882046d6b05ff8d')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True, t=224).hexdigest(),
                         '6d266145701f6f6cb96e198670703d6cc060d3d783cf27df226e4d2b')


class TestSHA512_256(unittest.TestCase):
    def setUp(self):
        self.f = sha512_t

    def test_empty_string(self):
        self.assertEqual(self.f('', string=True, t=256).hexdigest(),
                         'c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a')

    def test_less_than_one_block(self):
        self.assertEqual(self.f('abc', string=True, t=256).hexdigest(),
                         '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23')

    def test_exactly_one_block(self):
        self.assertEqual(self.f('x'*128, string=True, t=256).hexdigest(),
                         '6c0dfa95c650de7bb33dedd62fe0b0363f5deec77c582a216c7e33253f59a518')

    def test_many_blocks(self):
        self.assertEqual(self.f('x'*999999, string=True, t=256).hexdigest(),
                         '4edc0f8dcc3df6575c1d0d2fac27b8c4e2400bcb8033436c4207a1b70b581245')


if __name__ == '__main__':
    md5_suite = unittest.TestLoader().loadTestsFromTestCase(TestMD5)
    sha1_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA1)
    sha224_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA224)
    sha256_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA256)
    sha384_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA384)
    sha512_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA512)
    sha512_224_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA512_224)
    sha512_256_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA512_256)

    all_tests = unittest.TestSuite([md5_suite,
                                    sha1_suite,
                                    sha224_suite,
                                    sha256_suite,
                                    sha384_suite,
                                    sha512_suite,
                                    sha512_224_suite,
                                    sha512_256_suite])

    unittest.TextTestRunner(verbosity=2).run(all_tests)
