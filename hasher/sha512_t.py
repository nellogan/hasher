class sha512_t:
    # Initial hash buffer values.
    h0 = 0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5
    h1 = 0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5
    h2 = 0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5
    h3 = 0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5
    h4 = 0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5
    h5 = 0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5
    h6 = 0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5
    h7 = 0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5

    # t is the hash output length in bits.
    def __init__(self, file, string=False, t=256):
        self.t = t
        if string:
            message = bytearray(file, encoding='utf-8')
        else:
            with open(file, 'rb') as f:
                message = f.read()
        # IV generation to populate hash values.
        iv_generation = b'SHA-512' + b'/' + bytearray(str(self.t), encoding='utf-8')
        iv_generation = self._preprocess(iv_generation)
        self._compress(iv_generation)
        # Proceeds with normal sha256.
        message = self._preprocess(message)
        self._compress(message)

    @staticmethod
    def _right_rotate(arr, n):
        return ((arr >> n) | (arr << (64 - n))) & 0xffffffffffffffff

    @staticmethod
    def _preprocess(message):
        message_length = len(message)
        # Preprocess message
        # Step 1: Append a single 1 bit, or 0b10000000.
        message += b'\x80'

        # Step 2: Pad with 0s until preprocess_message length (in bits) == 896 mod 1024
        # or preprocess_message length (in bytes) == 112 mod 128, note -1 from added byte from step 1.
        message += b'\x00' * ((112 - message_length - 1) % 128)

        # Step 3: Append original message length (big endian) in bits mod 128 (bytes mod 16) to message.
        # Each ASCII character is 8 bits, therefore message_length*8 is the message length in bits.
        message += (message_length * 8).to_bytes(16, 'big')
        return message

    def _compress(self, message):
        # Constant table, k
        k = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ]
        # for each 1024-bit (128-byte) block
        for block_number in range(len(message) // 128):
            a, b, c, d, e, f, g, h = self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7
            block = message[block_number * 128: (block_number + 1) * 128]

            # Break the block into sixteen 8-byte words (big endian) then extend to eighty 8-byte words.
            m = [int.from_bytes(block[j * 8: (j + 1) * 8], 'big') for j in range(16)] + [0 for _ in range(16, 80)]

            for i in range(16, 80):
                sigma0 = self._small_sigma0(m, i)
                sigma1 = self._small_sigma1(m, i)
                m[i] = (m[i - 16] + sigma0 + m[i - 7] + sigma1) & 0xffffffffffffffff

            for i in range(80):
                capital_sigma0 = self._big_sigma0(a)
                capital_sigma1 = self._big_sigma1(e)
                ch = self._choose(e, f, g)
                maj = self._majority(a, b, c)
                temp1 = (h + capital_sigma1 + ch + k[i] + m[i])
                temp2 = (capital_sigma0 + maj)
                # 0xffffffffffffffff = bitmask for max 8-byte number.
                h = g
                g = f
                f = e
                e = (d + temp1) & 0xffffffffffffffff
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xffffffffffffffff

            self.h0 = (self.h0 + a) & 0xffffffffffffffff
            self.h1 = (self.h1 + b) & 0xffffffffffffffff
            self.h2 = (self.h2 + c) & 0xffffffffffffffff
            self.h3 = (self.h3 + d) & 0xffffffffffffffff
            self.h4 = (self.h4 + e) & 0xffffffffffffffff
            self.h5 = (self.h5 + f) & 0xffffffffffffffff
            self.h6 = (self.h6 + g) & 0xffffffffffffffff
            self.h7 = (self.h7 + h) & 0xffffffffffffffff

    def _small_sigma0(self, m, index):
        return self._right_rotate(m[index - 15], 1) ^ self._right_rotate(m[index - 15], 8) ^ (m[index - 15] >> 7)

    def _small_sigma1(self, m, index):
        return self._right_rotate(m[index - 2], 19) ^ self._right_rotate(m[index - 2], 61) ^ (m[index - 2] >> 6)

    def _big_sigma0(self, buffer):
        return (self._right_rotate(buffer, 28)) ^ (self._right_rotate(buffer, 34)) ^ (self._right_rotate(buffer, 39))

    def _big_sigma1(self, buffer):
        return (self._right_rotate(buffer, 14)) ^ (self._right_rotate(buffer, 18)) ^ (self._right_rotate(buffer, 41))

    @staticmethod
    def _choose(x, y, z):
        return (x & y) ^ ((~x) & z)

    @staticmethod
    def _majority(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    '''
    _gamma function concatenates and shifts all hash values such that output = t bits.
    t//64 is the number of complete 64-bit hash values to append.
    Remainder = (t % 64), left shift final complete 64-bit hash value by the remainder.
    (-(t % 64) % 64) = number of bits to right shift final hash value.
    Example:
    t = 500, t//64 = 7, remainder = 52, -52 % 64 = 12
    res = (self.h0 << 436) | (self.h1 << 372) | (self.h2 << 308) | (self.h3 << 244) | (self.h4 << 180) | (
                self.h5 << 116) | (self.h6 << 52) | (self.h7 >> 12)
    '''
    @staticmethod
    def _gamma(t, h):
        res = 0
        for i in range((t // 64) + 1):
            if i < (t // 64):
                res |= h[i] << (t - 64 * (i + 1))
            elif (t % 64) > 0:
                res |= h[i] >> (-(t % 64) % 64)
        return res

    def digest(self):
        digest = self._gamma(self.t, [self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7])
        digest = digest.to_bytes(64, byteorder='big')
        return digest

    def hexdigest(self):
        digest = int.from_bytes(self.digest(), 'big')
        return "{0:0{1}x}".format(digest, self.t//4)
