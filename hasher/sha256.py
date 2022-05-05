class sha256:
    # Initial hash buffer values.
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    def __init__(self, file, string=False):
        if string:
            message = bytearray(file, encoding='utf-8')
        else:
            with open(file, 'rb') as f:
                message = f.read()
        message = self._preprocess(message)
        self._compress(message)

    @staticmethod
    def _right_rotate(arr, n):
        return ((arr >> n) | (arr << (32 - n))) & 0xffffffff

    @staticmethod
    def _preprocess(message):
        message_length = len(message)
        # Preprocess message
        # Step 1: Append a single 1 bit, or 0b10000000.
        message += b'\x80'

        # Step 2: Pad with 0s until preprocess_message length (in bits) == 448 mod 512
        # or preprocess_message length (in bytes) == 56 mod 64, note -1 from added byte from step 1.
        message += b'\x00' * ((56 - message_length - 1) % 64)

        # Step 3: Append original message length (big endian) in bits mod 64 (bytes mod 8) to message.
        # Each ASCII character is 8 bits, therefore message_length*8 is the message length in bits.
        message += (message_length * 8).to_bytes(8, 'big')
        return message

    def _compress(self, message):
        # Constant table, k
        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        # for each 512-bit (64-byte) block
        for block_number in range(len(message) // 64):
            a, b, c, d, e, f, g, h = self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7
            block = message[block_number * 64: (block_number + 1) * 64]

            # Break the block into sixteen 4-byte words (big endian) then extend to sixty-four 4-byte words.
            m = [int.from_bytes(block[j * 4: (j + 1) * 4], 'big') for j in range(16)] + [0 for _ in range(16, 64)]

            for i in range(16, 64):
                sigma0 = self._small_sigma0(m, i)
                sigma1 = self._small_sigma1(m, i)
                m[i] = (m[i - 16] + sigma0 + m[i - 7] + sigma1) & 0xffffffff

            for i in range(64):
                capital_sigma0 = self._big_sigma0(a)
                capital_sigma1 = self._big_sigma1(e)
                ch = self._choose(e, f, g)
                maj = self._majority(a, b, c)
                temp1 = (h + capital_sigma1 + ch + k[i] + m[i])
                temp2 = (capital_sigma0 + maj)
                # 0xffffffff = bitmask for max 4-byte number.
                h = g
                g = f
                f = e
                e = (d + temp1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xffffffff

            self.h0 = (self.h0 + a) & 0xffffffff
            self.h1 = (self.h1 + b) & 0xffffffff
            self.h2 = (self.h2 + c) & 0xffffffff
            self.h3 = (self.h3 + d) & 0xffffffff
            self.h4 = (self.h4 + e) & 0xffffffff
            self.h5 = (self.h5 + f) & 0xffffffff
            self.h6 = (self.h6 + g) & 0xffffffff
            self.h7 = (self.h7 + h) & 0xffffffff

    def _small_sigma0(self, m, index):
        return self._right_rotate(m[index - 15], 7) ^ self._right_rotate(m[index - 15], 18) ^ (m[index - 15] >> 3)

    def _small_sigma1(self, m, index):
        return self._right_rotate(m[index - 2], 17) ^ self._right_rotate(m[index - 2], 19) ^ (m[index - 2] >> 10)

    def _big_sigma0(self, buffer):
        return (self._right_rotate(buffer, 2)) ^ (self._right_rotate(buffer, 13)) ^ (self._right_rotate(buffer, 22))

    def _big_sigma1(self, buffer):
        return (self._right_rotate(buffer, 6)) ^ (self._right_rotate(buffer, 11)) ^ (self._right_rotate(buffer, 25))

    @staticmethod
    def _choose(x, y, z):
        return (x & y) ^ ((~x) & z)

    @staticmethod
    def _majority(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def digest(self):
        digest = (self.h0 << 224) | (self.h1 << 192) | (self.h2 << 160) | (self.h3 << 128) | (self.h4 << 96) | (
                self.h5 << 64) | (self.h6 << 32) | self.h7
        digest = digest.to_bytes(32, byteorder='big')
        return digest

    def hexdigest(self):
        digest = int.from_bytes(self.digest(), 'big')
        return "{0:0{1}x}".format(digest, 64)
