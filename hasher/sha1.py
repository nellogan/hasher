class sha1:
    # Initialize hash buffer values.
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    def __init__(self, file, string=False):
        if string:
            message = bytearray(file, encoding='utf-8')
        else:
            with open(file, 'rb') as f:
                message = f.read()
        message = self._preprocess(message)
        self._compress(message)

    @staticmethod
    def _left_rotate(arr, n):
        return arr << n | (arr >> (32 - n))

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
        # for each 512-bit (64-byte) block
        for block_number in range(len(message) // 64):
            a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4
            block = message[block_number * 64: (block_number + 1) * 64]

            # Break the block into sixteen 4-byte words (big endian) then extend to eighty 4-byte words.
            m = [int.from_bytes(block[j * 4: (j + 1) * 4], 'big') for j in range(16)] + [0 for _ in range(16, 80)]
            for i in range(16, 80):
                m[i] = self._left_rotate((m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]), 1) & 0xffffffff

            for i in range(80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                # 0xffffffff = bitmask for max 4-byte number.
                a, b, c, d, e = ((self._left_rotate(a, 5) + f + e + k + m[i]) & 0xffffffff,
                                 a, self._left_rotate(b, 30) & 0xffffffff, c, d)

            self.h0 = (self.h0 + a) & 0xffffffff
            self.h1 = (self.h1 + b) & 0xffffffff
            self.h2 = (self.h2 + c) & 0xffffffff
            self.h3 = (self.h3 + d) & 0xffffffff
            self.h4 = (self.h4 + e) & 0xffffffff

    def digest(self):
        digest = (self.h0 << 128) | (self.h1 << 96) | (self.h2 << 64) | (self.h3 << 32) | self.h4
        digest = digest.to_bytes(20, byteorder='big')
        return digest

    def hexdigest(self):
        digest = int.from_bytes(self.digest(), 'big')
        return "{0:0{1}x}".format(digest, 40)
