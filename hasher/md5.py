class md5:
    # Initialize hash buffer values.
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476

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

        # Step 3: Append original message length (little endian) in bits mod 64 (bytes mod 8) to message.
        # Each ASCII character is 8 bits, therefore message_length*8 is the message length in bits.
        message += (message_length * 8).to_bytes(8, 'little')
        return message

    def _compress(self, message):
        # Everything in md5 is little endian.
        # Shift array, s
        s = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        ]

        # Constant array, k
        k = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        ]

        # for each 512-bit (64-byte) block
        for block_number in range(len(message) // 64):
            a, b, c, d = self.h0, self.h1, self.h2, self.h3
            block = message[block_number * 64: (block_number + 1) * 64]

            # Break the block into sixteen 4-byte words (little endian).
            m = [int.from_bytes(block[j * 4: (j + 1) * 4], 'little') for j in range(16)]

            for i in range(64):
                if 0 <= i <= 15:
                    f = (b & c) | ((~b) & d)
                    g = i
                elif 16 <= i <= 31:
                    f = (d & b) | ((~d) & c)
                    g = (5 * i + 1) & 15
                elif 32 <= i <= 47:
                    f = b ^ c ^ d
                    g = (3 * i + 5) & 15
                else:
                    f = c ^ (b | (~d))
                    g = (7 * i) & 15
                # 0xffffffff = bitmask for max 4-byte number.
                f = (f + a + k[i] + m[g]) & 0xffffffff
                a, d, c, b = d, c, b, (b + self._left_rotate(f, s[i])) & 0xffffffff

            self.h0 = (self.h0 + a) & 0xffffffff
            self.h1 = (self.h1 + b) & 0xffffffff
            self.h2 = (self.h2 + c) & 0xffffffff
            self.h3 = (self.h3 + d) & 0xffffffff

    def digest(self):
        digest = self.h0 | (self.h1 << 32) | (self.h2 << 64) | (self.h3 << 96)
        digest = digest.to_bytes(16, byteorder='little')
        return digest

    def hexdigest(self):
        digest = int.from_bytes(self.digest(), 'big')
        return "{0:0{1}x}".format(digest, 32)
