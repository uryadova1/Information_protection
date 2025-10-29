class RC5:

    def __init__(self, w, R, key, strip_extra_nulls=False):
        self.w = w  # word size in bits (16,32,64)
        self.R = R  # number of rounds (0..255)
        self.key = key if isinstance(key, (bytes, bytearray)) else bytes(key)
        self.strip_extra_nulls = strip_extra_nulls
        # some useful constants
        self.T = 2 * (R + 1)
        self.w8 = w // 8  # bytes per word
        self.w4 = self.w8 * 2  # bytes per block (2 words)
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(self.key)

        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    def __lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def __rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def __const(self):  # constants generation
        if self.w == 16:
            return 0xB7E1, 0x9E37  # return P, Q values
        elif self.w == 32:
            return 0xB7E15163, 0x9E3779B9
        elif self.w == 64:
            return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15
        else:
            raise ValueError("Unsupported word size")

    def __keyAlign(self):
        if self.b == 0:  # key is empty
            self.c = 1
            self.key = b'\x00' * self.w8
            self.b = len(self.key)
        elif self.b % self.w8:
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # fill key with \x00 bytes
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):
        P, Q = self.__const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def encryptBlock(self, data):
        if len(data) != self.w4:
            raise ValueError("encryptBlock expects exactly {} bytes".format(self.w4))
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        for i in range(1, self.R + 1):
            A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def decryptBlock(self, data):
        if len(data) != self.w4:
            raise ValueError("decryptBlock expects exactly {} bytes".format(self.w4))
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        for i in range(self.R, 0, -1):
            B = self.__rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def encryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    text = text.ljust(self.w4, b'\x00')
                    run = False
                text = self.encryptBlock(text)
                out.write(text)

    def decryptFile(self, inpFileName, outFileName):
        with open(inpFileName, 'rb') as inp, open(outFileName, 'wb') as out:
            while True:
                text = inp.read(self.w4)
                if not text:
                    break
                text = self.decryptBlock(text)
                if self.strip_extra_nulls:
                    text = text.rstrip(b'\x00')
                out.write(text)

    @staticmethod
    def __xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def __pad_md_style(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        orig_bits = len(data) * 8
        data = bytearray(data)
        data.append(0x80)
        while (len(data) + 8) % self.w4 != 0:
            data.append(0)
        data += orig_bits.to_bytes(8, byteorder='little')
        return bytes(data)

    def hashBytes(self, data: bytes, digest_size: int = None) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)

        block_size = self.w4
        padded = self.__pad_md_style(data)
        H = b'\x00' * block_size  # IV (zeros)
        # iterate blocks
        for off in range(0, len(padded), block_size):
            m = padded[off:off + block_size]
            # use message block as key (Davies–Meyer)
            rc = RC5(self.w, self.R, key=m)
            E = rc.encryptBlock(H)
            H = self.__xor_bytes(E, H)
        if digest_size is None or digest_size > block_size:
            return H
        else:
            return H[:digest_size]

    def hashFile(self, filename: str, digest_size: int = None) -> bytes:
        with open(filename, 'rb') as f:
            data = f.read()
        return self.hashBytes(data, digest_size=digest_size)

    def show_avalanche_test(self, data: bytes, flip_byte_index: int = 0, flip_bit: int = 0) -> dict:
        orig = self.hashBytes(data)
        if len(data) == 0:
            modified = b'\x00' * (flip_byte_index + 1)
        else:
            md = bytearray(data)
            idx = flip_byte_index % len(md)
            md[idx] ^= (1 << (flip_bit % 8))
            modified = bytes(md)
        newh = self.hashBytes(modified)

        diffs = 0
        length = max(len(orig), len(newh))
        o = orig.ljust(length, b'\x00')
        n = newh.ljust(length, b'\x00')
        for x, y in zip(o, n):
            diffs += bin(x ^ y).count("1")

        return {
            "original_hex": orig.hex(),
            "modified_hex": newh.hex(),
            "differing_bits": diffs,
            "digest_len_bytes": len(orig)
        }


def task3():
    rc5 = RC5(w=32, R=12, key=b"default-key")
    digest = rc5.hashFile("task3.txt")
    print("hash:", digest.hex())
    avalanche = rc5.show_avalanche_test(open("task3.txt", "rb").read(), flip_byte_index=0, flip_bit=0)
    print(avalanche)
