# Palash Rathore - 2018173
class sAES_E(object):

    def __init__(self, key):
        self.pre_round_key, self.round1_key, self.round2_key = self.key_expansion(
            key)
    # S-Box
    sBox = [
        0x9, 0x4, 0xA, 0xB, 0xD,
        0x1, 0x8, 0x5, 0x6, 0x2,
        0x0, 0x3, 0xC, 0xE, 0xF, 0x7,
    ]

    def sub_word(self, word):
        """ Substitute word
        """
        return (self.sBox[(word >> 4)] << 4) + self.sBox[word & 0x0F]

    def rot_word(self, word):
        """ Rotate word
        """
        return ((word & 0x0F) << 4) + ((word & 0xF0) >> 4)

    def key_expansion(self, key):
        """Key expansion
            Creates three 16-bit round keys from one single 16-bit cipher key
        """

        # Round constants
        Rcon1 = 0x80
        Rcon2 = 0x30

        # Calculating value of each word
        w = [None] * 6
        w[0] = (key & 0xFF00) >> 8
        w[1] = key & 0x00FF
        w[2] = w[0] ^ (self.sub_word(self.rot_word(w[1])) ^ Rcon1)
        w[3] = w[2] ^ w[1]
        w[4] = w[2] ^ (self.sub_word(self.rot_word(w[3])) ^ Rcon2)
        w[5] = w[4] ^ w[3]

        return (
            self.int_to_state((w[0] << 8) + w[1]),  # Pre-Round key
            self.int_to_state((w[2] << 8) + w[3]),  # Round 1 key
            self.int_to_state((w[4] << 8) + w[5]),  # Round 2 key
        )

    def gf_mult(self, a, b):
        """GF multiplication of a and b in x^4 + x + 1
        """
        product = 0

        # Mask the unwanted bits
        a = a & 0x0F
        b = b & 0x0F

        # While both multiplicands are non-zero
        while a and b:

            # If LSB of b is 1
            if b & 1:

                # Add current a to product
                product = product ^ a

            # Update a to a * 2
            a = a << 1

            # If a overflows beyond 4th bit
            if a & (1 << 4):

                # XOR with irreducible polynomial with high term eliminated
                a = a ^ 0b10011

            # Update b to b // 2
            b = b >> 1

        return product

    def int_to_state(self, n):
        """Convert a 2-byte integer into a (state matrix)
        """
        return [n >> 12 & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF, n & 0xF]

    def state_to_int(self, m):
        """Convert a (state matrix) into 2-byte integer
        """
        return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

    def add_round_key(self, s1, s2):
        """Add round keys in GF(2^4)
        """
        addrk = [i ^ j for i, j in zip(s1, s2)]
        return addrk

    def sub_nibbles(self, sbox, state):
        """Nibble substitution
        """
        subnibble = [sbox[nibble] for nibble in state]
        return subnibble

    def shift_rows(self, state):
        """Shift rows and inverse shift rows of state matrix (same)
        """
        shiftrows = [state[0], state[1], state[3], state[2]]
        return shiftrows

    def mix_columns(self, state):
        """Mix columns transformation on state matrix
        """
        mixcolumns = [
            state[0] ^ self.gf_mult(4, state[2]),
            state[1] ^ self.gf_mult(4, state[3]),
            state[2] ^ self.gf_mult(4, state[0]),
            state[3] ^ self.gf_mult(4, state[1]),
        ]
        return mixcolumns

    def encrypt(self, plaintext):
        """Encrypt plaintext with given key
        """
        state = self.add_round_key(
            self.pre_round_key, self.int_to_state(plaintext))
        state = self.mix_columns(self.shift_rows(
            self.sub_nibbles(self.sBox, state)))
        state = self.add_round_key(self.round1_key, state)
        state = self.shift_rows(self.sub_nibbles(self.sBox, state))
        state = self.add_round_key(self.round2_key, state)
        return self.state_to_int(state)
