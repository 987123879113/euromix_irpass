# Lots of hacks for pscript so the website can be generated using the same Python code


def this_is_js():
    return False


def safe_modulo(n, m):
    if this_is_js() and n < 0:
        # For pscript/Javascript
        return ((n % m) + m) % m

    return n % m


def n2h(a):
    if this_is_js():
        h = "0123456789abcdef"
        a1 = a % 16
        a2 = a // 16
        return h[a2] + h[a1]

    return "%02x" % a


def n2h_long(a):
    if this_is_js():
        h = "0123456789abcdef"
        ret = []
        while a > 0:
            a1 = a % 16
            a = safe_div(a, 16)
            ret = [h[a1]] + ret

        return "".join(ret)

    return "%x" % a


def shr(a, n):
    if this_is_js():
        a &= 0xffffffff

        bits = [1 if (a & (1 << i)) != 0 else 0 for i in range(32)][n:]

        output = 0
        for i in range(min(len(bits), 32)):
            output |= bits[i] << i

        return output

    return (a >> n) & 0xffffffff


def shl(a, n):
    if this_is_js():
        a &= 0xffffffff

        bits = [1 if (a & (1 << i)) != 0 else 0 for i in range(32)]

        output = 0
        for i in range(min(n, 32), 32):
            output |= bits[i-n] << i

        return output

    return (a << n) & 0xffffffff


def mul64(a, b):
    if this_is_js():
        al = a & 0xffff
        ah = shr(a, 16)

        bl = b & 0xffff
        bh = shr(b, 16)

        rl = al * bl
        rm1 = ah * bl
        rm2 = al * bh

        rm1l = rm1 & 0xffff
        rm2l = rm2 & 0xffff
        rml = (rm1l + rm2l) & 0xffff

        rl += shl(rml, 16)

        return rl

    return (a * b) & 0xffffffff


def safe_div(n, m):
    if this_is_js():
        if (m & (m - 1) == 0) and m != 0:
            # Is power of two
            for i in range(32):
                if (2 ** i) == m:
                    return shr(n, i)

        # Pray
        return n // m

    return n // m


def int_js_to_bytes(data, length, endianness="big"):
    if this_is_js():
        assert(endianness == "big")

        if length == 1:
            return data[0]

        elif length == 2:
            return [shr(data, 8) & 0xff, data & 0xff]

        elif length == 4:
            return [shr(data, 24) & 0xff, shr(data, 16) & 0xff, shr(data, 8) & 0xff, data & 0xff]

        assert(length == 1 or length == 2 or length == 4)

    else:
        return list(int.to_bytes(data, length, endianness))

def int_js_from_bytes(data, endianness="big"):
    if this_is_js():
        assert(endianness == "big")

        length = len(data)

        if length == 1:
            return data[0]

        elif length == 2:
            return shl(data[0], 8) | data[1]

        elif length == 4:
            return shl(data[0], 24) | shl(data[1], 16) | shl(data[2], 8) | data[3]

        assert(length == 1 or length == 2 or length == 4)

    else:
        return int.from_bytes(data, endianness)


class KonamiMRand:
    # mrnd.c from https://oku.edu.mie-u.ac.jp/~okumura/algo/archive/algo.tar.gz
    def __init__(self):
        self.x = [0] * 522


    def irnd(self, max=None):
        self.jrnd += 1

        if self.jrnd >= 521:
            self.rnd521()
            self.jrnd = 0

        ret = self.x[self.jrnd]
        if max is not None:
            ret = safe_modulo(ret, max)

        return ret


    def rnd521(self):
        for i in range(32):
            self.x[i] ^= self.x[i + 489]

        for i in range(32, 521):
            self.x[i] ^= self.x[i - 32]


    def init_rnd(self, seed):
        self.x = [0] * 522

        for i in range(16 + 1):
            bits = [0] * 32
            for j in range(32):
                seed = mul64(seed, 0x5d588b65) + 1
                bits[j] = 1 if (seed & 0x80000000) != 0 else 0

            u = 0
            for j in range(32):
                u |= shl(bits[j], j)

            self.x[i] = u & 0xffffffff

        self.x[16] = shl(self.x[16], 23) ^ shr(self.x[0], 9) ^ self.x[15]

        for i in range(17, 521):
            self.x[i] = shl(self.x[i-17], 23) ^ shr(self.x[i-16], 9) ^ self.x[i-1]

        for _ in range(9):
            self.rnd521()

        self.jrnd = 520


class EuromixIRPassword:
    def __init__(self, machine_key):
        self.machine_key = machine_key.upper()
        self.prng = KonamiMRand()
        self.parse_machine_key()


    def parse_machine_key(self):
        machine_key_chunks = []
        for chunk in self.machine_key.split("-"):
            chunk_bytes = []
            for c in chunk:
                chunk_bytes.append(ord(c))
            machine_key_chunks.append(chunk_bytes)

        if len(machine_key_chunks) != 3:
            raise ValueError("Machine key must have 3 dashes")

        chunk1, chunk2, chunk3 = machine_key_chunks

        seed = self.generate_seed_hash("SIDENC", "GN894EAA")
        chunk1_data = self.decode_chunk(
            self.generate_scrambled_charset(seed),
            chunk1
        )

        chunk2_data = self.decode_chunk(
            self.generate_scrambled_charset(seed + 0x240),
            chunk2
        )

        a = self.decode_chunk(
            self.generate_scrambled_charset(seed + 0x480),
            chunk3
        )

        chunk3_data = self.scramble_buffer_with_seed2(
            self.calc_crc16_alt(chunk2),
            int_js_to_bytes(a, 4)
        )

        seed = self.generate_seed_hash("GN894EAA", "SIDENC")
        chunk3_data ^= seed

        v1 = shr(chunk3_data, 8) & 0xff
        v2 = chunk3_data & 0xff
        self.prng.init_rnd(shl(v1, 8) | v2 | shl((shl(v2, 8) | v1), 16))

        chunk2_data ^= self.prng.irnd()
        chunk1_data ^= self.prng.irnd()

        buf = list(
            int_js_to_bytes(chunk1_data, 4)
            + int_js_to_bytes(chunk2_data, 4)
            + int_js_to_bytes(chunk3_data, 4)
        )

        a1 = self.calc_crc16_alt(buf, 4) & 0xff
        a2 = self.calc_crc16(buf, 10) & 0xff

        if a1 != buf[10] or a2 != buf[11]:
            raise ValueError("Invalid checksums! " + " ".join(["%02X" % x for x in buf]))

        self.security_id = "".join([n2h(x) for x in buf[4:10]])

        day = shr(chunk1_data, 0x0b) & 0x1f
        month = shr(chunk1_data, 0x10) & 0x0f
        year = chunk1_data // 0x100000

        print("%d/%d/%d" % (year, month, day), self.security_id)

        return chunk1 + chunk2 + chunk3


    def create_machine_key(self, security_id, year, month, day):
        payload = year * 0x100000 | shl((month & 0x0f), 0x10) | shl((day & 0x1f), 0x0b) | 0x31e

        buf = int_js_to_bytes(payload, 4) + security_id
        v1 = self.calc_crc16_alt(buf, 4) & 0xff
        buf += int_js_to_bytes(v1, 1)
        v2 = self.calc_crc16(buf, 10) & 0xff
        buf += int_js_to_bytes(v2, 1)

        seed = self.generate_seed_hash("GN894EAA", "SIDENC")
        self.prng.init_rnd(shl(v1, 8) | v2 | shl((shl(v2, 8) | v1), 16))

        t1 = self.prng.irnd()
        t2 = self.prng.irnd()
        buf = self.xor_bytes(buf, 0, t2)
        buf = self.xor_bytes(buf, 4, t1)
        buf = self.xor_bytes(buf, 8, seed)

        seed = self.generate_seed_hash("SIDENC", "GN894EAA")
        chunk1 = self.encode_chunk(
            self.generate_scrambled_charset(seed),
            int_js_from_bytes(buf[:4])
        )

        chunk2 = self.encode_chunk(
            self.generate_scrambled_charset(seed + 0x240),
            int_js_from_bytes(buf[4:8])
        )

        chunk3 = self.encode_chunk(
            self.generate_scrambled_charset(seed + 0x480),
            self.scramble_buffer_with_seed2(
                self.calc_crc16_alt(chunk2),
                buf[8:12]
            )
        )

        return chunk1 + chunk2 + chunk3


    def scramble_buffer_with_seed2(self, seed, data):
        output = self.scramble_buffer_with_seed(seed)

        for i in range(16):
            uVar6 = 3 - shr(output[i], 3)
            uVar4 = output[i] & 7
            uVar5 = output[i + 16] & 7
            bVar2 = shl(1, uVar5) & 0xff

            data_idx = 3 - shr(output[i + 16], 3) & 0xff
            bVar1 = data[data_idx]

            if (shr(data[uVar6 & 0xff], uVar4) & 1) == 0:
                data[data_idx] &= ~bVar2
            else:
                data[data_idx] |= bVar2

            uVar6 &= 0xff
            if (shr(bVar1, uVar5) & 1) == 0:
                data[uVar6] &= ~shl(1, uVar4)
            else:
                data[uVar6] |= shl(1, uVar4)

        return int_js_from_bytes(data) & 0xffffffff


    def generate_seed_hash(self, input, input2):
        def sra(x, n, m):
            if x & 2 ** (n - 1) != 0:
                filler = int('1' * m + '0' * (n - m), 2)
                x = shr(x, m) | filler
                return x

            else:
                return shr(x, m)

        input = [ord(c) for c in input]
        input2 = [ord(c) for c in input2]

        hash1 = 0
        for c in input2:
            for j in range(6):
                a = (((shl(hash1, 1) & 0xffffffff) | (sra(c, 8, j & 0x1f) & 1)))
                a &= 0xffffffff

                b = (sra(hash1, 32, 0x1f) & 0x4c11db7)
                b &= 0xffffffff

                hash1 = a ^ b

        output = 0
        for c in input:
            iVar3 = c + 0xa30c85
            hash1 = mul64(hash1, iVar3)
            uVar7 = mul64(hash1, iVar3)
            output += (hash1 & 0xffff0000) | (shr(uVar7, 0x0f) & 0xffff)
            output &= 0xffffffff

            hash1 = (uVar7 + c) & 0xffffffff

        return output & 0xffffffff


    def generate_scrambled_charset(self, seed):
        self.prng.init_rnd(seed)
        charset = [ord(c) for c in "123456789ABCDEFGHIJKLMNPQRSTUWXZ"]
        for _ in range(0x23d):
            i1 = self.prng.irnd(len(charset))
            i2 = self.prng.irnd(len(charset))
            charset[i1], charset[i2] = charset[i2], charset[i1]

        return charset


    def encode_chunk(self, charset, chunk, param2=32, chunkLen=7):
        output = []
        for _ in range(chunkLen):
            c = safe_modulo(chunk, param2)
            chunk = safe_div(chunk, param2)
            output.append(charset[c])

        return list(output)


    def decode_chunk(self, charset, chunk, param2=32, chunkLen=7):
        lastCharMaxIdx = 0

        # Is param2 ever not 32 and chunkLen ever not 7?
        chunkIdx = 0
        t = 0xffffffff
        while True:
            if t == 0:
                break

            lastCharMaxIdx = safe_modulo(t, param2)
            t = safe_div(t, param2)

            chunkIdx += 1
            if chunkIdx >= chunkLen:
                break

        output = 0
        for i, c in enumerate(chunk):
            charsetIdx = charset.index(c)
            output += charsetIdx * (param2 ** i)

        if (chunkIdx != len(chunk) or charsetIdx <= lastCharMaxIdx) and output <= 0xffffffff:
            return output

        return None


    def scramble_buffer_with_seed(self, seed):
        self.prng.init_rnd(seed)

        d = []
        for i in range(0, 0x20, 2):
            d.append(i)

        for i in range(1, 0x20, 2):
            d.append(i)

        output = [0] * len(d)
        for i in range(len(output) // 2):
            v = self.prng.irnd()

            if (v & 1) == 0:
                output[i] = d[i]
                output[i+0x10] = d[i+0x10]
            else:
                output[i] = d[i+0x10]
                output[i+0x10] = d[i]

        for j in range(2):
            for _ in range(0x240):
                t1 = self.prng.irnd() & 0x0f
                t2 = self.prng.irnd() & 0x0f
                output[t1 + j * 0x10], output[t2 + j * 0x10] = output[t2 + j * 0x10], output[t1 + j * 0x10]

        return output


    def scramble_buffer_with_seed_even_more(self, seed, data):
        output = self.scramble_buffer_with_seed(seed)

        for i in range(0x10):
            uVar3 = data
            if (uVar3 & shl(1, (output[i] & 0x1f))) == 0:
                uVar2 = uVar3 & ~shl(1, (output[i+0x10] & 0x1f))
            else:
                uVar2 = uVar3 | shl(1, (output[i+0x10] & 0x1f))
            data = uVar2

            if (uVar3 & shl(1, (output[i+0x10] & 0x1f))) == 0:
                uVar3 = data & ~shl(1, (output[i] & 0x1f))
            else:
                uVar3 = data | shl(1, (output[i] & 0x1f))
            data = uVar3

        return data


    def calc_crc16(self, data, length=None):
        crc = 0xffff

        if length is None:
            length = len(data)

        for i in range(length):
            crc ^= shl(data[i], 8)

            for _ in range(8):
                crc = shl(crc, 1) ^ (0x1021 if (crc & 0x8000) != 0 else 0)

        return ~crc & 0xffff


    def calc_crc16_alt(self, data, length=None):
        crc = 0xffff

        if length is None:
            length = len(data)

        for i in range(length):
            crc ^= data[i]

            for _ in range(8):
                crc = shr(crc, 1) ^ (0x8408 if (crc & 1) != 0 else 0)

        return crc & 0xffff


    def xor_bytes(self, data, offset, val):
        result = int_js_to_bytes(
            int_js_from_bytes(data[offset:offset+4]) ^ val,
            4
        )
        return list(data[:offset]) + list(result) + list(data[offset+4:])


    def verify_password(self, password):
        self.prng = KonamiMRand()

        password = [ord(c) for c in password.replace("-", "")] if password is not None else None

        chunk1, chunk2, chunk3 = [password[i:i+7] for i in range(0, len(password), 7)]

        # Scramble the input password charset based on the game code + security cassette ID
        seed = self.generate_seed_hash(self.security_id, "GN894EAA")

        x = self.decode_chunk(
            self.generate_scrambled_charset(seed),
            chunk1
        )
        chunk1_output = self.scramble_buffer_with_seed_even_more(
            seed + 0x381,
            x
        )

        chunk2_output = self.scramble_buffer_with_seed_even_more(
            self.calc_crc16(chunk1),
            self.decode_chunk(
                self.generate_scrambled_charset(seed + 0x240),
                chunk2
            )
        )

        chunk3_output = self.scramble_buffer_with_seed_even_more(
            self.calc_crc16_alt(chunk2),
            self.decode_chunk(
                self.generate_scrambled_charset(seed + 0x480),
                chunk3
            )
        )

        buf = list(
            int_js_to_bytes(chunk1_output, 4)
            + int_js_to_bytes(chunk2_output, 4)
            + int_js_to_bytes(chunk3_output, 4)
        )

        seed = self.generate_seed_hash("GN894EAA", self.security_id)
        self.prng.init_rnd(seed)
        buf = self.xor_bytes(buf, 8, self.prng.irnd())

        self.prng.init_rnd(int_js_from_bytes(buf[8:12]))
        buf = self.xor_bytes(buf, 0, self.prng.irnd())
        buf = self.xor_bytes(buf, 4, self.prng.irnd())

        h1 = self.calc_crc16(buf, 8) == int_js_from_bytes(buf[8:10])
        if h1 != True:
            return False

        h2 = self.calc_crc16_alt(buf, 10) == int_js_from_bytes(buf[10:12])
        if h2 != True:
            return False

        # Everything up to this point is verified correct
        buf = self.xor_bytes(buf, 4, seed)
        v = self.generate_seed_hash(self.security_id, n2h_long(int_js_from_bytes(buf[4:8])))
        buf = self.xor_bytes(buf, 0, v)

        h3 = self.calc_crc16(buf, 4) == int_js_from_bytes(buf[4:6])
        if h3 != True:
            return False

        h4 = self.calc_crc16_alt(buf, 6) == int_js_from_bytes(buf[6:8])
        if h4 != True:
            return False

        return True


    def generate_password(self, year, month, day):
        # You can't input a code from before the game was released
        assert(year > 2000)
        assert(month > 8)

        # Scramble the input password charset based on the game code + security cassette ID
        payload = day | shl(month, 8) | shl(year, 16)
        buf = int_js_to_bytes(payload, 4)

        buf += int_js_to_bytes(self.calc_crc16(buf, 4), 2)
        buf += int_js_to_bytes(self.calc_crc16_alt(buf, 6), 2)

        seed = self.generate_seed_hash(self.security_id, n2h_long(int_js_from_bytes(buf[4:8])))
        buf = self.xor_bytes(buf, 0, seed)

        seed = self.generate_seed_hash("GN894EAA", self.security_id)
        buf = self.xor_bytes(buf, 4, seed)

        buf += int_js_to_bytes(self.calc_crc16(buf, 8), 2)
        buf += int_js_to_bytes(self.calc_crc16_alt(buf, 10), 2)

        # buf[:8] must equal the checksum at buf[8:10]
        h1 = self.calc_crc16(buf, 8) == int_js_from_bytes(buf[8:10])
        if h1 != True:
            return False

        # buf[:10] must equal the checksum at buf[10:12]
        h2 = self.calc_crc16_alt(buf, 10) == int_js_from_bytes(buf[10:12])
        if h2 != True:
            return False

        chunk1_payload = int_js_from_bytes(buf[:4])
        chunk2_payload = int_js_from_bytes(buf[4:8])
        chunk3_payload = int_js_from_bytes(buf[8:12])

        seed = self.generate_seed_hash("GN894EAA", self.security_id)
        self.prng.init_rnd(seed)
        chunk3_payload ^= self.prng.irnd()

        self.prng.init_rnd(int_js_from_bytes(buf[8:12]))
        chunk1_payload ^= self.prng.irnd()
        chunk2_payload ^= self.prng.irnd()

        seed = self.generate_seed_hash(self.security_id, "GN894EAA")

        chunk1 = self.encode_chunk(
            self.generate_scrambled_charset(seed),
            self.scramble_buffer_with_seed_even_more(
                seed + 0x381,
                chunk1_payload
            )
        )

        chunk2 = self.encode_chunk(
            self.generate_scrambled_charset(seed + 0x240),
            self.scramble_buffer_with_seed_even_more(
                self.calc_crc16(chunk1),
                chunk2_payload
            )
        )

        chunk3 = self.encode_chunk(
            self.generate_scrambled_charset(seed + 0x480),
            self.scramble_buffer_with_seed_even_more(
                self.calc_crc16_alt(chunk2),
                chunk3_payload
            )
        )

        parts = []
        for x in [chunk1, chunk2, chunk3]:
            parts.append("".join([chr(c) for c in x]))

        return "-".join(parts)


def generate_password(machine_license_key, year=3030, day=9, month=22):
    try:
        irpass = EuromixIRPassword(machine_license_key)
        password = irpass.generate_password(year, day, month)

        irpass_check = EuromixIRPassword(machine_license_key)
        if irpass_check.verify_password(password) == False:
            return "Failed to generate password!"

        return password

    except ValueError as e:
        return e.message.replace("ValueError: ", "")

    except:
        return "Unknown error"