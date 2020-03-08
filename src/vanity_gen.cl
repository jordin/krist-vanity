#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

#define RR(x, y) rotate((uint)(x), -(uint)(y))

#define CH(x, y, z) bitselect((z),(y),(x))
#define MAJ(x, y, z) bitselect((x),(y),(z)^(x))
#define EP0(x) (RR((x),2) ^ RR((x),13) ^ RR((x),22))
#define EP1(x) (RR((x),6) ^ RR((x),11) ^ RR((x),25))
#define SIG0(x) (RR((x),7) ^ RR((x),18) ^ ((x) >> 3))
#define SIG1(x) (RR((x),17) ^ RR((x),19) ^ ((x) >> 10))

#define SHA256_DIGEST_LENGTH 64 // nybble count

#define NYBBLE_TO_HEX_TABLE(num) nybble_to_hex_table[num]
#define NYBBLE_TO_HEX_FUNC(num) nybble_to_hex(num)

#define STRTOL_ONE_CHAR_TABLE(ch) strtol_one_char_table[ch]
#define STRTOL_ONE_CHAR_FUNC(ch) strtol_one_char(ch)

#define HEX_TO_BASE36_TABLE(num) hex_to_base36_table[num]
#define HEX_TO_BASE36_FUNC(num) hex_to_base36(num)

/* configure these options based on gpu memory speed / calculation speed */
#define NYBBLE_TO_HEX(num) NYBBLE_TO_HEX_FUNC(num)
#define STRTOL_ONE_CHAR(ch) STRTOL_ONE_CHAR_TABLE(ch)
#define HEX_TO_BASE36(num) HEX_TO_BASE36_FUNC(num)

#define CONVERT(num) (STRTOL_ONE_CHAR(num[0]) << 4 | STRTOL_ONE_CHAR(num[1]))

constant const uchar desired[] = {DESIRED_ADDRESS};

constant const uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint strtol_one_char(const uchar ch) {
    return (ch - 48) - (ch >> 6) * 39;
}

inline uchar nybble_to_hex(const uint num) {
    return 0x30 + (num) + (((num) + 6) >> 4) * 0x27;
}

inline uchar hex_to_base36(uint num) {
    num = num / 7;
    return 0x30 + num + ((num + 54) >> 6) * 39 - ((num + 28) >> 6) * 22;
}

inline uint convert(private const uchar* hash) {
    return CONVERT(hash);
}

void sha256(const ushort length, private const uchar* plain_key, private uchar* digest_str) {
    uint digest[8] = {H0, H1, H2, H3, H4, H5, H6, H7};
    int t, msg_pad;
    int stop;
    uint item, total;
    uint A, B, C, D, E, F, G, H, T1, T2;
    int current_pad;

    bool twentySeven = length == 27;
    total = 2 - twentySeven;

    for (item = 0; item < total; item++) {
        A = digest[0];
        B = digest[1];
        C = digest[2];
        D = digest[3];
        E = digest[4];
        F = digest[5];
        G = digest[6];
        H = digest[7];

        uint W[64] = {0};
        msg_pad = item << 6;

        if (length == 64 && item == 1) {
            W[0] = 0x80000000;
            W[15] = 0x200;
        } else {
            current_pad = (length - msg_pad) > 64 ? 64 : (length - msg_pad);
            stop = current_pad / 4;
            for (t = 0; t < stop; t++) {
                W[t] = (plain_key[msg_pad + t * 4]) << 24 |
                    (plain_key[msg_pad + t * 4 + 1]) << 16 |
                    (plain_key[msg_pad + t * 4 + 2]) << 8 |
                    plain_key[msg_pad + t * 4 + 3];
            }

            if (twentySeven) {
                W[t] = (plain_key[msg_pad + t * 4]) << 24 |
                    (plain_key[msg_pad + t * 4 + 1]) << 16 |
                    (plain_key[msg_pad + t * 4 + 2]) << 8 |
                    (0x80);
            } else {
                W[t] = 0x80000000;
            }

            if (current_pad < 56) {
                W[15] = length << 3;
            }
        }

        for (t = 0; t < 16; t++) {
            T1 = H + EP1(E) + CH(E, F, G) + K[t] + W[t];
            T2 = EP0(A) + MAJ(A, B, C);
            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        }

        for (t = 16; t < 64; t++) {
            W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
            T1 = H + EP1(E) + CH(E, F, G) + K[t] + W[t];
            T2 = EP0(A) + MAJ(A, B, C);

            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        }

        digest[0] += A;
        digest[1] += B;
        digest[2] += C;
        digest[3] += D;
        digest[4] += E;
        digest[5] += F;
        digest[6] += G;
        digest[7] += H;
    }

    #pragma unroll
    for (uint i = 0; i < 8; ++i) {
        uint base = i << 3;
        uint x = digest[i];
        digest_str[base] = NYBBLE_TO_HEX((x >> 28));
        digest_str[base + 1] = NYBBLE_TO_HEX((x >> 24) & 0xF);
        digest_str[base + 2] = NYBBLE_TO_HEX((x >> 20) & 0xF);
        digest_str[base + 3] = NYBBLE_TO_HEX((x >> 16) & 0xF);
        digest_str[base + 4] = NYBBLE_TO_HEX((x >> 12) & 0xF);
        digest_str[base + 5] = NYBBLE_TO_HEX((x >> 8) & 0xF);
        digest_str[base + 6] = NYBBLE_TO_HEX((x >> 4) & 0xF);
        digest_str[base + 7] = NYBBLE_TO_HEX((x) & 0xF);
    }
}

inline void double_sha256(private const ushort length, private const uchar* input, private uchar* output) {
    sha256(length, input, output);
    sha256(SHA256_DIGEST_LENGTH, output, output);
}

bool make_v1_address(private const uchar* pkey, private uchar* address, private uchar* hash) {
    sha256(68, pkey, hash);
    #pragma unroll
    for (uint i = 0; i < DESIRED_LENGTH; i++) {
        if (hash[i] != desired[i]) {
            return false;
        }
    }
    return true;
}
bool make_v2_address(private const uchar* pkey, private uchar* address, private uchar* hash) {
    uchar chars[9];
    double_sha256(68, pkey, hash);
    uint i;

    #pragma unroll
    for (i = 0; i < 9; ++i) {
        chars[i] = HEX_TO_BASE36(CONVERT(hash));
        double_sha256(SHA256_DIGEST_LENGTH, hash, hash);
    }

    bool used[9] = {false};
    
    #pragma unroll
    for (i = 0; i < 9; ++i) {
        uint index = convert(&(hash[i << 1])) % 9;

        while (used[index]) {
            sha256(SHA256_DIGEST_LENGTH, hash, hash);
            index = convert(&(hash[i << 1])) % 9;
        }

        used[index] = true;

        address[i] = chars[index];

        if (i < DESIRED_LENGTH && address[i] != desired[i]) {
            return false;
        }
    }

    return true;
}

inline void make_private_key(const ulong password, uchar* pkey) {
    pkey[0] = 'K';
    pkey[1] = 'R';
    pkey[2] = 'I';
    pkey[3] = 'S';
    pkey[4] = 'T';
    pkey[5] = 'W';
    pkey[6] = 'A';
    pkey[7] = 'L';
    pkey[8] = 'L';
    pkey[9] = 'E';
    pkey[10] = 'T';

    pkey[11] = NYBBLE_TO_HEX(password >> 60 & 0xF);
    pkey[12] = NYBBLE_TO_HEX(password >> 56 & 0xF);
    pkey[13] = NYBBLE_TO_HEX(password >> 52 & 0xF);
    pkey[14] = NYBBLE_TO_HEX(password >> 48 & 0xF);
    pkey[15] = NYBBLE_TO_HEX(password >> 44 & 0xF);
    pkey[16] = NYBBLE_TO_HEX(password >> 40 & 0xF);
    pkey[17] = NYBBLE_TO_HEX(password >> 36 & 0xF);
    pkey[18] = NYBBLE_TO_HEX(password >> 32 & 0xF);
    pkey[19] = NYBBLE_TO_HEX(password >> 28 & 0xF);
    pkey[20] = NYBBLE_TO_HEX(password >> 24 & 0xF);
    pkey[21] = NYBBLE_TO_HEX(password >> 20 & 0xF);
    pkey[22] = NYBBLE_TO_HEX(password >> 16 & 0xF);
    pkey[23] = NYBBLE_TO_HEX(password >> 12 & 0xF);
    pkey[24] = NYBBLE_TO_HEX(password >> 8 & 0xF);
    pkey[25] = NYBBLE_TO_HEX(password >> 4 & 0xF);
    pkey[26] = NYBBLE_TO_HEX(password & 0xF);

    sha256(27, pkey, pkey);

    pkey[64] = '-';
    pkey[65] = '0';
    pkey[66] = '0';
    pkey[67] = '0';
}

kernel void check(global ulong* buffer, const ulong base) {
    const size_t id = get_global_id(0);

    uchar pkey[128] = {0};
    uchar address[10] = {0};
    uchar hash[SHA256_DIGEST_LENGTH];

    for (ulong iteration = 0; iteration < ITERATIONS; ++iteration) {
        const ulong password = base + id * ITERATIONS + iteration;

        make_private_key(password, pkey);

        if (make_v2_address(pkey, address, hash)) {
            buffer[0] = password;
        }
    }
}