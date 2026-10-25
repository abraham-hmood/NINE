#pragma once
// AES primitives for the x86-64 interpreter.
//
// Implements the byte-level operations the AES-NI instructions are defined in
// terms of (SubBytes / InvSubBytes / ShiftRows / InvShiftRows / MixColumns /
// InvMixColumns / AddRoundKey), plus a full AES-128/AES-256 key schedule and
// block encrypt/decrypt for the Key Locker bulk forms.
//
// Header-only: InsnInterpreter.cpp is the only translation unit that needs it,
// so no CMake source entry is required.

#include <cstdint>
#include <cstring>

namespace nexus {
namespace aes {

// ---- GF(2^8) arithmetic -------------------------------------------------

inline uint8_t xtime(uint8_t a) {
    return static_cast<uint8_t>((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = static_cast<uint8_t>(a & 0x80);
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1B;
        b = static_cast<uint8_t>(b >> 1);
    }
    return p;
}

inline uint8_t gpow(uint8_t a, unsigned n) {
    uint8_t r = 1;
    while (n) {
        if (n & 1) r = gmul(r, a);
        a = gmul(a, a);
        n >>= 1;
    }
    return r;
}

inline uint8_t rotl8(uint8_t a, unsigned n) {
    return static_cast<uint8_t>((a << n) | (a >> (8 - n)));
}

// Forward S-box, derived from the GF(2^8) inverse + affine transform so the
// table cannot drift from the arithmetic used by MixColumns.
inline const uint8_t* sbox() {
    static uint8_t table[256];
    static bool ready = false;
    if (!ready) {
        for (int x = 0; x < 256; ++x) {
            uint8_t inv = (x == 0) ? 0 : gpow(static_cast<uint8_t>(x), 254);
            table[x] = static_cast<uint8_t>(
                inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^
                rotl8(inv, 4) ^ 0x63);
        }
        ready = true;
    }
    return table;
}

inline const uint8_t* invSbox() {
    static uint8_t table[256];
    static bool ready = false;
    if (!ready) {
        const uint8_t* s = sbox();
        for (int x = 0; x < 256; ++x) table[s[x]] = static_cast<uint8_t>(x);
        ready = true;
    }
    return table;
}

// ---- state transforms (state is 16 bytes, column-major: 4*col + row) ----

inline void subBytes(uint8_t s[16]) {
    const uint8_t* t = sbox();
    for (int i = 0; i < 16; ++i) s[i] = t[s[i]];
}

inline void invSubBytes(uint8_t s[16]) {
    const uint8_t* t = invSbox();
    for (int i = 0; i < 16; ++i) s[i] = t[s[i]];
}

inline void shiftRows(uint8_t s[16]) {
    uint8_t out[16];
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            out[4 * c + r] = s[4 * ((c + r) & 3) + r];
    std::memcpy(s, out, 16);
}

inline void invShiftRows(uint8_t s[16]) {
    uint8_t out[16];
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            out[4 * c + r] = s[4 * ((c - r + 4) & 3) + r];
    std::memcpy(s, out, 16);
}

inline void mixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = static_cast<uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
        p[1] = static_cast<uint8_t>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
        p[2] = static_cast<uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
        p[3] = static_cast<uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
    }
}

inline void invMixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        p[0] = static_cast<uint8_t>(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
        p[1] = static_cast<uint8_t>(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
        p[2] = static_cast<uint8_t>(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
        p[3] = static_cast<uint8_t>(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
    }
}

inline void xorBlock(uint8_t s[16], const uint8_t k[16]) {
    for (int i = 0; i < 16; ++i) s[i] ^= k[i];
}

// ---- AES-NI round forms -------------------------------------------------

inline void roundEnc(uint8_t s[16], const uint8_t key[16]) {
    shiftRows(s);
    subBytes(s);
    mixColumns(s);
    xorBlock(s, key);
}

inline void roundEncLast(uint8_t s[16], const uint8_t key[16]) {
    shiftRows(s);
    subBytes(s);
    xorBlock(s, key);
}

inline void roundDec(uint8_t s[16], const uint8_t key[16]) {
    invShiftRows(s);
    invSubBytes(s);
    invMixColumns(s);
    xorBlock(s, key);
}

inline void roundDecLast(uint8_t s[16], const uint8_t key[16]) {
    invShiftRows(s);
    invSubBytes(s);
    xorBlock(s, key);
}

// ---- AESKEYGENASSIST ----------------------------------------------------

inline uint32_t subWord(uint32_t w) {
    const uint8_t* t = sbox();
    return static_cast<uint32_t>(t[w & 0xFF]) |
           (static_cast<uint32_t>(t[(w >> 8) & 0xFF]) << 8) |
           (static_cast<uint32_t>(t[(w >> 16) & 0xFF]) << 16) |
           (static_cast<uint32_t>(t[(w >> 24) & 0xFF]) << 24);
}

// RotWord for a little-endian-packed dword (the form AESKEYGENASSIST reads
// from a register/memory operand): byte sequence [b0,b1,b2,b3] -> [b1,b2,b3,b0].
inline uint32_t rotWord(uint32_t w) {
    return (w >> 8) | (w << 24);
}

// ---- key schedule -------------------------------------------------------

struct RoundKeys {
    uint8_t rk[15][16]{}; // up to Nr+1 round keys
    int rounds = 0;       // 10 (AES-128) or 14 (AES-256)
};

// Key schedule in pure byte form (FIPS-197 §5.2): word i is bytes
// w[i][0..3] in state order, which keeps RotWord endianness-free.
inline void expandKey(const uint8_t* key, int keyBytes, RoundKeys& out) {
    static const uint8_t rcon[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };
    const int nk = keyBytes / 4;          // 4 (AES-128) or 8 (AES-256)
    const int nr = nk + 6;                // 10 or 14
    const int total = 4 * (nr + 1);       // words
    uint8_t w[60][4] = {};
    for (int i = 0; i < nk; ++i)
        for (int j = 0; j < 4; ++j) w[i][j] = key[4 * i + j];

    for (int i = nk; i < total; ++i) {
        uint8_t temp[4];
        for (int j = 0; j < 4; ++j) temp[j] = w[i - 1][j];
        if (i % nk == 0) {
            // RotWord then SubWord then Rcon on the first byte.
            uint8_t rot[4] = { temp[1], temp[2], temp[3], temp[0] };
            const uint8_t* s = sbox();
            temp[0] = static_cast<uint8_t>(s[rot[0]] ^ rcon[i / nk]);
            temp[1] = s[rot[1]];
            temp[2] = s[rot[2]];
            temp[3] = s[rot[3]];
        } else if (nk > 6 && (i % nk) == 4) {
            const uint8_t* s = sbox();
            for (int j = 0; j < 4; ++j) temp[j] = s[temp[j]];
        }
        for (int j = 0; j < 4; ++j) w[i][j] = static_cast<uint8_t>(w[i - nk][j] ^ temp[j]);
    }
    for (int r = 0; r <= nr; ++r)
        for (int c = 0; c < 4; ++c)
            for (int j = 0; j < 4; ++j) out.rk[r][4 * c + j] = w[4 * r + c][j];
    out.rounds = nr;
}

inline void encryptBlock(uint8_t block[16], const RoundKeys& keys) {
    xorBlock(block, keys.rk[0]);
    for (int r = 1; r < keys.rounds; ++r) roundEnc(block, keys.rk[r]);
    roundEncLast(block, keys.rk[keys.rounds]);
}

// Straightforward inverse cipher (FIPS-197 §5.3.2 "InvCipher"). AESDEC's
// per-round "Equivalent Inverse Cipher" form is implemented separately by
// roundDec()/roundDecLast() for the AES-NI opcodes.
inline void decryptBlock(uint8_t block[16], const RoundKeys& keys) {
    xorBlock(block, keys.rk[keys.rounds]);
    for (int r = keys.rounds - 1; r >= 1; --r) {
        invShiftRows(block);
        invSubBytes(block);
        xorBlock(block, keys.rk[r]);
        invMixColumns(block);
    }
    invShiftRows(block);
    invSubBytes(block);
    xorBlock(block, keys.rk[0]);
}

// ---- NINE software Key Locker handle ------------------------------------
//
// Real AES*KL instructions unwrap a 384/512-bit handle with the internal
// wrapping key installed by LOADIWKEY (ring-0 only), so no user-mode runtime
// can synthesise a valid Intel handle. NINE therefore defines its own
// plaintext handle, which keeps the Key Locker opcodes usable and lets a
// handle that was not produced by NINE fail closed (ZF=1) instead of faulting:
//
//   offset 0..7    : 'N' 'I' 'N' 'E' 'K' 'L' 0x01 0x00
//   offset 8       : key length in bytes (16 for *128KL, 32 for *256KL)
//   offset 9..15   : zero
//   offset 16..47  : key bytes (AES-128) / offset 16..47 for AES-256
//   offset 48..63  : zero (present only in the 512-bit handle)
//
// handleBytes is 48 for 128-bit keys and 64 for 256-bit handles.
inline bool parseNineHandle(const uint8_t* handle, size_t handleBytes,
                            int expectedKeyBytes, const uint8_t*& keyOut) {
    static const uint8_t magic[7] = { 'N', 'I', 'N', 'E', 'K', 'L', 0x01 };
    if (handleBytes < 48) return false;
    if (std::memcmp(handle, magic, sizeof(magic)) != 0) return false;
    if (handle[7] != 0x00) return false;
    if (static_cast<int>(handle[8]) != expectedKeyBytes) return false;
    for (int i = 9; i < 16; ++i)
        if (handle[i] != 0) return false;
    if (handleBytes >= 64) {
        for (int i = 48; i < 64; ++i)
            if (handle[i] != 0) return false;
    }
    keyOut = handle + 16;
    return true;
}

} // namespace aes
} // namespace nexus
