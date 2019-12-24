#pragma once

// This is high quality software because the includes are sorted alphabetically.
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

using namespace std;

typedef vector<uint8_t> Bytes;

namespace ChaChaMi {
uint8_t char_to_uint[256];
const char uint_to_char[10 + 26 + 1] = "0123456789abcdefghijklmnopqrstuvwxyz";

bool operator==(const Bytes &a, const Bytes &b) {
    size_t na = a.size();
    size_t nb = b.size();
    if (na != nb)
        return false;
    return memcmp(a.data(), b.data(), na) == 0;
}
Bytes str_to_bytes(const char *src) {
    return Bytes(src, src + strlen(src));
}

Bytes hex_to_raw(const Bytes &src) {
    size_t n = src.size();
    assert(n % 2 == 0);
    Bytes dst(n / 2);
    for (size_t i = 0; i < n / 2; i++) {
        uint8_t hi = char_to_uint[src[i * 2 + 0]];
        uint8_t lo = char_to_uint[src[i * 2 + 1]];
        dst[i] = (hi << 4) | lo;
    }
    return dst;
}

Bytes raw_to_hex(const Bytes &src) {
    size_t n = src.size();
    Bytes dst(n * 2);
    for (size_t i = 0; i < n; i++) {
        uint8_t hi = (src[i] >> 4) & 0xf;
        uint8_t lo = (src[i] >> 0) & 0xf;
        dst[i * 2 + 0] = uint_to_char[hi];
        dst[i * 2 + 1] = uint_to_char[lo];
    }
    return dst;
}

struct Chacha20Block {
    // This is basically a random number generator seeded with key and nonce.
    // Generates 64 random bytes every time count is incremented.

    uint32_t state[16];

    static uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t pack4(const uint8_t *a) {
        return uint32_t(a[0] << 0 * 8) |
               uint32_t(a[1] << 1 * 8) |
               uint32_t(a[2] << 2 * 8) |
               uint32_t(a[3] << 3 * 8);
    }

    static void unpack4(uint32_t src, uint8_t *dst) {
        dst[0] = (src >> 0 * 8) & 0xff;
        dst[1] = (src >> 1 * 8) & 0xff;
        dst[2] = (src >> 2 * 8) & 0xff;
        dst[3] = (src >> 3 * 8) & 0xff;
    }

    Chacha20Block(const uint8_t key[32], const uint8_t nonce[8]) {
        const uint8_t *magic_constant = (uint8_t *)"expand 32-byte k";
        state[0] = pack4(magic_constant + 0 * 4);
        state[1] = pack4(magic_constant + 1 * 4);
        state[2] = pack4(magic_constant + 2 * 4);
        state[3] = pack4(magic_constant + 3 * 4);
        state[4] = pack4(key + 0 * 4);
        state[5] = pack4(key + 1 * 4);
        state[6] = pack4(key + 2 * 4);
        state[7] = pack4(key + 3 * 4);
        state[8] = pack4(key + 4 * 4);
        state[9] = pack4(key + 5 * 4);
        state[10] = pack4(key + 6 * 4);
        state[11] = pack4(key + 7 * 4);
        // 64 bit counter initialized to zero by default.
        state[12] = 0;
        state[13] = 0;
        state[14] = pack4(nonce + 0 * 4);
        state[15] = pack4(nonce + 1 * 4);
    }

    void set_counter(uint64_t counter) {
        // Want to process many blocks in parallel?
        // No problem! Just set the counter to the block you want to process.
        state[12] = uint32_t(counter);
        state[13] = counter >> 32;
    }

    void next(uint32_t result[16]) {
        // This is where the crazy voodoo magic happens.
        // Mix the bytes a lot and hope that nobody finds out how to undo it.
        for (int i = 0; i < 16; i++)
            result[i] = state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b];                            \
    x[d] = rotl32(x[d] ^ x[a], 16);          \
    x[c] += x[d];                            \
    x[b] = rotl32(x[b] ^ x[c], 12);          \
    x[a] += x[b];                            \
    x[d] = rotl32(x[d] ^ x[a], 8);           \
    x[c] += x[d];                            \
    x[b] = rotl32(x[b] ^ x[c], 7);

        for (int i = 0; i < 10; i++) {
            CHACHA20_QUARTERROUND(result, 0, 4, 8, 12)
            CHACHA20_QUARTERROUND(result, 1, 5, 9, 13)
            CHACHA20_QUARTERROUND(result, 2, 6, 10, 14)
            CHACHA20_QUARTERROUND(result, 3, 7, 11, 15)
            CHACHA20_QUARTERROUND(result, 0, 5, 10, 15)
            CHACHA20_QUARTERROUND(result, 1, 6, 11, 12)
            CHACHA20_QUARTERROUND(result, 2, 7, 8, 13)
            CHACHA20_QUARTERROUND(result, 3, 4, 9, 14)
        }

        for (int i = 0; i < 16; i++)
            result[i] += state[i];

        uint32_t *counter = state + 12;
        // increment counter
        counter[0]++;
        if (0 == counter[0]) {
            // wrap around occured, increment higher 32 bits of counter
            counter[1]++;
            // Limited to 2^64 blocks of 64 bytes each.
            // If you want to process more than 1180591620717411303424 bytes
            // you have other problems.
            // We could keep counting with counter[2] and counter[3] (nonce),
            // but then we risk reusing the nonce which is very bad.
            assert(0 != counter[1]);
        }
    }

    void next(uint8_t result8[64]) {
        uint32_t temp32[16];

        next(temp32);

        for (size_t i = 0; i < 16; i++)
            unpack4(temp32[i], result8 + i * 4);
    }
};

struct Chacha20 {
    // XORs plaintext/encrypted bytes with whatever Chacha20Block generates.
    // Encryption and decryption are the same operation.
    // Chacha20Blocks can be skipped, so this can be done in parallel.
    // If keys are reused, messages can be decrypted.
    // Known encrypted text with known position can be tampered with.
    // See https://en.wikipedia.org/wiki/Stream_cipher_attack

    Chacha20Block block;
    uint8_t keystream8[64];
    size_t position;

    Chacha20(
        const uint8_t key[32],
        const uint8_t nonce[8],
        uint64_t counter = 0) : block(key, nonce), position(64) {
        block.set_counter(counter);
    }

    void crypt(uint8_t *bytes, size_t n_bytes) {
        for (size_t i = 0; i < n_bytes; i++) {
            if (position >= 64) {
                block.next(keystream8);
                position = 0;
            }
            bytes[i] ^= keystream8[position];
            position++;
        }
    }
};

void test_keystream(
    const char *text_key,
    const char *text_nonce,
    const char *text_keystream) {
    Bytes key = hex_to_raw(str_to_bytes(text_key));
    Bytes nonce = hex_to_raw(str_to_bytes(text_nonce));
    Bytes keystream = hex_to_raw(str_to_bytes(text_keystream));

    // Since Chacha20 just XORs the plaintext with the keystream,
    // we can feed it zeros and we will get the keystream.
    Bytes zeros(keystream.size(), 0);
    Bytes result(zeros);

    Chacha20 chacha(key.data(), nonce.data());
    chacha.crypt(&result[0], result.size());

    assert(result == keystream);
}

void test_crypt(
    const char *text_key,
    const char *text_nonce,
    const char *text_plain,
    const char *text_encrypted,
    uint64_t counter) {
    Bytes key = hex_to_raw(str_to_bytes(text_key));
    Bytes nonce = hex_to_raw(str_to_bytes(text_nonce));
    Bytes plain = hex_to_raw(str_to_bytes(text_plain));
    Bytes encrypted = hex_to_raw(str_to_bytes(text_encrypted));

    Chacha20 chacha(key.data(), nonce.data(), counter);

    Bytes result(plain);
    // Encryption and decryption are the same operation.
    chacha.crypt(&result[0], result.size());

    assert(result == encrypted);
}

uint32_t adler32(const uint8_t *bytes, size_t n_bytes) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n_bytes; i++) {
        a = (a + bytes[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

void test_encrypt_decrypt(uint32_t expected_adler32_checksum) {
    // Encrypt and decrypt a megabyte of [0, 1, 2, ..., 255, 0, 1, ...].
    Bytes bytes(1024 * 1024);
    for (size_t i = 0; i < bytes.size(); i++)
        bytes[i] = i & 255;

    // Encrypt

    // Best password by consensus.
    uint8_t key[32] = {1, 2, 3, 4, 5, 6};
    // Really does not matter what this is, except that it is only used once.
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    Chacha20 chacha(key, nonce);
    chacha.crypt(bytes.data(), bytes.size());

    // Verify by checksum that the encrypted text is as expected.
    // Note that the adler32 checksum is not cryptographically secure.
    // It is only used for testing here.
    uint32_t checksum = adler32(bytes.data(), bytes.size());
    assert(checksum == expected_adler32_checksum);

    // Decrypt

    // Reset ChaCha20 de/encryption object.
    chacha = Chacha20(key, nonce);
    chacha.crypt(bytes.data(), bytes.size());

    // Check if crypt(crypt(input)) == input.
    for (size_t i = 0; i < bytes.size(); i++)
        assert(bytes[i] == (i & 255));
}

}; // namespace ChaChaMi