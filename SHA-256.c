//  SHA-2.c

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "SHA-256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define WORDS_PER_BLOCK 16
#define BYTES_PER_BLOCK 64
#define BYTES_PER_WORD 4
#define ROUNDS_PER_BLOCK 64

#define ROTR(n, s) (((n) >> (s)) | ((n) << (32 - (s))))

#define CH(X, Y, Z) (((X) & (Y)) ^ (~(X) & (Z)))
#define MAJ(X, Y, Z) (((X) & (Y)) ^ ((X) & (Z)) ^ ((Y) & (Z)))
#define E0(X) (ROTR(X, 2) ^ ROTR(X, 13) ^ ROTR(X, 22))
#define E1(X) (ROTR(X, 6) ^ ROTR(X, 11) ^ ROTR(X, 25))
#define e0(X) (ROTR(X, 7) ^ ROTR(X, 18) ^ ((X) >> 3))
#define e1(X) (ROTR(X, 17) ^ ROTR(X, 19) ^ ((X) >> 10))

typedef struct {
    uint32_t words[WORDS_PER_BLOCK];
} Block_t;

static void init_hash(uint32_t *hash) {
    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;
    
}

static void pad_msg(Block_t **blocks,  uint64_t *num_blocks, const char *msg, const uint64_t length) {
    uint64_t i, j;
    uint64_t num_bytes = length;
    uint64_t num_bits = length * 8;
    uint32_t t0, t1, t2, t3;
    uint8_t *pmsg;
    
    if (num_bytes % BYTES_PER_BLOCK >= 56)
        num_bytes += BYTES_PER_BLOCK;
    
    num_bytes += BYTES_PER_BLOCK - (num_bytes % BYTES_PER_BLOCK);
    
    *num_blocks = num_bytes / BYTES_PER_BLOCK;
    *blocks = calloc(*num_blocks, sizeof(Block_t));
    pmsg = calloc(num_bytes, sizeof(uint8_t));
    memcpy(pmsg, msg, length);
    
    pmsg[length] = 0x80;
    
    pmsg[num_bytes - 8] = (num_bits >> 56) & 0xff;
    pmsg[num_bytes - 7] = (num_bits >> 48) & 0xff;
    pmsg[num_bytes - 6] = (num_bits >> 40) & 0xff;
    pmsg[num_bytes - 5] = (num_bits >> 32) & 0xff;
    pmsg[num_bytes - 4] = (num_bits >> 24) & 0xff;
    pmsg[num_bytes - 3] = (num_bits >> 16) & 0xff;
    pmsg[num_bytes - 2] = (num_bits >> 8) & 0xff;
    pmsg[num_bytes - 1] = num_bits & 0xff;
    
    for (i = 0; i < *num_blocks; i++) {
        for (j = 0; j < WORDS_PER_BLOCK; j++) {
            t0 = pmsg[(i * BYTES_PER_BLOCK) + (j * BYTES_PER_WORD)];
            t1 = pmsg[(i * BYTES_PER_BLOCK) + (j * BYTES_PER_WORD) + 1];
            t2 = pmsg[(i * BYTES_PER_BLOCK) + (j * BYTES_PER_WORD) + 2];
            t3 = pmsg[(i * BYTES_PER_BLOCK) + (j * BYTES_PER_WORD) + 3];
            
            (*blocks)[i].words[j] = (t0 << 24) | (t1 << 16) | (t2 << 8) | t3;
        }
    }
    
    free(pmsg);
}

static void expand_blocks(Block_t *b, uint32_t *W) {
    int i;
    for (i = 0; i < ROUNDS_PER_BLOCK; i++) {
        if (i < 16)
            W[i] = b->words[i];
        else
            W[i] = e1(W[i - 2]) + W[i - 7] + e0(W[i - 15]) + W[i - 16];
    }
}


void sha256_hash(uint32_t *hash, const char *msg, const uint64_t length) {
    Block_t *blocks;
    uint64_t num_blocks;
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t W[ROUNDS_PER_BLOCK] = {};
    int i, j;
    
    init_hash(hash);
    pad_msg(&blocks, &num_blocks, msg, length);
    
    for (i = 1; i <= num_blocks; i++) {
        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];
        f = hash[5];
        g = hash[6];
        h = hash[7];
        expand_blocks(&blocks[i-1], W);
        
        for (j = 0; j < ROUNDS_PER_BLOCK; j++) {
            t1 = h + E1(e) + CH(e, f, g) + K[j] + W[j];
            t2 = E0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
    
    
    free(blocks);
}
