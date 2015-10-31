//  SHA-256.h

#ifndef SHA_256
#define SHA_256

// Hashes a message into an array of 8 32-bit integers. The length is given in bytes

void sha256_hash(uint32_t *hash,  const char *msg, const uint64_t length);

#endif
