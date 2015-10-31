//  main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "SHA-256.h"

static char *msg = "The quick brown fox jumps over the lazy dog";

int main(int argc, const char * argv[]) {
    
    // example usage
    
    uint32_t hash[8];
    sha256_hash(hash, msg, strlen(msg));
    
    printf("Message: %s\nSHA-256 hash: ", msg);
    
    for (int i = 0; i < 8; i++) {
        printf("%08x ", hash[i]);
    }

    printf("\n");
    
    return 0;
}
