#ifndef UTIL_H
#define UTIL_H

#include <stddef.h> // offsetof, size_t
#include <stdint.h> // uint8_t

#include "kem.h"

void hex2bin(const char *in, uint8_t *out, size_t len);
void bin2hex(const uint8_t *in, char *out, size_t len);

// D=71 for level 1, each stored as int (4), for both h0 and h1 (2)
static const size_t WLIST_LEN = offsetof(sk_t, bin); // equals sizeof(compressed_idx_d_ar_t);

#endif // UTIL_H
