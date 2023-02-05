#ifndef CUSTOM_DECAPS_H
#define CUSTOM_DECAPS_H

#include <stdint.h> // uint8_t

#include "internal/defs.h" // IN, OUT

int my_crypto_kem_dec(OUT uint8_t *ss, OUT uint8_t *ss_sigma, IN const uint8_t *ct, IN const uint8_t *sk);

#endif // CUSTOM_DECAPS_H
