#ifndef GEN_PK_FROM_SK_H
#define GEN_PK_FROM_SK_H

#include <stdint.h> // uint8_t

// This function is based on crypto_kem_keypair from AWS implementation,
// but without SK generation, i.e., sk needs to be supplied via parameter.
void gen_pk_from_sk(uint8_t *pk, uint8_t *sk);


#endif // GEN_PK_FROM_SK_H
