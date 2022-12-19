#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if LEVEL == 1
    static const char KAT_FILEPATH[] = "./kat/KAT_L1.rsp";
#elif LEVEL == 3
    static const char KAT_FILEPATH[] = "./kat/KAT_L3.rsp";
#else
#error Unknown level!

#endif

#include "kem.h"
#include "internal/types.h"
#include "internal/gf2x.h"
#include "internal/utilities.h"
#include "internal/sampling.h"

#include "export.h"
#include "import.h"
#include "util.h"

void keypair_internal(uint8_t *pk, uint8_t *sk) {
  // The secret key is (h0, h1),
  // and the public key h=(h0^-1 * h1).
  // Padded structures are used internally, and are required by the
  // decoder and the gf2x multiplication.
  pad_r_t h0 = {0};
  pad_r_t h1 = {0};
  pad_r_t h0inv = {0};
  pad_r_t h = {0};

  memcpy(h0.val.raw, sk+sizeof(compressed_idx_d_ar_t), sizeof(r_t));
  memcpy(h1.val.raw, sk+sizeof(compressed_idx_d_ar_t)+R_BYTES, sizeof(r_t));

  // Calculate the public key
  gf2x_mod_inv(&h0inv, &h0);
  gf2x_mod_mul(&h, &h1, &h0inv);

  // print("h0: ", (uint64_t *)&h0, R_BITS);
  // print("h0i:", (uint64_t *)&h0inv, R_BITS);
  // print("h1: ", (uint64_t *)&h1, R_BITS);
  // print("h:  ", (uint64_t *)&h, R_BITS);

  memcpy(pk, h.val.raw, R_BYTES);
}

int main() {
    uint8_t sk1[sizeof(sk_t)] = {0};
    uint8_t pk1[sizeof(pk_t)] = {0};
    uint8_t sk2[sizeof(sk_t)] = {0};
    uint8_t pk2[sizeof(pk_t)] = {0};

#ifdef USE_NIST_RAND
    char seed_hex[]= "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";  
    unsigned char seed[48];
    hex2bin(seed_hex, seed, 48);
    randombytes_init(seed, NULL, 256);
#endif
    crypto_kem_keypair(pk1, sk1);
    // for (int i = 0; i < R_BYTES; ++i) {
    //   printf("%02x ", sk1[i+sizeof(compressed_idx_d_ar_t)]);
    // }


    uint8_t *seedbuf = malloc(48);
    uint8_t *sigmabuf = malloc(M_BYTES);

    int ret = import_keys_aws(KAT_FILEPATH, sk2, seedbuf, sigmabuf);
    if (ret != 0) {
      printf("Error opening KAT file: %d\n", ret);
    }

    printf("Seed: ");
    for (unsigned int i = 0; i < 48; ++i){
      printf("%02x ", seedbuf[i]);
    }
    printf("\n");
    printf("Sigma: ");
    for (unsigned int i = 0; i < M_BYTES; ++i){
      printf("%02x ", sigmabuf[i]);
    }
    printf("\n");
    
    keypair_internal(pk2, sk2);
    export_keys_aws("./kat/export.rsp", sk2, pk2, sigmabuf, seedbuf);

    free(seedbuf);

    // memcpy(sk2, sk1, sizeof(sk_t)); // create copy of original state

    uint8_t *h0 = &sk1[sizeof(compressed_idx_d_ar_t)]; // skip wlist
    uint8_t *h1 = &sk1[sizeof(compressed_idx_d_ar_t)+R_BYTES]; // skip wlist and h0

    uint8_t *h0_1 = &sk2[sizeof(compressed_idx_d_ar_t)]; // skip wlist
    uint8_t *h1_1 = &sk2[sizeof(compressed_idx_d_ar_t)+R_BYTES]; // skip wlist and h0


    // h1[R_BYTES] ^=  1;


    int sk_cmp = memcmp(sk1, sk2, sizeof(sk_t));
    int h0_cmp = memcmp(h0, h0_1, R_BYTES);
    int h1_cmp = memcmp(h1, h1_1, R_BYTES);
    int pk_cmp = memcmp(pk1, pk2, sizeof(pk_t));

    if (h0_cmp == 0 || h1_cmp == 0) {
      printf("h0 or h1 matches: %d|%d\n", h0_cmp, h1_cmp);
    }
    if (sk_cmp == 0) {
      printf("Secret key matches!\n");
    }
    if (pk_cmp == 0) {
      printf("Public key matches!\n");
    }
    if (sk_cmp != pk_cmp && pk_cmp == 0) {
      printf("In case of fault: apparently you changed the wrong region of the secret key!\n");
    }

    uint8_t *sk_ptr = sk2;
    uint8_t *pk_ptr = pk2;

    free(sigmabuf);

    return 0;
}
