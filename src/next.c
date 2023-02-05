#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "kem.h"

#include "custom_decaps.h"
#include "custom_encaps.h"
#include "next.h"
#include "FromNIST/rng.h"
#include "util.h"

extern AES256_CTR_DRBG_struct DRBG_ctx;

void proceed_new(uint8_t *h0 __attribute__((unused)),
                 uint8_t *h1 __attribute__((unused)),
                 uint8_t *sk,
                 uint8_t *pk,
                 uint8_t *seed __attribute__((unused)),
                 uint32_t fault_offset __attribute__((unused))
                 ) {
  uint8_t *ct = malloc(sizeof(ct_t));
  uint8_t *ss_a = malloc(sizeof(ss_t));
  uint8_t *ss_b = malloc(sizeof(ss_t));
  // uint8_t *ss_sigma_b = malloc(sizeof(ss_t));
  memset(ct, 0, sizeof(ct_t));
  memset(ss_a, 0, sizeof(ss_t));
  memset(ss_b, 0, sizeof(ss_t));
  // memset(ss_sigma_b, 0, sizeof(ss_t));

  const size_t aes_struct_size = sizeof(DRBG_ctx);
  uint8_t drbg_buf[aes_struct_size];
  uint8_t *drbg_ptr = (uint8_t*)&DRBG_ctx;
  memcpy(drbg_buf, drbg_ptr, aes_struct_size); // save state
  // my_crypto_kem_enc(ct, ss_a, pk);
  crypto_kem_enc(ct, ss_a, pk);
  crypto_kem_dec(ss_b, ct, sk);
  memcpy(drbg_ptr, drbg_buf, aes_struct_size); // restore state
  // sk[fault_offset] ^= 1;

  // my_crypto_kem_dec(ss_b, ss_sigma_b, ct, sk);

  // sk[fault_offset] ^= 1;
  printf("ss_b: ");
  for(int a = 0; a < 32; ++a) printf("%02x ", ss_a[a]);
  printf("\n");

  free(ct);
  free(ss_a);
  free(ss_b);
  // free(ss_sigma_b);
}
                 

void proceed(uint8_t *h0 __attribute__((unused)),
             uint8_t *h1 __attribute__((unused)),
             uint8_t *sk,
             uint8_t *pk,
             uint8_t *seed __attribute__((unused))) {
    // printf("Now proceeding with encaps...\n");
    // printf("sk sigma: ");
    // for (int i = 0; i < 32; ++i) printf("%02x ", sk[R_BYTES*3+WLIST_LEN+i]);
    // printf("\n");

    uint8_t *ct1 = malloc(sizeof(ct_t));
    uint8_t *ct2 = malloc(sizeof(ct_t));
    uint8_t *ss1_a = malloc(sizeof(ss_t));
    uint8_t *ss1_b = malloc(sizeof(ss_t));
    uint8_t *ss1_sigma_b = malloc(sizeof(ss_t));
    uint8_t *ss2_a = malloc(sizeof(ss_t));
    uint8_t *ss2_b = malloc(sizeof(ss_t));
    memset(ct1, 0, sizeof(ct_t)); memset(ct2, 0, sizeof(ct_t));
    memset(ss1_a, 0, sizeof(ss_t)); memset(ss2_a, 0, sizeof(ss_t));
    memset(ss1_b, 0, sizeof(ss_t)); memset(ss2_b, 0, sizeof(ss_t));

    const size_t aes_struct_size = sizeof(DRBG_ctx);
    uint8_t drbg_buf[aes_struct_size];
    uint8_t *drbg_ptr = (uint8_t*)&DRBG_ctx;
    memcpy(drbg_buf, drbg_ptr, aes_struct_size); // save state

    my_crypto_kem_enc(ct2, ss1_a, pk);

    memcpy(drbg_ptr, drbg_buf, aes_struct_size); // restore state

    crypto_kem_enc(ct1, ss2_a, pk);

    // memcpy(drbg_ptr, drbg_buf, aes_struct_size); // restore state


    // printf("Now proceeding with decaps...");
    my_crypto_kem_dec(ss1_b, ss1_sigma_b, ct2, sk);
    sk[WLIST_LEN+10] ^= 1;
    crypto_kem_dec(ss2_b, ct1, sk);
    // printf("\n");

    int res1 = memcmp(ss2_a, ss2_b, sizeof(ss_t));
    int res2 = memcmp(ss1_a, ss1_b, sizeof(ss_t));

    printf("my_crypto_kem_enc+my_crypto_kem_dec ss:\n");
    printf("Alice: [");
    for (int i = 0; i < 32; ++i) printf("%02x ", ss1_a[i]);
    printf("\b]\n");
    printf("Bob:   [");
    for (int i = 0; i < 32; ++i) printf("%02x ", ss1_b[i]);
    printf("\b]\n");
    // printf("Sigma: [");
    // for (int i = 0; i < 32; ++i) printf("%02x ", sk[WLIST_LEN+3*R_BYTES+i]);
    // printf("\b]\n");
    printf("BobSig [");
    for (int i = 0; i < 32; ++i) printf("%02x ", ss1_sigma_b[i]);
    printf("\b]\n");

    // printf("   crypto_kem_enc+   crypto_kem_dec ss:\n");
    // printf("Alice: [");
    // for (int i = 0; i < 32; ++i) printf("%02x ", ss2_a[i]);
    // printf("\b]\n");
    // printf("Bob:   [");
    // for (int i = 0; i < 32; ++i) printf("%02x ", ss2_b[i]);
    // printf("\b]\n");

    // printf("CMP Res: %d, %d\n", res1, res2);


    free(ss1_a);
    free(ss1_b);
    free(ss1_sigma_b);
    free(ss2_a);
    free(ss2_b);
    free(ct1);
    free(ct2);
}
