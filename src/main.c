#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEY_PAIR
#if LEVEL == 1
    static const char KAT_FILEPATH[] = "./kat/KAT_L1.rsp";
#elif LEVEL == 3
    static const char KAT_FILEPATH[] = "./kat/KAT_L3.rsp";
#else
#error Unknown level!

#endif
#endif // KEY_PAIR

#include "kem.h"
#include "internal/types.h"
#include "internal/gf2x.h"
#include "internal/utilities.h"
#include "internal/sampling.h"
#include "bike_fromnist_rng.h"


#include "export.h"
#include "import.h"
#include "next.h"
#include "util.h"
#include "parse_args.h"
#include "dist_spectrum.h"
#include "gen_pk_from_sk.h"

extern AES256_CTR_DRBG_struct DRBG_ctx;


#ifdef KEY_PAIR
int main(int argc, char **argv) {
    uint8_t sk[sizeof(sk_t)] = {0};
    uint8_t pk[sizeof(pk_t)] = {0};
    char pk_hex[sizeof(pk_t)*2+1] = {0};
    int len;

    if (argc != 2) {
      printf("wrong number of arguments, just pass a secret key as hex string\n");
      return 1;
    }
    len = strlen(argv[1]);
    if (len != sizeof(sk_t) *2) {
      printf("wrong input length: supposed to be %lu, actually %d\n", sizeof(sk_t) *2, len);
      return 1;
    }

    hex2bin(argv[1], sk, len/2);
    gen_pk_from_sk(pk, sk);
    bin2hex(pk, pk_hex, sizeof(pk_t));

    printf("%s\n", pk_hex);

    return 0;
}
#else // KEY_PAIR


int main(int argc, char **argv) {
    tool_args_t args;
    parse_args(argc, argv, &args);

    if (args.show_help) {
        print_help();
        return 0;
    }
    if (args.verbose) {
        printf("Verbose specified.\n");
    }

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

    // FAULT YOUR SECRET KEY (sk2) HERE AS YOU LIKE
    // curly braces are intended to limit scope of pointers used in sample code
    // I have not tested the code below, but it should give you an idea ;)
    {
    /*
    // Example: fault wlist data:
    uint32_t *wlist_h0 = &(uint32_t*)sk2[0];
    uint32_t *wlist_h1 = &(uint32_t*)sk2[WLIST_LEN/2];
    wlist_h0[5] ^= 0x000000ff; // toggle lowest byte of fifth weight list entry of h0
    wlist_h1[10] |= 0xff000000; // set highest byte of tenth weight list entry of h1
    wlist_h0[4] = wlist_h0[40]; // set fourth weight list entry of h0 to fourtiest weight list entry of h0
    */

    /*
    // Example: fault wlist data:
    uint8_t *raw_h0 = sk2[WLIST_LEN];
    uint8_t *raw_h1 = sk2[WLIST_LEN+R_BYTES/2];
    raw_h0[500] ^= 0x01; // flip lowest bit of byte #500 of h0
    raw_h1[1000] = 0x40; // set byte #1000 of h1 to 0x40 (i.e., 01000000 in binary representation)
    raw_h1[1020] = 0x55; // set byte #1020 of h1 to 0x55 (i.e., 01010101 in binary representation)
    */
    }

    // Generate corresponding public key

    memcpy(sk2, sk1, WLIST_LEN+R_BYTES*2);

    gen_pk_from_sk(pk2, sk2);

    // Export key again to hex format
    ret = export_keys_aws("./kat/export.rsp", sk2, pk2, sigmabuf, seedbuf);
    if (ret != 0) {
      printf("Error while writing KAT file.\n");
    }

    free(seedbuf);
    free(sigmabuf);

    memcpy(sk2, sk1, sizeof(sk_t)); // create copy of original state

    uint8_t *h0 = &sk1[sizeof(compressed_idx_d_ar_t)]; // skip wlist
    uint8_t *h1 = &sk1[sizeof(compressed_idx_d_ar_t) + R_BYTES]; // skip wlist and h0

    uint8_t *h0_1 = &sk2[sizeof(compressed_idx_d_ar_t)]; // skip wlist
    uint8_t *h1_1 = &sk2[sizeof(compressed_idx_d_ar_t) + R_BYTES]; // skip wlist and h0


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

    // report_distance_spectrum(h0, R_BYTES, R_BITS, "h0");
    // report_distance_spectrum(h1, R_BYTES, R_BITS, "h1");
    // report_distance_spectrum(pk1, R_BYTES, R_BITS, "h");

    uint8_t* fresh_h0 = malloc(R_BYTES);
    uint8_t* fresh_h1 = malloc(R_BYTES);
    uint8_t* fresh_seed = malloc(48);
    uint8_t* fresh_sk2 = malloc(sizeof(sk_t));
    uint8_t* fresh_pk2 = malloc(sizeof(pk_t));

    const size_t aes_struct_size = sizeof(DRBG_ctx);
    uint8_t drbg_buf[aes_struct_size];
    uint8_t *drbg_ptr = (uint8_t*)&DRBG_ctx;
    memcpy(drbg_buf, drbg_ptr, aes_struct_size); // save state
    
    const uint32_t NUM_RUNS = 100;
    for (uint32_t i = 0; i < NUM_RUNS; ++i) {
      memcpy(fresh_sk2, sk1, sizeof(sk_t));
      memcpy(fresh_pk2, pk1, sizeof(pk_t));
      printf("Run %u of %u: ", i+1, NUM_RUNS);
      int fault_offset = rand() % (R_BYTES);
      fresh_sk2[WLIST_LEN+fault_offset] ^= 1;
      printf("(faulting at %d)", fault_offset);

      // memcpy(drbg_ptr, drbg_buf, aes_struct_size); // restore state

      proceed(fresh_h0, fresh_h1, fresh_sk2, fresh_pk2, fresh_seed);
    }

    free(fresh_h0);
    free(fresh_h1);
    free(fresh_seed);
    free(fresh_sk2);
    free(fresh_pk2);

    return 0;
}
#endif // KEY_PAIR
