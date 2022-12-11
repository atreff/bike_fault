#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define VERBOSE 1
#include "kem.h"
#include "internal/types.h"
#include "internal/gf2x.h"
#include "internal/utilities.h"
#include "internal/sampling.h"

static const size_t WLIST_LEN = sizeof(compressed_idx_d_ar_t); // D=71 for level 1, each stored as int (4), for both h0 and h1 (2)


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

const char *to_cmp = "sk = ";

void hex2bin(const char *in, unsigned char *out, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    sscanf(&in[2*i], "%2hhx", &out[i]);
  }
}

void bin2hex(const unsigned char *in, char *out, size_t len) {
    static const char HEX[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        out[i*2]   = HEX[in[i] >> 4];
		out[i*2+1] = HEX[in[i] & 0x0F];
    }
}

void import_keys_aws(const char *filename, uint8_t *sk) {
    FILE *f = fopen(filename, "r");
    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(file_len);
    char *ptr = NULL;
    while (1) {
      if (fgets(buf, file_len, f) != NULL) {
        if (strncmp(buf, to_cmp, strlen(to_cmp)) == 0) {
          ptr = strstr(buf, " = ");
          ptr+=3; // skip ' = '
          ptr[strcspn(ptr, "\n")] = 0;
          break;
        }
      } else {
        break;
      }
    }
    fclose(f);
    // printf("%s", ptr);
    assert(sizeof(compressed_idx_d_ar_t) == 4*D*2);

    const unsigned int kat_rsp_sk_len = (WLIST_LEN // wlist
                                + R_BYTES*2 // h0 and h1
                                + R_BYTES // h
                                + M_BYTES) // sigma
                                * 2; // hex repr
    // printf("\n%d<=>%d\n", strlen(ptr), (4*D*2+R_BYTES+R_BYTES*2+M_BYTES)*2);
    assert(strlen(ptr) == kat_rsp_sk_len);
    ptr += sizeof(compressed_idx_d_ar_t)*2;//4*D*2*2;
    // printf("\nh0:\n");
    // for (int i = 0; i < R_BYTES; ++i) { // h0
    //   printf("%c%c ", ptr[2*i], ptr[2*i+1]);
    // }
    // printf("\nh1:\n");
    // for (int i = 0; i < R_BYTES; ++i) { // h1
    //   printf("%c%c ", ptr[R_BYTES+2*i], ptr[R_BYTES+2*i+1]);
    // }
    // printf("\n");

    hex2bin(ptr, sk+sizeof(compressed_idx_d_ar_t), 2*R_BYTES);
    free(buf);  
}
void export_keys_aws(const char *filename, uint8_t *sk, uint8_t *pk) {
    FILE *f = fopen(filename, "w");
    const char *header = "# BIKE\n\ncount = 0\nseed = *\n";
    fwrite(header, strlen(header), 1, f);
    const char *text_pk = "pk = ";
    char *pk_hex = malloc(2*R_BYTES);
    bin2hex(pk, pk_hex, R_BYTES);
    fwrite(text_pk, strlen(text_pk), 1, f);
    free(pk_hex);
    fwrite(pk_hex, strlen(pk_hex), 1, f);
    fwrite("\n", 1, 1, f);
    const char *text_sk = "sk = ";
    char *sk_hex = malloc(2*(2*R_BYTES));
    // We do not save corresponding weight lists, just fill with *!
    bin2hex(sk+WLIST_LEN, sk_hex, 2*R_BYTES);
    fwrite(text_sk, strlen(text_sk), 1, f);
    for (unsigned int ctr = 0; ctr < WLIST_LEN*2; ++ctr) {
        fwrite("*", 1, 1, f);
    }
    fwrite(sk_hex, strlen(sk_hex), 1, f);
    free(sk_hex);
    // We do not save the public key (again), just fill with #!
    for (unsigned int ctr = 0; ctr < R_BYTES*2; ++ctr) {
        fwrite("#", 1, 1, f);
    }
    // We do not save the corresponding sigma, just fill with -!
    for (unsigned int ctr = 0; ctr < M_BYTES*2; ++ctr) {
        fwrite("-", 1, 1, f);
    }
    fwrite("\n", 1, 1, f);
    const char *text_ct = "ct = *\n";
    fwrite(text_ct, strlen(text_ct), 1, f);
    const char *text_ss = "ss = *\n";
    fwrite(text_ss, strlen(text_ss), 1, f);
    fclose(f);
}

void import_keys_ref(const char *filename, uint8_t *sk) {
    FILE *f = fopen(filename, "r");
    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(file_len);
    char *ptr;
    while (1) {
      if (fgets(buf, file_len, f) != NULL) {
        if (strncmp(buf, to_cmp, strlen(to_cmp)) == 0) {
          ptr = strstr(buf, " = ");
          ptr+=3; // skip ' = '
          ptr[strcspn(ptr, "\n")] = 0;
          break;
        }
        
      } else {
        break;
      }
    }
    fclose(f);
    // printf("%s", ptr);
    assert(strlen(ptr) == (R_BYTES*2 + M_BYTES)*2);
    // printf("\nh0:\n");
    // for (int i = 0; i < R_BYTES; ++i) { // h0
    //   printf("%c%c ", ptr[2*i], ptr[2*i+1]);
    // }
    // printf("\nh1:\n");
    // for (int i = 0; i < R_BYTES; ++i) { // h1
    //   printf("%c%c ", ptr[R_BYTES+2*i], ptr[R_BYTES+2*i+1]);
    // }
    // printf("\n");

    hex2bin(ptr, sk, 2*R_BYTES);
    free(buf);
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
    import_keys_aws("./kat/PQCkemKAT_BIKE_5223.rsp", sk2);
    
    keypair_internal(pk2, sk2);
    export_keys_aws("./kat/export.rsp", sk2, pk2);


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
    return 0;
}
