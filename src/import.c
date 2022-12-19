#include <assert.h> // assert
#include <stdbool.h> // bool, true, false
#include <stddef.h> // NULL
#include <stdint.h> // uint8_t, uint32_t
#include <stdlib.h> // malloc, free
#include <stdio.h> // FILE, fopen, fread, ftell, fseek, fgets, fclose, SEEK_END, SEEK_SET
#include <string.h> // strlen, strcspn, strncmp, strstr, strncpy

#include "kem.h" // R_BYTES, M_BYTES, compressed_idx_d_ar_t

#include "import.h"
#include "util.h" // hex2bin

const char sk_to_cmp[] = "sk = ";
const char seed_to_cmp[] = "seed = ";

void create_wlist_from_bin(const uint8_t *raw, uint32_t *wlist, uint32_t expected_bits) {
  uint32_t ctr = 0;
  uint32_t bit_ctr = 0;
  for (uint32_t i = 0; i < expected_bits;) {
    bool found_bit = false;
    if ((raw[ctr] >> bit_ctr) & 1) {
      found_bit = true;
      wlist[i] = ctr*8 + bit_ctr;
    }
    ++bit_ctr;
    if (bit_ctr == 8) {
      ++ctr;
      bit_ctr = 0;
    }
    if (found_bit) {
      ++i;
    }
  }
}

// TODO: read sigma
int import_keys_aws(const char *filename, uint8_t *sk, uint8_t *seed, uint8_t *sigma) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
      return 1;
    }
    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(file_len);
    char *ptr = NULL;
    char *seed_ptr = NULL;
    char *seed_buf = malloc(48 * 2 + 1);
    while (true) {
      if (fgets(buf, file_len, f) != NULL) {
        if (strncmp(buf, "\n", 1) == 0 && ptr != NULL && seed_ptr != NULL) {
          break;
        }
        if (strncmp(buf, seed_to_cmp, strlen(seed_to_cmp)) == 0) {
          seed_ptr = strstr(buf, " = ");
          seed_ptr += 3; // skip ' = '
          seed_ptr[strcspn(seed_ptr, "\n")] = 0;
          strncpy(seed_buf, seed_ptr, 48*2);
          continue;
        }
        if (strncmp(buf, sk_to_cmp, strlen(sk_to_cmp)) == 0) {
          ptr = strstr(buf, " = ");
          ptr += 3; // skip ' = '
          ptr[strcspn(ptr, "\n")] = 0;
          break;
        }
      } else { // reached end of line
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

    hex2bin(seed_buf, seed, 48);
    free(seed_buf);
    hex2bin(ptr, sk + sizeof(compressed_idx_d_ar_t), 2 * R_BYTES);
    create_wlist_from_bin(sk + sizeof(compressed_idx_d_ar_t), (uint32_t*)sk, 2 * D);
    ptr += 2 * (2 * R_BYTES); // skip h0 and h1
    ptr += 2 * R_BYTES; // skip h
    hex2bin(ptr, sigma, M_BYTES);

    free(buf);
    return 0;
}


int import_keys_ref(const char *filename, uint8_t *sk) {
    FILE *f = fopen(filename, "r");
    if (f == NULL) {
      return 1;
    }
    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(file_len);
    char *ptr;
    while (1) {
      if (fgets(buf, file_len, f) != NULL) {
        if (strncmp(buf, sk_to_cmp, strlen(sk_to_cmp)) == 0) {
          ptr = strstr(buf, " = ");
          ptr += 3; // skip ' = '
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

    hex2bin(ptr, sk, 2 * R_BYTES);
    free(buf);
    return 0;
}
