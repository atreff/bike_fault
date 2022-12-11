#include <assert.h>
#include <stdlib.h> // malloc, free
#include <stdio.h> // FILE, fopen, fread, ftell, fseek, fgets, fclose
#include <string.h> // strlen

#include "kem.h" // R_BYTES, M_BYTES, compressed_idx_d_ar_t

#include "import.h"
#include "util.h" // hex2bin

const char *to_cmp = "sk = ";

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
