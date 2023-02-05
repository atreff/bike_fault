#include <string.h> // memcpy

#include "gen_pk_from_sk.h"
#include "kem.h" // pad_r_t, compressed_idx_d_ar_t, r_t, R_BYTES
#include "internal/gf2x.h" // gf2x_mod_inv, gf2x_mod_mul

// This function is based on crypto_kem_keypair from AWS implementation,
// but without SK generation, i.e., sk needs to be supplied via parameter.
void gen_pk_from_sk(uint8_t *pk, uint8_t *sk) {
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

  memcpy(pk, h.val.raw, R_BYTES);
  // also copy calculated public key to PK section of private key
  memcpy(sk+sizeof(compressed_idx_d_ar_t)+2*R_BYTES, h.val.raw, R_BYTES);
}
