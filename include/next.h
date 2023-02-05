#ifndef NEXT_H
#define NEXT_H

#include <stdint.h> // uint8_t
#include <inttypes.h> // PRIu32

#include "internal/sampling.h"
#include "internal/sha.h"
#include "internal/gf2x.h"
#include "internal/decode.h"


void proceed(uint8_t *h0, uint8_t *h1, uint8_t *sk1, uint8_t *pk1, uint8_t *seed);
void proceed_new(uint8_t *h0, uint8_t *h1, uint8_t *sk1, uint8_t *pk1, uint8_t *seed, uint32_t fault_offset);

static inline ret_t my_sha(OUT sha_dgst_t *  dgst,
                   IN const uint32_t byte_len,
                   IN const uint8_t *msg)
{
  // printf("SHA3 input: "); for(uint32_t i = 0; i < byte_len;++i) { printf("%02x", msg[i]); } printf("\n\n");
  sha3_384(dgst->u.raw, msg, byte_len);
  // printf("SHA3 output: "); for(uint32_t i = 0; i < 48;++i) { printf("%02x", dgst->u.raw[i]); } printf("\n\n");

  return SUCCESS;
}

static inline void convert_seed_to_m_type(m_t *m, const seed_t *seed)
{
  bike_static_assert(sizeof(*m) == sizeof(*seed), m_size_eq_seed_size);
  bike_memcpy(m->raw, seed->raw, sizeof(*m));
}

static inline void convert_m_to_seed_type(seed_t *seed, const m_t *m)
{
  bike_static_assert(sizeof(*m) == sizeof(*seed), m_size_eq_seed_size);
  bike_memcpy(seed->raw, m->raw, sizeof(*seed));
}

// (e0, e1) = H(m)
static inline ret_t function_h(pad_e_t *e, const m_t *m, const pk_t *pk)
{
  DEFER_CLEANUP(seed_t seed = {0}, seed_cleanup);

#if defined(BIND_PK_AND_M)
  DEFER_CLEANUP(sha_dgst_t  dgst = {0}, sha_dgst_cleanup);
  DEFER_CLEANUP(pk_m_bind_t pk_m = {0}, pk_m_bind_cleanup);

  // Coppy the public key and the message to a temporary buffer
  pk_m.pk = *pk;
  pk_m.m  = *m;

  // Hash the binded pk and m
  GUARD(my_sha(&dgst, sizeof(pk_m), (uint8_t *)&pk_m));

  convert_dgst_to_seed_type(&seed, &dgst);
#else
  // pk is unused parameter in this case so we do this to avoid
  // clang sanitizers complaining.
  (void)pk;

  convert_m_to_seed_type(&seed, m);
#endif
  return generate_error_vector(e, &seed);
}

// out = L(e)
static inline ret_t function_l(m_t *out, const pad_e_t *e)
{
  DEFER_CLEANUP(sha_dgst_t dgst = {0}, sha_dgst_cleanup);
  DEFER_CLEANUP(e_t tmp, e_cleanup);

  // Take the padding away
  tmp.val[0] = e->val[0].val;
  tmp.val[1] = e->val[1].val;

  GUARD(my_sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));

  // Truncate the SHA384 digest to a 256-bits m_t
  bike_static_assert(sizeof(dgst) >= sizeof(*out), dgst_size_lt_m_size);
  bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));

  return SUCCESS;
}

// Generate the Shared Secret K(m, c0, c1)
static inline ret_t function_k(ss_t *out, const m_t *m, const ct_t *ct)
{
  DEFER_CLEANUP(func_k_t tmp, func_k_cleanup);
  DEFER_CLEANUP(sha_dgst_t dgst = {0}, sha_dgst_cleanup);

  // Copy every element, padded to the nearest byte
  tmp.m  = *m;
  tmp.c0 = ct->c0;
  tmp.c1 = ct->c1;

  GUARD(my_sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));

  // Truncate the SHA384 digest to a 256-bits value
  // to subsequently use it as a seed.
  bike_static_assert(sizeof(dgst) >= sizeof(*out), dgst_size_lt_out_size);
  bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));

  return SUCCESS;
}

static inline ret_t encrypt(ct_t *ct,
                       const pad_e_t *e,
                       const pk_t *pk,
                       const m_t *m)
{
  // Pad the public key and the ciphertext
  pad_r_t p_ct = {0};
  pad_r_t p_pk = {0};
  p_pk.val     = *pk;

  // Generate the ciphertext
  // ct = pk * e1 + e0
  gf2x_mod_mul(&p_ct, &e->val[1], &p_pk);
  gf2x_mod_add(&p_ct, &p_ct, &e->val[0]);

  ct->c0 = p_ct.val;

  // c1 = L(e0, e1)
  GUARD(function_l(&ct->c1, e));

  // m xor L(e0, e1)
  for(size_t i = 0; i < sizeof(*m); i++) {
    ct->c1.raw[i] ^= m->raw[i];
  }

  // print("e0: ", (const uint64_t *)PE0_RAW(e), R_BITS);
  // print("e1: ", (const uint64_t *)PE1_RAW(e), R_BITS);
  // print("c0:  ", (uint64_t *)ct->c0.raw, R_BITS);
  // print("c1:  ", (uint64_t *)ct->c1.raw, M_BITS);

  return SUCCESS;
}


////// decode

static inline ret_t reencrypt(OUT m_t *m, IN const pad_e_t *e, IN const ct_t *l_ct)
{
  DEFER_CLEANUP(m_t tmp, m_cleanup);

  GUARD(function_l(&tmp, e));

  // m' = c1 ^ L(e')
  for(size_t i = 0; i < sizeof(*m); i++) {
    m->raw[i] = tmp.raw[i] ^ l_ct->c1.raw[i];
  }

  return SUCCESS;
}


#endif // NEXT_H
