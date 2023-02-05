#include <stdio.h> // printf
#include <stdint.h> // uint8_t, uint32_t
#include "internal/defs.h" // IN, OUT
#include "internal/cleanup.h" // DEFER_CLEANUP
#include "internal/types.h" // ss_t, aligned_sk_t, e_t, m_t, pad_e_t
#include "internal/decode.h" // decode
#include "next.h" // reencrypt

#include "custom_decaps.h" // my_crypto_kem_dec

int my_crypto_kem_dec(OUT uint8_t *ss,
                   OUT uint8_t *ss_sigma,
                   IN const uint8_t *ct,
                   IN const uint8_t *sk)
{
  // Public values, does not require a cleanup on exit
  ct_t l_ct;

  DEFER_CLEANUP(ss_t l_ss, ss_cleanup);
  DEFER_CLEANUP(ss_t l_ss_sigma, ss_cleanup);
  DEFER_CLEANUP(aligned_sk_t l_sk, sk_cleanup);
  DEFER_CLEANUP(e_t e, e_cleanup);
  DEFER_CLEANUP(m_t m_prime, m_cleanup);
  DEFER_CLEANUP(m_t m_prime_sigma, m_cleanup);
  DEFER_CLEANUP(pad_e_t e_tmp, pad_e_cleanup);
  DEFER_CLEANUP(pad_e_t e_prime = {0}, pad_e_cleanup);

  // Copy the data from the input buffers. This is required in order to avoid
  // alignment issues on non x86_64 processors.
  bike_memcpy(&l_ct, ct, sizeof(l_ct));
  bike_memcpy(&l_sk, sk, sizeof(l_sk));

  // Decode and check if success.
  uint32_t retval;
  volatile uint32_t success_cond = (decode(&e, &l_ct, &l_sk) == SUCCESS);
  printf("\nDEBUG: success_cond of decode(...): %d (1=SUCCESS, 0=FAIL)\n", success_cond);
  // printf("\nDEBUG: success_cond = %u | expr: (retval == SUCCESS)\n", success_cond);

  // Copy the error vector in the padded struct.
  e_prime.val[0].val = e.val[0];
  e_prime.val[1].val = e.val[1];


  retval = reencrypt(&m_prime, &e_prime, &l_ct);
  if (retval != SUCCESS) {
    printf("Decaps failed at reencrypt!\n");
    return FAIL;
  }
  //GUARD(reencrypt(&m_prime, &e_prime, &l_ct));

  // Check if H(m') is equal to (e0', e1')
  // (in constant-time)
  retval = function_h(&e_tmp, &m_prime, &l_sk.pk);
  if (retval != SUCCESS) {
    printf("Decaps failed at function_h!\n");
    return FAIL;
  }
  // GUARD(function_h(&e_tmp, &m_prime, &l_sk.pk));
  success_cond = secure_cmp(PE0_RAW(&e_prime), PE0_RAW(&e_tmp), R_BYTES);
    // printf("success cond: %" PRIu32 "\n", success_cond);

  success_cond &= secure_cmp(PE1_RAW(&e_prime), PE1_RAW(&e_tmp), R_BYTES);
  // printf("success cond: %" PRIu32 "\n", success_cond);

  // success_cond = 1;
    // printf("success cond: %" PRIu32 "\n", success_cond);

  // Compute either K(m', C) or K(sigma, C) based on the success condition
  uint32_t mask = secure_l32_mask(0, success_cond);
  // printf("mask: %" PRIu32 "\n", mask);
  for(size_t i = 0; i < M_BYTES; i++) {
    m_prime.raw[i] &= u8_barrier(~mask);
    m_prime.raw[i] |= (u8_barrier(mask) & l_sk.sigma.raw[i]);
    m_prime_sigma.raw[i] = l_sk.sigma.raw[i];
  }

  // printf("m_prime: ");
  // for(int i = 0; i < 32; ++i) printf("%02x (s: %02x), ", m_prime.raw[i], l_sk.sigma.raw[i]);
  // printf("\n");

  // Generate the shared secret
  retval = function_k(&l_ss, &m_prime, &l_ct);
  uint32_t retval2 = function_k(&l_ss_sigma, &m_prime_sigma, &l_ct);
  (void)retval2;
  if (retval != SUCCESS) {
    printf("Decaps failed at function_k!\n");
    return FAIL;
  }
  // GUARD(function_k(&l_ss, &m_prime, &l_ct));

  // Copy the data into the output buffer
  bike_memcpy(ss, &l_ss, sizeof(l_ss));
  bike_memcpy(ss_sigma, &l_ss_sigma, sizeof(l_ss_sigma));

  // printf(" ss: ");
  // for (int i = 0; i < 32; ++i) {
  //   printf("%02x ", ss[i]);
  // }
  // printf("\n");

  return SUCCESS;
}
