
#include "internal/cleanup.h" // DEFER_CLEANUP
#include "internal/types.h" // pk_t, ct_t, m_t, ss_t, seeds_t, pad_e_t
#include "internal/utilities.h" // bike_memcpy, 

#include "custom_encaps.h" // my_crypto_kem_enc
#include "next.h" // get_seeds, convert_seed_to_m_type, function_h

int my_crypto_kem_enc(uint8_t *ct, uint8_t *ss, uint8_t *pk) {
  // Public values (they do not require cleanup on exit).
  pk_t l_pk;
  ct_t l_ct;

  DEFER_CLEANUP(m_t m, m_cleanup);
  DEFER_CLEANUP(ss_t l_ss, ss_cleanup);
  DEFER_CLEANUP(seeds_t seeds = {0}, seeds_cleanup);
  DEFER_CLEANUP(pad_e_t e, pad_e_cleanup);

  // Copy the data from the input buffer. This is required in order to avoid
  // alignment issues on non x86_64 processors.
  bike_memcpy(&l_pk, pk, sizeof(l_pk));

  get_seeds(&seeds);

  // e = H(m) = H(seed[0])
  convert_seed_to_m_type(&m, &seeds.seed[0]);

  // printf(GREEN "Chosen m (%zu bytes): ", sizeof(m));
  // for (size_t i = 0; i < sizeof(m); ++i) {
  //   printf("%02x ", m.raw[i]);
  // }
  // printf("\n" RESET);
  GUARD(function_h(&e, &m, &l_pk));
  // printf("(e0, e1) = H(m).\n");

  // Calculate the ciphertext
  GUARD(encrypt(&l_ct, &e, &l_pk, &m));

  // Generate the shared secret
  GUARD(function_k(&l_ss, &m, &l_ct));

  // print("ss: ", (uint64_t *)l_ss.raw, SIZEOF_BITS(l_ss));

  // Copy the data to the output buffers
  bike_memcpy(ct, &l_ct, sizeof(l_ct));
  bike_memcpy(ss, &l_ss, sizeof(l_ss));

  return SUCCESS;
  }
