#ifndef IMPORT_H
#define IMPORT_H

#include <stdint.h> // uint8_t

int import_keys_aws(const char *filename, uint8_t *sk, uint8_t *seed, uint8_t *sigma);

int import_keys_ref(const char *filename, uint8_t *sk);

#endif // IMPORT_H
