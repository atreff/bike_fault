#ifndef EXPORT_H
#define EXPORT_H

#include <stdint.h> // uint8_t

int export_keys_aws(const char *filename, uint8_t *sk, uint8_t *pk, uint8_t *sigma, uint8_t *seed);

#endif // EXPORT_H
