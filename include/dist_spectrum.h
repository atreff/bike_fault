#ifndef DIST_SPECTRUM_H
#define DIST_SPECTRUM_H

#include <stdint.h> // uint8_t, uint32_t
#include <stddef.h> // size_t


void compute_dist_spectrum();

uint32_t get_bit_distance_count(uint8_t *ptr, size_t len, uint32_t bit_distance);
void get_bit_distance_spectrum(uint8_t *ptr, size_t len, uint32_t *bit_distances, uint32_t max_distance);
void report_distance_spectrum(uint8_t *ptr, size_t len, uint32_t max_distance, const char *file_suffix);

#endif // DIST_SPECTRUM_H
