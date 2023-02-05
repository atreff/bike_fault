#include <stddef.h> // size_t
#include <stdint.h> // uint8_t, uint32_t
#include <stdlib.h> // malloc, free
#include <stdio.h> // printf

#include "dist_spectrum.h"


// TODO
void compute_dist_spectrum() {

}

uint32_t get_bit_distance_count(uint8_t *ptr, size_t len, uint32_t bit_distance) {
    uint32_t counter = 0;
    uint32_t prev_pos = UINT32_MAX/2;
    uint32_t current_pos = 0;
    for(size_t i = 0; i < len; ++i) {
        for(size_t bit = 0; bit < 8; ++bit) {
            printf("%d", (ptr[i] >> (7-bit)) & 1);
        }
    }
    printf("\n");
    for (size_t i = 0; i < len; ++i) {
        for (size_t bit = 0; bit < 8; ++bit) {
            if ((ptr[i] >> (7-bit)) & 1) { // if bit is set, check whether the distance to the last position equals bit_distance
                if (current_pos - prev_pos == bit_distance) {
                    ++counter;
                    printf("Found at %zu:%zu (last: %u, now: %d)\n", i, bit, prev_pos, current_pos);
                }
                prev_pos = current_pos;
            }
            ++current_pos;
        }
    }
    printf("\n");
    return counter;
}

void report_distance_spectrum(uint8_t *ptr, size_t len, uint32_t max_distance, const char *file_suffix) {
    uint32_t *spectrum = malloc(max_distance * sizeof(uint32_t));
    get_bit_distance_spectrum(ptr, len, spectrum, max_distance);
    // char *buffer = malloc(4096);
    // sprintf(buffer, "D=(");
    printf("D=(");
    int num_distances = 0;
    for(uint32_t i = 0; i < max_distance; ++i) {
        if (spectrum[i] > 0) {
            printf("%u:%d,", i+1, spectrum[i]);
            num_distances += spectrum[i];
            // char tmpbuf[10];
            // sprintf(tmpbuf, "%u:%d,", i+1, spectrum[i]);
            // strcat(buffer, tmpbuf);
        }
    }
    // strcat(buffer, "\b)\n");
    printf("\b)\n");
    printf("Total distances: %d\n", num_distances);

    char fname[32];
    snprintf(fname, 32, "distances_%s.txt", file_suffix);
    FILE *f = fopen(fname, "w");
    for (uint32_t i = 0; i < max_distance; ++i) {
        if (spectrum[i] == 0) {
            continue;
        }
        fprintf(f, "%u, %u\n", i, spectrum[i]);
    }
    fclose(f);
    // free(buffer);
    free(spectrum);
}

void get_bit_distance_spectrum(uint8_t *ptr, size_t len, uint32_t *bit_distances, uint32_t max_distance) {
    uint32_t first_offset = UINT32_MAX/2;

    uint32_t prev_pos = UINT32_MAX/2;
    uint32_t current_pos = 0;
    for(size_t i = 0; i < len; ++i) {
        for(size_t bit = 0; bit < 8; ++bit) {
            // printf("%d", (ptr[i] >> (7-bit)) & 1);
        }
    }
    // printf("\n");
    for (size_t i = 0; i < len; ++i) {
        for (size_t bit = 0; bit < 8; ++bit) {
            if ((ptr[i] >> (7-bit)) & 1) { // if bit is set, check whether the distance to the last position equals bit_distance
                if (first_offset == UINT32_MAX/2) {
                    first_offset = current_pos;
                }
                uint32_t distance = current_pos - prev_pos;
                if (distance < max_distance) {
                    // printf("Previous one: %zu:%zu (pos: %u), distance: %u\n", i, bit, prev_pos, distance);
                    prev_pos = current_pos;
                    ++bit_distances[distance-1];
                } else {
                    prev_pos = current_pos;
                }
            }
            ++current_pos;
        }
    }
    // current_pos holds total size, prev_pos is last set bit, first_offset is first set bit.
    // Used to compute the wraparound distance
    uint32_t wraparound_distance = current_pos - prev_pos + first_offset;
    printf("WA Dist: %u\n", wraparound_distance);
    ++bit_distances[wraparound_distance];
    // printf("\n");
}
