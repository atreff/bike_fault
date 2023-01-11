#ifndef UTIL_H
#define UTIL_H

#include <stddef.h> // offsetof, size_t
#include <stdint.h> // uint8_t

#include "kem.h"

void hex2bin(const char *in, uint8_t *out, size_t len);
void bin2hex(const uint8_t *in, char *out, size_t len);

// D=71 for level 1, each stored as int (4), for both h0 and h1 (2)
static const size_t WLIST_LEN = offsetof(sk_t, bin); // equals sizeof(compressed_idx_d_ar_t);


// ANSI terminal specific stuff

#define RESET      "\x1B[0m"
#define BLACK      "\x1B[30m"
#define RED        "\x1B[31m"
#define GREEN      "\x1B[32m"
#define YELLOW     "\x1B[33m"
#define BLUE       "\x1B[34m"
#define MAGENTA    "\x1B[35m"
#define CYAN       "\x1B[36m"
#define WHITE      "\x1B[37m"
#define DEFAULT    "\x1B[39m"
#define BGBLACK    "\x1B[40m"
#define BGRED      "\x1B[41m"
#define BGGREEN    "\x1B[42m"
#define BGYELLOW   "\x1B[43m"
#define BGBLUE     "\x1B[44m"
#define BGMAGENTA  "\x1B[45m"
#define BGCYAN     "\x1B[46m"
#define BGWHITE    "\x1B[47m"
#define BGDEFAULT  "\x1B[49m"
#define BOLD       "\x1B[1m"
#define DIM        "\x1B[2m"
#define ITALIC     "\x1B[3m"
#define UNDERLINE  "\x1B[4m"
#define BLINK      "\x1B[5m"
#define INVERSE    "\x1B[7m"
#define HIDDEN     "\x1B[8m"
#define STRIKETHRU "\x1B[9m"
#define DUNDERLINE "\x1B[21m"

#define LINEUP     "\033[1A"
#define LINEUP2    "\033[2A"
#define LINEUP3    "\033[3A"
#define LINEUP4    "\033[4A"
#define LINEUP5    "\033[5A"

#define ERASELINE  "\033[2K"

#endif // UTIL_H
