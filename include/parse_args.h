#ifndef PARSE_ARGS
#define PARSE_ARGS

#include <stdbool.h> // bool

typedef struct tool_args_s {
    bool verbose;
    bool show_help;
    unsigned int iterations;
} tool_args_t;

void parse_args(int argc, char **argv, tool_args_t *parsed_args);

#endif // PARSE_ARGS
