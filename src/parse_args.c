#include <stdio.h> // printf
#include <stdlib.h>
#include <getopt.h> // getopt_long, option, required_argument, no_argument
#include "parse_args.h" // tool_args_t, parse_args

static const struct option TOOL_OPTIONS_LONG[] = {
    { "iterations", required_argument, 0, 'i' },
    { "verbose",    no_argument,       0, 'v' },
    { "help",       no_argument,       0, 'h' },
    { 0 }
};
static const char *TOOL_OPTIONS_SHORT = "vhi:";

void parse_args(int argc, char **argv, tool_args_t *parsed_args) {
    for(;;) {
        int index = -1;
        int result = getopt_long(argc, argv, TOOL_OPTIONS_SHORT, TOOL_OPTIONS_LONG, &index);

        if (result == -1) {
            break;
        }
        int iters;
        switch (result) {
            case 'v':
                parsed_args->verbose = 1;
                break;
            case 'h':
                parsed_args->show_help = 1;
                break;
            case 'i':
                iters = atoi(optarg);
                if (iters <= 0) {
                    printf("error: iterations is < 0\n");
                    abort();
                }
                parsed_args->iterations = iters;
                break;
            default:
                break;
        }

    }
    while (optind < argc) {
        printf("other parameter: [%s]\n", argv[optind++]);
    }
}
