/* Minimal assertions for the host tests: count failures, keep going. */
#ifndef NIXTROPIC_TESTS_CHECK_H
#define NIXTROPIC_TESTS_CHECK_H
#include <stdio.h>

static int check_failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        check_failures++; \
    } \
} while (0)

/* Call at the end of main(): prints a summary, returns the exit code. */
static int check_done(const char *suite)
{
    if (check_failures == 0) {
        printf("%s: all passed\n", suite);
        return 0;
    }
    printf("%s: %d failed\n", suite, check_failures);
    return 1;
}
#endif
