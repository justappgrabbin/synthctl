/* memhog.c — static helper: allocates and touches memory until it can't. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    size_t chunk = 4 * 1024 * 1024, total = 0;
    for (;;) {
        char *p = malloc(chunk);
        if (!p) { fprintf(stderr, "malloc failed at %zu MB\n", total >> 20); return 1; }
        memset(p, 1, chunk);
        total += chunk;
        if (total > (256UL << 20)) { printf("survived past 256MB\n"); return 0; }
    }
}
