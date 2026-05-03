#include <stdlib.h>

int main(void) {
    char *buf = malloc(16);
    if (!buf) {
        return 1;
    }

    free(buf);
    if (buf) {
        free(buf);
    }

    return 0;
}
