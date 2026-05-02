#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        char command[1000] = {0};
        sprintf(command, "userinfo -v \"%s\"", argv[1]);
        system(command);
    }
    return 0;
}
