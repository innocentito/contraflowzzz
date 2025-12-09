#include <stdio.h>

int main() {
    char data[] = "secret";
    char key = 0x42;

    // xor loop
    for (int i = 0; i<6; i++) {
        data[i] ^= key;
    }

    printf("%s\n", data);
    return 0;
}