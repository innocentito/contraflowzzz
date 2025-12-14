#include <stdio.h>
#include <stdint.h>

int main() {
    uint8_t data[] = "secret";
    
    for (int i = 0; i < 6; i++) {
        __asm__(
            "movb $3, %%cl\n\t"
            "rolb %%cl, %0"
            : "+m"(data[i])
            :
            : "cl"
        );
    }
    
    printf("Rotated: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
    return 0;
}
