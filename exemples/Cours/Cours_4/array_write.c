#include <stdio.h>

int main() {
    int array[5] = {0};
    for (int i = 0; i < 5; i++) {
        array[i] = i * 2;
    }
    printf("Array filled.\n");
    return 0;
}
