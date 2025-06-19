#include <stdio.h>

int check(int input) {
    if (input == 1337) {
        return 1;
    }
    return 0;
}

int main() {
    int val = 0;
    check(val);
    return 0;
}
