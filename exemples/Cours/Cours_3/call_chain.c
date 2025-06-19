#include <stdio.h>

void fonction_b() {
    printf("Inside fonction_b\n");
}

void fonction_a() {
    printf("Inside fonction_a\n");
    fonction_b();
}

int main() {
    fonction_a();
    return 0;
}
