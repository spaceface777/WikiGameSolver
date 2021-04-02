#include <stdlib.h>
#include <stdio.h>
#include <string.h>


struct Foo {
    int x;
};

// Type your code here, or load an example.
int main() {
    struct Foo x = (struct Foo){123};

    printf("%d", HEAP(x)->x);
}
