#include "pch.h"
#include "util.h"

void printhex(const void* data, size_t len) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
    for (int i = 0; i < len; i++) {
        printf("%02X ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
    printf("[end: %zu bytes]\n", len);
}