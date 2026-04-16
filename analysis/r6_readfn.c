/*
 * r6_readfn.c — Dump the machine code of key functions at runtime
 * to understand what FUN_101bd8d0 actually does.
 */
#include <stdio.h>
#include <windows.h>

int main() {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) { printf("FAIL\n"); return 1; }
    unsigned base = (unsigned)h;
    printf("DLL at 0x%08x\n\n", base);

    /* Dump FUN_101bd8d0 (value getter) */
    unsigned char *fn = (unsigned char*)(base + 0x1bd8d0);
    printf("FUN_101bd8d0 (value getter) first 64 bytes:\n");
    int i;
    for (i = 0; i < 64; i++) {
        if (i % 16 == 0 && i > 0) printf("\n");
        printf("%02x ", fn[i]);
    }
    printf("\n\n");

    /* Dump FUN_101a1f80 (field value serializer) */
    fn = (unsigned char*)(base + 0x1a1f80);
    printf("FUN_101a1f80 (field value serializer) first 128 bytes:\n");
    for (i = 0; i < 128; i++) {
        if (i % 16 == 0 && i > 0) printf("\n");
        printf("%02x ", fn[i]);
    }
    printf("\n\n");

    /* Dump FUN_101a8e80 (compound serializer) first 256 bytes */
    fn = (unsigned char*)(base + 0x1a8e80);
    printf("FUN_101a8e80 (compound serializer) first 256 bytes:\n");
    for (i = 0; i < 256; i++) {
        if (i % 16 == 0 && i > 0) printf("\n");
        printf("%02x ", fn[i]);
    }
    printf("\n\n");

    /* Dump FUN_101a9da0 (field iterator) first 256 bytes */
    fn = (unsigned char*)(base + 0x1a9da0);
    printf("FUN_101a9da0 (field iterator) first 256 bytes:\n");
    for (i = 0; i < 256; i++) {
        if (i % 16 == 0 && i > 0) printf("\n");
        printf("%02x ", fn[i]);
    }
    printf("\n");

    FreeLibrary(h);
    return 0;
}
