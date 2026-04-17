#include <windows.h>
#include <stdio.h>
int main(void) {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 1;
    unsigned char *base = (unsigned char*)h;

    /* Key2: FUN_10154690(DAT_10314b6c, 0x100, 1, &0x30b2d0, 1, &0x30b2d8, 1, 0x40) */
    printf("=== Key2 (protected_zip) ===\n");
    printf("Exponent: 0x%08X\n", *(unsigned int*)(base + 0x30b2d0));
    printf("Modulus (64 words at 0x30b2d8):\n");
    unsigned int *mod2 = (unsigned int*)(base + 0x30b2d8);
    for (int i = 63; i >= 0; i--) {
        printf("%08X", mod2[i]);
        if (i % 8 == 0) printf("\n");
    }

    /* Key1: FUN_10101120 - modulus at 0x30b588, 64 words */
    printf("\n=== Key1 (FUN_10101120) ===\n");
    printf("Exponent: 0x%08X\n", *(unsigned int*)(base + 0x30b580));
    printf("Modulus (0x40=64 words at 0x30b588):\n");
    unsigned int *mod1 = (unsigned int*)(base + 0x30b588);
    for (int i = 63; i >= 0; i--) {
        printf("%08X", mod1[i]);
        if (i % 8 == 0) printf("\n");
    }

    /* Key3: line 277145 - FUN_10154690(DAT_10326c70, 0x80, ...) */
    /* Need to read the exact call */
    printf("\n=== Key3 (line 277145) ===\n");
    printf("Key size: 0x%08X\n", *(unsigned int*)(base + 0x30b8f0));
    printf("Exponent: 0x%08X\n", *(unsigned int*)(base + 0x30b8f8));

    FreeLibrary(h);
    return 0;
}
