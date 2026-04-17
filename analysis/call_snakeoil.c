/* call_snakeoil.c - Call SnakeOil directly from nngine.dll without DllMain */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef void (__cdecl *SnakeOilFn)(
    unsigned char* src, int len, unsigned char* dst,
    unsigned int key_lo, unsigned int key_hi
);

int main(void) {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) { printf("Failed to load DLL\n"); return 1; }

    SnakeOilFn snakeoil = (SnakeOilFn)((unsigned char*)h + 0x1B3E10);

    /* Test: encrypt zeros with tb_secret, expect BC755FBC32341970 */
    unsigned char zeros[8] = {0};
    unsigned char out[8] = {0};
    snakeoil(zeros, 8, out, 0xC9FB66F8, 0x000ACAB6);

    printf("SnakeOil(zeros, tb_secret) = ");
    for (int i = 0; i < 8; i++) printf("%02X ", out[i]);
    printf("\n");

    unsigned char expected[] = {0xBC, 0x75, 0x5F, 0xBC, 0x32, 0x34, 0x19, 0x70};
    if (memcmp(out, expected, 8) == 0) {
        printf("*** SnakeOil WORKS! ***\n");
    } else {
        printf("Output mismatch - SnakeOil not callable without init\n");
        FreeLibrary(h);
        return 1;
    }

    FreeLibrary(h);
    return 0;
}
