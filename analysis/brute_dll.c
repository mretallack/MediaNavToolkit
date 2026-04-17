/* brute_dll.c - Use the DLL's SnakeOil to brute-force Secret₃
 *
 * Strategy: We know the first 8 bytes of the 0x68 encrypted body
 * and the first 8 bytes of the 0x60 plaintext (assuming they match).
 * XOR gives us the expected PRNG output.
 *
 * We test candidate keys by encrypting the 0x60 plaintext prefix
 * and checking if the result matches the 0x68 encrypted prefix.
 *
 * The key space is 2^64 which is too large for brute force.
 * But the key might have structure (e.g., derived from known values).
 *
 * This program tests keys from a wordlist of candidates.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef void (__cdecl *SnakeOilFn)(void *src, int len, void *dst, uint32_t key_lo, uint32_t key_hi);

int main(void) {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) { printf("DLL load failed\n"); return 1; }
    SnakeOilFn so = (SnakeOilFn)((char*)h + 0x1B3E10);

    /* 0x60 plaintext first 8 bytes */
    uint8_t plain60[8] = {0x12, 0xbc, 0x8f, 0x27, 0x39, 0x2b, 0xfb, 0x33};
    /* 0x68 encrypted first 8 bytes */
    uint8_t enc68[8] = {0x31, 0xdc, 0x59, 0x8e, 0xdc, 0xb1, 0x3a, 0xd7};
    uint8_t out[8];

    /* Test known keys first */
    uint64_t keys[] = {
        3037636188661496ULL,  /* tb_secret */
        3745651132643726ULL,  /* tb_code */
        3362879562238844ULL,  /* hu_code */
        4196269328295954ULL,  /* hu_secret */
        0
    };
    const char *names[] = {"tb_secret", "tb_code", "hu_code", "hu_secret", NULL};

    for (int i = 0; keys[i]; i++) {
        so(plain60, 8, out, (uint32_t)keys[i], (uint32_t)(keys[i] >> 32));
        printf("%s: ", names[i]);
        for (int j = 0; j < 8; j++) printf("%02x", out[j]);
        printf(" %s\n", memcmp(out, enc68, 8) == 0 ? "*** MATCH ***" : "");
    }

    /* Try: key = combination of known values */
    uint32_t parts[] = {
        0x000BF285, 0x69BACB7C, /* hu_code halves */
        0x000EE87C, 0x16B1E812, /* hu_secret halves */
        0x000D4EA6, 0x5D36B98E, /* tb_code halves */
        0x000ACAB6, 0xC9FB66F8, /* tb_secret halves */
        0x42000B53, /* APPCID */
        0xC44D75AC, /* device.nng field3 */
        0x65FAB84A, /* device.nng field1 */
        0
    };
    int nparts = 0;
    while (parts[nparts]) nparts++;

    printf("\nTrying all pairs of known 32-bit values...\n");
    int found = 0;
    for (int i = 0; i < nparts; i++) {
        for (int j = 0; j < nparts; j++) {
            so(plain60, 8, out, parts[i], parts[j]);
            if (memcmp(out, enc68, 8) == 0) {
                printf("*** FOUND: lo=0x%08X hi=0x%08X ***\n", parts[i], parts[j]);
                uint64_t key = ((uint64_t)parts[j] << 32) | parts[i];
                printf("  Secret3 = %llu (0x%016llX)\n",
                       (unsigned long long)key, (unsigned long long)key);
                found = 1;
            }
        }
    }

    if (!found) {
        printf("No match from known value pairs.\n");

        /* Try XOR combinations */
        printf("Trying XOR combinations...\n");
        for (int i = 0; i < nparts; i++) {
            for (int j = i; j < nparts; j++) {
                uint32_t lo = parts[i] ^ parts[j];
                for (int k = 0; k < nparts; k++) {
                    for (int l = k; l < nparts; l++) {
                        uint32_t hi = parts[k] ^ parts[l];
                        so(plain60, 8, out, lo, hi);
                        if (memcmp(out, enc68, 8) == 0) {
                            printf("*** FOUND: lo=0x%08X^0x%08X hi=0x%08X^0x%08X ***\n",
                                   parts[i], parts[j], parts[k], parts[l]);
                            uint64_t key = ((uint64_t)hi << 32) | lo;
                            printf("  Secret3 = %llu\n", (unsigned long long)key);
                            found = 1;
                        }
                    }
                }
            }
        }
    }

    if (!found) printf("No match found.\n");

    FreeLibrary(h);
    return 0;
}
