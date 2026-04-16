#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned g_w1, g_wn;
static void w1(unsigned *bs, int val) {
    unsigned f=g_w1, b=(unsigned)bs;
    __asm__ volatile("push %2\n\tmov %0,%%ecx\n\tcall *%1"
        :: "r"(b), "r"(f), "r"(val) : "ecx","edx","eax","memory");
}
static void __attribute__((noinline)) wn(unsigned *bs, unsigned val, unsigned nb) {
    unsigned f=g_wn, b=(unsigned)bs;
    __asm__ volatile("mov %3,%%eax\n\tpush %%eax\n\tpush %2\n\tmov %0,%%ecx\n\tcall *%1"
        :: "r"(b), "r"(f), "r"(val), "m"(nb) : "ecx","edx","eax","memory");
}
static void wstr(unsigned *bs, const char *s) {
    unsigned len = 0; while (s[len]) len++;
    wn(bs, len, 5);
    unsigned i; for (i = 0; i < len; i++) wn(bs, (unsigned char)s[i], 8);
}

int main() {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 1;
    g_w1 = (unsigned)h + 0x1a9e80;
    g_wn = (unsigned)h + 0x1a8150;

    unsigned char expected[] = {
        0x58,0x0c,0xb3,0xe3,0x92,0xf7,0x14,0x6b,0x98,0x93,0x07,0xb9,0x4c,0x5f,0xce,0x51,
        0x52,0x49,0x8b,0x2a,0xbc,0x23,0x91,0x1c,0xe1,0xde,0x34,0xf7,0x90,0xd2,0x55,0xf7,
        0xfa,0x89,0x77,0xe0,0x7e,0xaf,0xca,0xad,0xaa,0x96,0x2c,0x06,0x2a,0x60,0x55,0xdf,
        0x08,0x5f,0x3f,0x3a,0xf9,0x0f,0xb7,0x90,0xf6,0xee,0x9c,0xd6,0x64,0x65,0xb4,0x41,
        0x8d,0x6f,0x78,0x42,0x39,0xf6
    };

    /* The first 2 bytes 58 0C match with 14 presence bits. */
    /* But the string encoding doesn't match any field permutation. */
    /* Maybe the string length uses a DIFFERENT bit width than 5. */
    /* Or maybe strings are encoded differently (e.g., length-prefixed with variable bits). */

    /* Let me try: what if the string length is encoded as a VARINT? */
    /* Or what if the 5-bit "type_id" is NOT the length prefix width? */

    /* Let me try different length prefix widths */
    unsigned char buf[256];
    unsigned bs[8];

    int lw; /* length width */
    for (lw = 1; lw <= 8; lw++) {
        memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
        bs[0]=(unsigned)buf; bs[3]=256;

        /* 14 presence bits */
        int pbits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0};
        int i;
        for (i = 0; i < 14; i++) w1(bs, pbits[i]);

        /* 2 bools */
        wn(bs, 0, 1);
        wn(bs, 0, 1);

        /* First string with lw-bit length */
        unsigned slen = 24; /* "Windows 10 (build 19044)" */
        wn(bs, slen, lw);
        for (i = 0; i < (int)slen; i++) wn(bs, (unsigned char)"Windows 10 (build 19044)"[i], 8);

        unsigned total = bs[2] + (bs[1] > 0 ? 1 : 0);
        /* Check if byte 2 matches */
        if (buf[2] == expected[2]) {
            printf("lw=%d: byte2 MATCH! %02x %02x %02x %02x\n", lw, buf[0],buf[1],buf[2],buf[3]);
        }
    }

    /* Also try: what if the value for present field 3 is NOT a bool? */
    /* What if field 3 is a STRING? */
    printf("\nTrying field 3 as string:\n");
    const char *test_strings[] = {
        "Windows 10 (build 19044)", "10.0.0", "19044",
        "5.26.2024481134", "Dacia_ULC", "en", "TB",
        "false", "0", ""
    };
    int si;
    for (si = 0; si < 10; si++) {
        memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
        bs[0]=(unsigned)buf; bs[3]=256;
        int pbits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0};
        int i;
        for (i = 0; i < 14; i++) w1(bs, pbits[i]);
        /* Field 3 value as string */
        wstr(bs, test_strings[si]);
        if (buf[1] == expected[1] && buf[2] == expected[2]) {
            printf("  '%s': bytes match! %02x %02x %02x %02x\n",
                   test_strings[si], buf[0],buf[1],buf[2],buf[3]);
        }
    }

    /* Try: what if the MSB writer uses a DIFFERENT byte order? */
    /* What if after 14 LSB bits, the next value is written LSB-first too? */
    printf("\nTrying all-LSB encoding (no MSB writer):\n");
    memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
    bs[0]=(unsigned)buf; bs[3]=256;
    int pbits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0};
    int i;
    for (i = 0; i < 14; i++) w1(bs, pbits[i]);
    /* Write bools as LSB */
    w1(bs, 0); w1(bs, 0);
    /* Write string length 24 as 5 LSB bits */
    for (i = 0; i < 5; i++) w1(bs, (24 >> i) & 1);
    /* Write 'W' as 8 LSB bits */
    for (i = 0; i < 8; i++) w1(bs, (0x57 >> i) & 1);
    printf("  All-LSB: %02x %02x %02x %02x (expect 58 0c b3 e3)\n",
           buf[0], buf[1], buf[2], buf[3]);

    FreeLibrary(h);
    return 0;
}
