#include <windows.h>
#include <stdio.h>
#include <string.h>

/* The DLL also has bit READER functions (for deserialization) */
/* FUN_101a86b0 (RVA 0x1a86b0) = read_nbits_msb */
/* FUN_101a8790 (RVA 0x1a8790) = read_1bit_lsb */
/* Let me find them by looking at the response parser */

/* Actually, let me just WRITE the expected data using the bit writers */
/* and then read it back to verify the encoding. */

/* Better approach: write known data, compare with expected, */
/* try different field orderings. */

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

/* Try encoding with a specific field order and compare */
static int try_order(int *order, int nfields, unsigned char *expected) {
    /* Field values */
    const char *strings[] = {
        "Windows 10 (build 19044)",  /* 0: OSName */
        "10.0.0",                     /* 1: OSVersion */
        "19044",                      /* 2: OSBuildVersion */
        "5.26.2024481134",            /* 3: AgentVersion */
        NULL,                         /* 4: AgentAliases (array) */
        "en",                         /* 5: Language */
        "TB",                         /* 6: AgentType */
    };
    /* Bools: DebugMode=0 (idx 7), AutoMode=0 (idx 8) */

    unsigned char buf[256];
    unsigned bs[8];
    memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
    bs[0]=(unsigned)buf; bs[3]=256;

    /* Write 14 presence bits: 0,0,0,1,1,0,1,0, 0,0,1,1,0,0 */
    int pbits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0};
    int i;
    for (i = 0; i < 14; i++) w1(bs, pbits[i]);

    /* Write values in the given order */
    for (i = 0; i < nfields; i++) {
        int f = order[i];
        if (f == 7 || f == 8) {
            wn(bs, 0, 1); /* bool false */
        } else if (f == 4) {
            wn(bs, 1, 5); /* array count=1 */
            wstr(bs, "Dacia_ULC");
        } else if (f >= 0 && f <= 6 && strings[f]) {
            wstr(bs, strings[f]);
        }
    }

    unsigned total = bs[2] + (bs[1] > 0 ? 1 : 0);
    if (total != 70) return 0;
    return memcmp(buf, expected, 70) == 0;
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

    /* Try the original order: bools first, then strings in XML order */
    int order1[] = {7,8, 0,1,2,3,4,5,6};
    if (try_order(order1, 9, expected)) { printf("ORDER 1 MATCH!\n"); return 0; }

    /* Try: strings first, then bools */
    int order2[] = {0,1,2,3,4,5,6, 7,8};
    if (try_order(order2, 9, expected)) { printf("ORDER 2 MATCH!\n"); return 0; }

    /* Try alphabetical order */
    /* AgentAliases, AgentType, AutoMode, DebugMode, Language, */
    /* OSBuildVersion, OSName, OSVersion */
    int order3[] = {4,6,8,7,5, 2,0,1,3};
    if (try_order(order3, 9, expected)) { printf("ORDER 3 MATCH!\n"); return 0; }

    /* Try: DebugMode, AutoMode, OSName, OSVersion, OSBuildVersion, */
    /* AgentVersion, AgentAliases, Language, AgentType */
    /* But with AgentVersion BEFORE AgentAliases */
    int order4[] = {7,8, 0,1,2,3,4,5,6};
    /* Same as order1, already tried */

    /* Try swapping bools: AutoMode first */
    int order5[] = {8,7, 0,1,2,3,4,5,6};
    if (try_order(order5, 9, expected)) { printf("ORDER 5 MATCH!\n"); return 0; }

    /* Try: all strings first, bools last */
    int order6[] = {0,1,2,3,5,6,4, 7,8};
    if (try_order(order6, 9, expected)) { printf("ORDER 6 MATCH!\n"); return 0; }

    /* Brute force: try all permutations of the 9 fields */
    /* 9! = 362880 — feasible */
    int perm[9] = {0,1,2,3,4,5,6,7,8};
    int count = 0;

    /* Simple permutation generator */
    int c[9] = {0};
    if (try_order(perm, 9, expected)) { printf("PERM MATCH: "); goto found; }
    int ii = 0;
    while (ii < 9) {
        if (c[ii] < ii) {
            if (ii % 2 == 0) { int t=perm[0]; perm[0]=perm[ii]; perm[ii]=t; }
            else { int t=perm[c[ii]]; perm[c[ii]]=perm[ii]; perm[ii]=t; }
            if (try_order(perm, 9, expected)) { printf("PERM MATCH: "); goto found; }
            count++;
            c[ii]++;
            ii = 0;
        } else {
            c[ii] = 0;
            ii++;
        }
    }
    printf("No match found in %d permutations\n", count);
    goto done;

found:
    printf("{");
    { int j; for (j = 0; j < 9; j++) printf("%d%s", perm[j], j<8?",":""); }
    printf("}\n");

done:
    FreeLibrary(h);
    return 0;
}
