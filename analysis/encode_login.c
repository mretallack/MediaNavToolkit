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

static void write_string(unsigned *bs, const char *s) {
    unsigned len = 0;
    while (s[len]) len++;
    wn(bs, len, 5);  /* 5-bit length prefix */
    unsigned i;
    for (i = 0; i < len; i++)
        wn(bs, (unsigned char)s[i], 8);  /* 8-bit chars MSB */
}

int main() {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 1;
    g_w1 = (unsigned)h + 0x1a9e80;
    g_wn = (unsigned)h + 0x1a8150;

    unsigned char buf[256];
    unsigned bs[8];
    memset(buf, 0, sizeof(buf));
    memset(bs, 0, sizeof(bs));
    bs[0] = (unsigned)buf;
    bs[3] = 256;

    /* LoginArg has 9 fields, all present:
       DebugMode(bool), AutoMode(bool),
       OperatingSystemName(str), OperatingSystemVersion(str),
       OperatingSystemBuildVersion(str), AgentVersion(str),
       AgentAliases(array of str), Language(str), AgentType(str)
    */

    /* Write 9 presence bits (all present = 1) */
    int i;
    for (i = 0; i < 9; i++) w1(bs, 1);

    /* DebugMode = false → 1-bit value = 0 */
    wn(bs, 0, 1);
    /* AutoMode = false → 1-bit value = 0 */
    wn(bs, 0, 1);

    /* OperatingSystemName = "Windows 10 (build 19044)" (24 chars) */
    write_string(bs, "Windows 10 (build 19044)");
    /* OperatingSystemVersion = "10.0.0" (6 chars) */
    write_string(bs, "10.0.0");
    /* OperatingSystemBuildVersion = "19044" (5 chars) */
    write_string(bs, "19044");
    /* AgentVersion = "5.26.2024481134" (15 chars) */
    write_string(bs, "5.26.2024481134");

    /* AgentAliases = ["Dacia_ULC"] → 5-bit count=1, then string */
    wn(bs, 1, 5);  /* array count = 1 */
    write_string(bs, "Dacia_ULC");

    /* Language = "en" (2 chars) */
    write_string(bs, "en");
    /* AgentType = "TB" (2 chars) */
    write_string(bs, "TB");

    /* Check total bits */
    unsigned total_bits = bs[1] + bs[2] * 8;
    /* Actually bs[1] is bit offset within current byte, bs[2] is byte count */
    unsigned total_bytes = bs[2] + (bs[1] > 0 ? 1 : 0);

    printf("Total: %u bytes, %u bits in last byte\n", bs[2], bs[1]);
    printf("Expected: 70 bytes\n");
    printf("Output: ");
    for (i = 0; i < (int)total_bytes && i < 80; i++) printf("%02x", buf[i]);
    printf("\n");

    /* Known login body from capture */
    printf("Expect: 580cb3e392f7146b989307b94c5fce5152498b2abc23911ce1de34f790d255f7fa8977e07eafcaadaa962c062a6055df085f3f3af90fb790f6ee9cd66465b4418d6f784239f6\n");

    FreeLibrary(h);
    return 0;
}
