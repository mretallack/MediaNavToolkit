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

    unsigned char buf[256];
    unsigned bs[8];

    /* 14 presence bits: 0,0,0,1,1,0,1,0, 0,0,1,1,0,0 */
    /* Present fields: 3,4,6,10,11 */
    /* Field 3 = DebugMode (bool, type_id=1) */
    /* Field 4 = AutoMode (bool, type_id=1) */
    /* Field 6 = LoginArg compound (type_id=2?) → triggers sub-serialization */
    /* Field 10 = ??? */
    /* Field 11 = ??? */

    /* Actually, the present fields might be the LoginArg fields directly */
    /* if the compound type is flattened. Let me try: */
    /* 14 presence bits where 5 are present, then values for those 5 */

    /* Hypothesis: the 14 presence bits map to a FLAT list of all fields */
    /* across RequestEnvelopeRO + LoginArg, and the present ones are: */
    /* 3=DebugMode, 4=AutoMode, 6=OperatingSystemName, 10=AgentAliases, 11=Language */
    /* But that's only 5 fields, and we need 9 LoginArg fields */

    /* Let me try the INTERLEAVED model: */
    /* presence(field_i), if present AND compound: recurse into sub-fields */
    /* presence(field_i), if present AND simple: write value */

    /* For the login body, field 6 might be a compound (LoginArg) */
    /* When present, it recursively writes 9 sub-field presence bits + values */

    /* Test: 5 top-level presence + compound expansion */
    memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
    bs[0]=(unsigned)buf; bs[3]=256;

    /* Top-level: 0,0,0,1,1,0,1,0 (first 8 bits) */
    w1(bs,0); w1(bs,0); w1(bs,0);
    w1(bs,1); /* field 3 present - maybe Credentials? */
    w1(bs,1); /* field 4 present - maybe Type? */
    w1(bs,0);
    w1(bs,1); /* field 6 present - maybe LoginArg compound? */

    /* If field 6 is compound, recurse: 9 sub-fields all present */
    int i;
    for (i = 0; i < 9; i++) w1(bs, 1);

    /* Now write values for present fields */
    /* field 3 value: ??? */
    /* field 4 value: ??? */
    /* field 6 sub-values: DebugMode, AutoMode, strings... */

    /* Actually, let me just check if the presence pattern matches */
    printf("After 7+9=16 presence bits: %02x %02x\n", buf[0], buf[1]);
    printf("Expected:                   58 0c\n");

    /* 7 top-level + 9 sub = 16 presence bits */
    /* buf[0] should be: bits 0-7 = 0,0,0,1,1,0,1, then first sub-presence */
    /* bit 7 = first sub-presence = 1 */
    /* So byte 0 = 1,1,0,1,1,0,0,0 (MSB to LSB) = 0xD8? No, LSB-first: */
    /* bit0=0,bit1=0,bit2=0,bit3=1,bit4=1,bit5=0,bit6=1,bit7=1 = 0xD8 */
    /* But expected is 0x58 = bit0=0,bit1=0,bit2=0,bit3=1,bit4=1,bit5=0,bit6=1,bit7=0 */
    /* Difference: bit7. If first sub-presence is 0 (absent), byte = 0x58! */

    /* So: 7 top-level bits + first sub-field ABSENT */
    /* Let me try: field 6 is compound, first sub-field is absent */
    memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
    bs[0]=(unsigned)buf; bs[3]=256;

    w1(bs,0); w1(bs,0); w1(bs,0);
    w1(bs,1); /* field 3 */
    w1(bs,1); /* field 4 */
    w1(bs,0);
    w1(bs,1); /* field 6 = compound */
    /* Sub-fields: first absent, then 8 present */
    w1(bs,0); /* sub-field 0 absent */
    for (i = 0; i < 8; i++) w1(bs, 1); /* sub-fields 1-8 present */
    /* Remaining top-level fields */
    w1(bs,0); w1(bs,0); w1(bs,1); w1(bs,1); w1(bs,0); w1(bs,0);

    printf("\nTest compound: %02x %02x\n", buf[0], buf[1]);

    /* Try exact match: 0x58 0x0C */
    /* 0x58 = 0,0,0,1,1,0,1,0 LSB */
    /* 0x0C = 0,0,1,1,0,0,0,0 LSB */
    memset(buf, 0, sizeof(buf)); memset(bs, 0, sizeof(bs));
    bs[0]=(unsigned)buf; bs[3]=256;
    int bits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0};
    for (i = 0; i < 14; i++) w1(bs, bits[i]);
    /* Now write values for present fields (3,4,6,10,11) */
    wn(bs, 0, 1); /* field 3 value = 0 (bool false) */
    wn(bs, 0, 1); /* field 4 value = 0 (bool false) */
    /* field 6 value: string? */
    wstr(bs, "Windows 10 (build 19044)");
    /* field 10 value: string? */
    wstr(bs, "10.0.0");
    /* field 11 value: string? */
    wstr(bs, "19044");

    printf("\n14 presence + 2 bool + 3 strings: %02x %02x %02x %02x\n",
           buf[0], buf[1], buf[2], buf[3]);
    printf("Expected:                         %02x %02x %02x %02x\n",
           expected[0], expected[1], expected[2], expected[3]);

    /* Check if first 4 bytes match */
    if (buf[0]==expected[0] && buf[1]==expected[1] && buf[2]==expected[2] && buf[3]==expected[3])
        printf("*** FIRST 4 BYTES MATCH! ***\n");

    FreeLibrary(h);
    return 0;
}
