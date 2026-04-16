/*
 * r6_probe.c — Probe the igo-binary bitstream serializer
 *
 * Strategy: Use LoadLibraryExA (Mode B, no DllMain) to load nngine.dll,
 * then call the bit writer functions with known values to understand
 * how strings and other types are encoded in the value buffer.
 *
 * From toolbox.md:
 * - w1 (RVA 0x1a9e80): write 1 bit LSB-first (presence bits)
 * - wn (RVA 0x1a8150): write N bits MSB-first (value data)
 * - FUN_10056ad0: write raw bytes to growable buffer (value writer)
 * - FUN_101a8e80: compound serializer (iterates fields, writes presence + values)
 * - FUN_101a1f80: field value serializer (dispatches based on type)
 *
 * We know:
 * - type_id 1 = 1-byte value (presence only, no value bits for simple cases)
 * - type_id 5 = variable-length (string)
 * - Strings are NOT raw ASCII in the body — they're transformed somehow
 *
 * Goal: figure out the string transformation by encoding known strings
 * and comparing with captured data.
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* Bit writer function addresses (RVAs) */
static unsigned g_base;
static unsigned g_w1_addr;   /* write_1bit_lsb */
static unsigned g_wn_addr;   /* write_nbits_msb */

/* w1: write 1 bit LSB-first */
static void w1(unsigned *bs, int value) {
    unsigned f = g_w1_addr, b = (unsigned)bs;
    __asm__ volatile(
        "push %2\n\t"
        "mov %0, %%ecx\n\t"
        "call *%1"
        :: "r"(b), "r"(f), "r"(value)
        : "ecx", "edx", "eax", "memory"
    );
}

/* wn: write N bits MSB-first */
static void __attribute__((noinline)) wn(unsigned *bs, unsigned val, unsigned nb) {
    unsigned f = g_wn_addr, b = (unsigned)bs;
    __asm__ volatile(
        "mov %3, %%eax\n\t"
        "push %%eax\n\t"
        "push %2\n\t"
        "mov %0, %%ecx\n\t"
        "call *%1"
        :: "r"(b), "r"(f), "r"(val), "m"(nb)
        : "ecx", "edx", "eax", "memory"
    );
}

/* Write bytes to value buffer (FUN_10056ad0) */
static unsigned g_vw_addr;
static void __attribute__((noinline)) vwrite(unsigned *vbuf, const void *data, unsigned len) {
    unsigned f = g_vw_addr, b = (unsigned)vbuf;
    __asm__ volatile(
        "push %3\n\t"
        "push %2\n\t"
        "mov %0, %%ecx\n\t"
        "call *%1"
        :: "r"(b), "r"(f), "r"((unsigned)data), "m"(len)
        : "ecx", "edx", "eax", "memory"
    );
}

int main() {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL,
                                DONT_RESOLVE_DLL_REFERENCES);
    if (!h) {
        printf("LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    g_base = (unsigned)h;
    g_w1_addr = g_base + 0x1a9e80;
    g_wn_addr = g_base + 0x1a8150;
    g_vw_addr = g_base + 0x056ad0;

    printf("DLL at 0x%08x\n", g_base);

    /* === Test 1: Reproduce the boot body (50 86) === */
    {
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        /* Boot presence bits: fields 4, 6, 9, 10, 15 present */
        int boot_bits[] = {0,0,0,0,1,0,1,0, 0,1,1,0,0,0,0,1};
        int i;
        for (i = 0; i < 16; i++) w1(bs, boot_bits[i]);

        printf("Boot body: ");
        for (i = 0; i < 2; i++) printf("%02x ", buf[i]);
        printf("(expect: 50 86)\n");
    }

    /* === Test 2: Reproduce the login presence bits (58 0c) === */
    {
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        /* Login presence bits: fields 3, 4, 6, 10, 11 present */
        int login_bits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0,0,0};
        int i;
        for (i = 0; i < 16; i++) w1(bs, login_bits[i]);

        printf("Login presence: ");
        for (i = 0; i < 2; i++) printf("%02x ", buf[i]);
        printf("(expect: 58 0c)\n");
    }

    /* === Test 3: Try encoding a string using wn (MSB bit writer) === */
    /* If strings are encoded as MSB bits, each char would be 8 bits */
    {
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        /* Write "en" as 8-bit MSB values */
        wn(bs, 'e', 8);  /* 0x65 */
        wn(bs, 'n', 8);  /* 0x6e */
        wn(bs, 0, 8);    /* null terminator */

        printf("String 'en' via wn(8): ");
        int i;
        for (i = 0; i < 4; i++) printf("%02x ", buf[i]);
        printf("\n");
    }

    /* === Test 4: Try encoding a string using the LSB multi-bit writer === */
    /* FUN_101a8310 at RVA 0x1a8310 */
    {
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        unsigned g_wn_lsb = g_base + 0x1a8310;
        unsigned b = (unsigned)bs;

        /* Write 'e' (0x65) as 8 bits LSB-first */
        unsigned val = 'e', nb = 8;
        __asm__ volatile(
            "mov %3, %%eax\n\t"
            "push %%eax\n\t"
            "push %2\n\t"
            "mov %0, %%ecx\n\t"
            "call *%1"
            :: "r"(b), "r"(g_wn_lsb), "r"(val), "m"(nb)
            : "ecx", "edx", "eax", "memory"
        );
        /* Write 'n' (0x6e) as 8 bits LSB-first */
        val = 'n';
        __asm__ volatile(
            "mov %3, %%eax\n\t"
            "push %%eax\n\t"
            "push %2\n\t"
            "mov %0, %%ecx\n\t"
            "call *%1"
            :: "r"(b), "r"(g_wn_lsb), "r"(val), "m"(nb)
            : "ecx", "edx", "eax", "memory"
        );

        printf("String 'en' via LSB(8): ");
        int i;
        for (i = 0; i < 4; i++) printf("%02x ", buf[i]);
        printf("\n");
    }

    /* === Test 5: Encode known login field values and compare === */
    /* The login body after presence bits starts with b3 e3 92 f7 ... */
    /* Field 3 is the first present field. From the XML, the login fields are:
       Looking at the triplet array from dump_fields:
       [0]Crypt [1]Type [2]Id [3]RequestId [4]Type [5]Type
       [6]Delegation [7]Credentials [8]Version [9]Fault ...
       
       So field 3 = RequestId, field 4 = Type, field 6 = Delegation
       field 10 = Cellid(?), field 11 = Elevation(?)
       
       But that doesn't match LoginArg fields at all.
       The triplet array is for the ENVELOPE, not the body.
       The body has its own field list.
    */

    /* Let's try: what if the value data is just the raw bytes written
       by the value writer (FUN_10056ad0), concatenated? */
    /* From the XML:
       DebugMode=false (absent)
       AutoMode=false (absent)  
       OperatingSystemName="Windows 10 (build 19044)" (24 chars)
       OperatingSystemVersion="10.0.0" (6 chars)
       OperatingSystemBuildVersion="19044" (5 chars)
       AgentVersion="5.26.2024481134" (15 chars)
       AgentAliases=["Dacia_ULC"] (array with 1 string)
       Language="en" (2 chars)
       AgentType="TB" (2 chars)
       
       Total string bytes: 24+6+5+15+9+2+2 = 63 + null terminators = 70
       Actual value data: 68 bytes
       Close but not exact. Strings might not be null-terminated in the value buffer.
    */

    printf("\n=== Comparing with captured login value data ===\n");
    unsigned char captured[] = {
        0xb3, 0xe3, 0x92, 0xf7, 0x14, 0x6b, 0x98, 0x93,
        0x07, 0x9b, 0x4c, 0x5f, 0xce, 0x51, 0x52, 0x49,
        0x8b, 0x2a, 0xbc, 0x23, 0x91, 0x1c, 0xe1, 0xde,
        0x34, 0xf7, 0x90, 0xd2, 0x55, 0xf7, 0xfa, 0x89,
        0x77, 0xe0, 0x7e, 0xaf, 0xca, 0xad, 0xaa, 0x96,
        0x2c, 0x06, 0x2a, 0x60, 0x55, 0xdf, 0x08, 0x5f,
        0x3f, 0x3a, 0xf9, 0x0f, 0xb7, 0x90, 0xf6, 0xee,
        0x9c, 0xd6, 0x64, 0x65, 0xb4, 0x41, 0x8d, 0x6f,
        0x78, 0x42, 0x39, 0xf6
    };
    printf("Captured value data (%d bytes):\n", (int)sizeof(captured));
    
    /* Check if it's XOR with a known key */
    const char *os_name = "Windows 10 (build 19044)";
    printf("XOR with '%s':\n  ", os_name);
    int i;
    for (i = 0; i < 24 && i < (int)sizeof(captured); i++)
        printf("%02x ", captured[i] ^ (unsigned char)os_name[i]);
    printf("\n");

    /* Check if it's bit-reversed */
    printf("Bit-reversed first 8 bytes:\n  ");
    for (i = 0; i < 8; i++) {
        unsigned char b = captured[i], r = 0;
        int j;
        for (j = 0; j < 8; j++) r |= ((b >> j) & 1) << (7 - j);
        printf("%02x(%c) ", r, (r >= 32 && r < 127) ? r : '.');
    }
    printf("\n");

    FreeLibrary(h);
    return 0;
}
