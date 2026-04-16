/*
 * r6_strings.c — Figure out how strings are encoded in the value buffer
 *
 * The key question: the value data in captured requests is not plaintext.
 * What transformation is applied to strings before they go into the buffer?
 *
 * Approach: Call FUN_101a1f80 (field value serializer) directly with
 * a fake field descriptor and known string values. This function dispatches
 * based on type_id to write the value.
 *
 * From toolbox.md:
 * - FUN_101a1f80 checks mode flag, calls FUN_101a8310 (LSB) or FUN_101a8150 (MSB)
 * - type_id 5 = variable-length (string)
 * - The value getter FUN_101bd8d0 returns a "transformed" value
 *
 * Alternative: maybe the "transformation" is just that strings are written
 * as length-prefixed byte sequences into the value buffer, and the apparent
 * randomness is because the presence bits and value bytes are interleaved
 * in the final bitstream.
 *
 * Let me re-examine: the two-buffer architecture means:
 * Buffer 1 (bitstream): presence bits, written LSB-first
 * Buffer 2 (byte buffer): value data, written as raw bytes
 * Then they're MERGED somehow into the final output.
 *
 * Wait — are they merged by interleaving bits? That would explain why
 * the output looks random! The presence bits go into the bitstream,
 * and the value bytes ALSO go into the bitstream as multi-bit writes.
 * It's ALL one bitstream, not two separate buffers!
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>

static unsigned g_base;

/* Bit writer addresses */
static unsigned g_w1_addr;   /* write_1bit_lsb: RVA 0x1a9e80 */
static unsigned g_wn_addr;   /* write_nbits_msb: RVA 0x1a8150 */
static unsigned g_wn_lsb;   /* write_nbits_lsb: RVA 0x1a8310 */

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

static void __attribute__((noinline)) wn_msb(unsigned *bs, unsigned val, unsigned nb) {
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

static void __attribute__((noinline)) wn_lsb(unsigned *bs, unsigned val, unsigned nb) {
    unsigned f = g_wn_lsb, b = (unsigned)bs;
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

int main() {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) { printf("FAIL %lu\n", GetLastError()); return 1; }
    g_base = (unsigned)h;
    g_w1_addr = g_base + 0x1a9e80;
    g_wn_addr = g_base + 0x1a8150;
    g_wn_lsb  = g_base + 0x1a8310;

    printf("DLL at 0x%08x\n", g_base);

    /*
     * HYPOTHESIS: The entire request body is ONE bitstream.
     * Presence bits are written with w1 (1 bit LSB-first).
     * Value data is written with wn (N bits) into the SAME bitstream.
     * This means value bytes are bit-shifted relative to the presence bits.
     *
     * For the login body:
     * - 16 presence bits (2 bytes if byte-aligned)
     * - But if values are interleaved, the bit position after presence
     *   bits is at bit 16, which IS byte-aligned (byte 2).
     * - So the first value byte starts at byte 2.
     *
     * But wait — the presence bits for login are 58 0c = 5 fields present.
     * If each present field writes its value immediately after its presence bit,
     * then the bits would be interleaved: p0 p1 p2 p3 [value3] p4 [value4] ...
     *
     * Let me test this theory by simulating the login encoding.
     */

    printf("\n=== Test: Interleaved presence + value bits ===\n");
    {
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        /* Login fields (16 total):
         * 0: absent, 1: absent, 2: absent
         * 3: present (RequestId? or DebugMode?)
         * 4: present
         * 5: absent
         * 6: present
         * 7-9: absent
         * 10: present
         * 11: present
         * 12-15: absent
         *
         * From the XML, the present fields with values are:
         * OperatingSystemName, OperatingSystemVersion,
         * OperatingSystemBuildVersion(?), AgentVersion,
         * AgentAliases, Language, AgentType
         *
         * But only 5 presence bits are set. Some fields might be
         * compound (containing sub-fields).
         */

        /* Simulate: write presence bits with values interleaved */
        /* Field 0: absent */
        w1(bs, 0);
        /* Field 1: absent */
        w1(bs, 0);
        /* Field 2: absent */
        w1(bs, 0);
        /* Field 3: present — write a test string "en" */
        w1(bs, 1);
        /* Now write the value for field 3 */
        wn_msb(bs, 'e', 8);
        wn_msb(bs, 'n', 8);
        wn_msb(bs, 0, 8);  /* null terminator? */
        /* Field 4: present — write "TB" */
        w1(bs, 1);
        wn_msb(bs, 'T', 8);
        wn_msb(bs, 'B', 8);
        wn_msb(bs, 0, 8);

        printf("Interleaved (MSB values): ");
        int i;
        for (i = 0; i < 10; i++) printf("%02x ", buf[i]);
        printf("\n");

        /* Now try with LSB values */
        memset(buf, 0, sizeof(buf));
        memset(bs, 0, sizeof(bs));
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        w1(bs, 0); w1(bs, 0); w1(bs, 0);
        w1(bs, 1);
        wn_lsb(bs, 'e', 8);
        wn_lsb(bs, 'n', 8);
        wn_lsb(bs, 0, 8);
        w1(bs, 1);
        wn_lsb(bs, 'T', 8);
        wn_lsb(bs, 'B', 8);
        wn_lsb(bs, 0, 8);

        printf("Interleaved (LSB values): ");
        for (i = 0; i < 10; i++) printf("%02x ", buf[i]);
        printf("\n");
    }

    printf("\n=== Test: All presence bits first, then all values ===\n");
    {
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        /* Write all 16 presence bits first */
        int login_bits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0,0,0};
        int i;
        for (i = 0; i < 16; i++) w1(bs, login_bits[i]);

        /* Then write value data as MSB bytes */
        const char *test = "en";
        for (i = 0; test[i]; i++) wn_msb(bs, test[i], 8);
        wn_msb(bs, 0, 8);

        printf("Separated (MSB): ");
        for (i = 0; i < 8; i++) printf("%02x ", buf[i]);
        printf("\n");
        printf("Expected login:  58 0c b3 e3 ...\n");

        /* Try with LSB values */
        memset(buf, 0, sizeof(buf));
        memset(bs, 0, sizeof(bs));
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        for (i = 0; i < 16; i++) w1(bs, login_bits[i]);
        for (i = 0; test[i]; i++) wn_lsb(bs, test[i], 8);
        wn_lsb(bs, 0, 8);

        printf("Separated (LSB): ");
        for (i = 0; i < 8; i++) printf("%02x ", buf[i]);
        printf("\n");
    }

    printf("\n=== Test: What does 0xb3 look like as bits after 58 0c? ===\n");
    {
        /* The captured login body starts: 58 0c b3 e3 92 f7 ...
         * 58 0c = presence bits (16 bits)
         * b3 = 10110011 — this is the start of value data
         *
         * If values are written MSB-first starting at bit 16:
         * b3 = 10110011 → first value byte is 0xb3
         *
         * If values are written LSB-first starting at bit 16:
         * b3 = 10110011 → reversed = 11001101 = 0xCD
         *
         * Neither 0xb3 nor 0xCD is an obvious ASCII char.
         * But what if there's a length prefix before the string?
         */

        /* Try: length-prefixed string "Windows 10 (build 19044)" = 24 chars */
        /* If length is encoded as a varint or fixed-width integer... */
        unsigned char buf[256] = {0};
        unsigned bs[8] = {0};
        bs[0] = (unsigned)buf;
        bs[3] = 256;

        int login_bits[] = {0,0,0,1,1,0,1,0, 0,0,1,1,0,0,0,0};
        int i;
        for (i = 0; i < 16; i++) w1(bs, login_bits[i]);

        /* Try writing length=24 as 8-bit MSB, then string bytes */
        wn_msb(bs, 24, 8);
        const char *os = "Windows 10 (build 19044)";
        for (i = 0; os[i]; i++) wn_msb(bs, os[i], 8);

        printf("len(8)+string MSB: ");
        for (i = 2; i < 6; i++) printf("%02x ", buf[i]);
        printf("(expect: b3 e3 92 f7)\n");

        /* Try length as 16-bit MSB */
        memset(buf, 0, sizeof(buf));
        memset(bs, 0, sizeof(bs));
        bs[0] = (unsigned)buf;
        bs[3] = 256;
        for (i = 0; i < 16; i++) w1(bs, login_bits[i]);
        wn_msb(bs, 24, 16);
        for (i = 0; os[i]; i++) wn_msb(bs, os[i], 8);

        printf("len(16)+string MSB: ");
        for (i = 2; i < 6; i++) printf("%02x ", buf[i]);
        printf("(expect: b3 e3 92 f7)\n");

        /* Try length as 8-bit LSB */
        memset(buf, 0, sizeof(buf));
        memset(bs, 0, sizeof(bs));
        bs[0] = (unsigned)buf;
        bs[3] = 256;
        for (i = 0; i < 16; i++) w1(bs, login_bits[i]);
        wn_lsb(bs, 24, 8);
        for (i = 0; os[i]; i++) wn_lsb(bs, os[i], 8);

        printf("len(8)+string LSB: ");
        for (i = 2; i < 6; i++) printf("%02x ", buf[i]);
        printf("(expect: b3 e3 92 f7)\n");
    }

    FreeLibrary(h);
    return 0;
}
