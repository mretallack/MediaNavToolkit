/*
 * trace_creds.c — Extracted from Ghidra decompile of nngine.dll
 *
 * Reproduces the credential selection and SnakeOil encryption logic
 * to understand how Secret₃ is derived for 0x08 flag requests.
 *
 * Key functions extracted:
 *   FUN_100b3a60 — protocol envelope builder (selects key)
 *   FUN_100b1670 — credential copier (copies Name/Code/Secret)
 *   FUN_101b3e10 — SnakeOil encrypt
 *
 * Build: gcc -o trace_creds trace_creds.c -lm
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*=== SnakeOil (FUN_101b3e10, RVA 0x1b3e10) ===*/
void snakeoil(uint8_t *src, int len, uint8_t *dst,
              uint32_t key_lo, uint32_t key_hi)
{
    uint32_t eax = key_lo, esi = key_hi;
    for (int i = 0; i < len; i++) {
        uint32_t edx = ((esi << 21) | (eax >> 11)) ^ esi;
        uint32_t ecx = (eax << 21) ^ eax;
        ecx ^= (edx >> 3);
        uint32_t new_esi = ((edx << 4) | (ecx >> 28)) ^ edx;
        uint32_t new_eax = (ecx << 4) ^ ecx;
        esi = new_esi;
        eax = new_eax;
        dst[i] = (uint8_t)(eax >> 23) ^ src[i];
    }
}

/*=== Credential Object Layout ===
 *
 * From FUN_100b1670 (credential copier):
 *   this[0]  (+0x00): vtable pointer
 *   this[1]  (+0x04): Name string (copied from src+0x04)
 *   this[2]  (+0x08): field (from src+0x08)
 *   this[3]  (+0x0C): flag byte (from src+0x0C)
 *   this[4]  (+0x10): Code_lo (from src+0x10) ← bulk copy start
 *   this[5]  (+0x14): Code_hi (from src+0x14)
 *   this[6]  (+0x18): unknown (from src+0x18)
 *   this[7]  (+0x1C): Secret_lo (from src+0x1C) ← ENCRYPTION KEY
 *   this[8]  (+0x20): Secret_hi (from src+0x20) ← ENCRYPTION KEY
 *   ...
 *   this[0x25](+0x94): end of bulk copy (0x22 dwords from src+0x10)
 *   this[0x26](+0x98): from src+0x98
 *   this[0x28](+0xA0): from src+0xA0
 *
 * From FUN_100b3a60 (protocol builder):
 *   Code  = *(uint64_t*)(cred + 0x10)  → goes into wire header
 *   Secret = {*(uint32_t*)(cred+0x1C), *(uint32_t*)(cred+0x20)} → SnakeOil key
 *
 * The debug log confirms:
 *   "name: %s\ncode: %lld\nsecret: %lld"
 *   name   = *(char**)(cred + 0x04) [via string at cred+0x08?]
 *   code   = {*(uint32_t*)(cred+0x10), *(uint32_t*)(cred+0x14)}
 *   secret = {*(uint32_t*)(cred+0x1C), *(uint32_t*)(cred+0x20)}
 */

typedef struct {
    uint32_t vtable;     /* +0x00 */
    uint32_t name_ptr;   /* +0x04: pointer to Name string */
    uint32_t field_08;   /* +0x08 */
    uint8_t  flag_0c;    /* +0x0C */
    uint8_t  pad[3];
    uint32_t code_lo;    /* +0x10 */
    uint32_t code_hi;    /* +0x14 */
    uint32_t field_18;   /* +0x18 */
    uint32_t secret_lo;  /* +0x1C */
    uint32_t secret_hi;  /* +0x20 */
    /* ... more fields up to +0x94 */
} CredentialObject;

/*=== Key Selection Logic (from FUN_100b3a60 lines 152300-152320) ===
 *
 * iVar3 = credential_provider->get_credentials();  // vtable[6]
 *
 * if (iVar3 == 0 || request->mode == 2) {
 *     // RANDOM mode: time-based seed
 *     mode = 2;
 *     t = time(NULL);
 *     t = (t << 21) ^ t;
 *     hi = (uint32_t)(t >> 32);
 *     lo = (uint32_t)t ^ (hi >> 3);
 *     key_hi = ((hi << 4) | (lo >> 28)) ^ hi;
 *     key_lo = (lo << 4) ^ lo;
 *     // key = {key_lo, key_hi}
 * } else {
 *     // DEVICE mode: use credential's Secret
 *     mode = 3;
 *     header_code = *(uint64_t*)(iVar3 + 0x10);  // Code for wire header
 *     key_lo = *(uint32_t*)(iVar3 + 0x1C);       // Secret_lo
 *     key_hi = *(uint32_t*)(iVar3 + 0x20);       // Secret_hi
 * }
 *
 * // BOTH query and body encrypted with {key_lo, key_hi}
 * snakeoil(query, query_len, query, key_lo, key_hi);
 * snakeoil(body, body_len, body, key_lo, key_hi);
 */

void print_hex(const char *label, const uint8_t *data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len && i < 32; i++) printf("%02X ", data[i]);
    printf("\n");
}

int main(void) {
    /* Known credential values */
    uint64_t tb_code   = 3745651132643726ULL;  /* 0x000D4EA65D36B98E */
    uint64_t tb_secret = 3037636188661496ULL;  /* 0x000ACAB6C9FB66F8 */
    uint64_t hu_code   = 3362879562238844ULL;  /* 0x000BF28569BACB7C */
    uint64_t hu_secret = 4196269328295954ULL;  /* 0x000EE87C16B1E812 */

    printf("=== Known Credentials ===\n");
    printf("  tb_code:   %llu (lo=0x%08X hi=0x%08X)\n", tb_code,
           (uint32_t)tb_code, (uint32_t)(tb_code >> 32));
    printf("  tb_secret: %llu (lo=0x%08X hi=0x%08X)\n", tb_secret,
           (uint32_t)tb_secret, (uint32_t)(tb_secret >> 32));
    printf("  hu_code:   %llu (lo=0x%08X hi=0x%08X)\n", hu_code,
           (uint32_t)hu_code, (uint32_t)(hu_code >> 32));
    printf("  hu_secret: %llu (lo=0x%08X hi=0x%08X)\n", hu_secret,
           (uint32_t)hu_secret, (uint32_t)(hu_secret >> 32));

    /* Name₃ = 0xC4 + hu_code(8B BE) + tb_code(7B BE) */
    uint8_t name3[16];
    name3[0] = 0xC4;
    for (int i = 0; i < 8; i++) name3[1+i] = (hu_code >> (56 - i*8)) & 0xFF;
    for (int i = 0; i < 7; i++) name3[9+i] = (tb_code >> (56 - i*8)) & 0xFF;
    print_hex("Name3", name3, 16);

    printf("\n=== Credential Object Layout ===\n");
    printf("  The credential provider at this+0x1C returns a credential object.\n");
    printf("  The object has Code at +0x10/+0x14 and Secret at +0x1C/+0x20.\n");
    printf("  For DEVICE mode, the SnakeOil key = Secret.\n");
    printf("  For RANDOM mode, the key = time-based seed.\n");

    printf("\n=== Testing: what if the credential object for 0x08 has ===\n");
    printf("  Name = Name₃ (constructed from Code values)\n");
    printf("  Code = ??? \n");
    printf("  Secret = ???\n");

    /* The credential source data is at parent+0x84 in FUN_100b10c0.
     * FUN_100b1670 copies from source+0x10 to dest+0x10 (0x22 dwords).
     * So the Secret at dest+0x1C comes from source+0x1C.
     * The source is at parent+0x84, so Secret comes from parent+0x84+0x1C = parent+0xA0.
     *
     * The parent object is a device descriptor. The credential data at +0x84
     * is part of the device descriptor structure.
     *
     * For the TOOLBOX device descriptor:
     *   +0x84+0x10 = +0x94: tb_code_lo
     *   +0x84+0x14 = +0x98: tb_code_hi
     *   +0x84+0x1C = +0xA0: tb_secret_lo
     *   +0x84+0x20 = +0xA4: tb_secret_hi
     *
     * For the HU device descriptor (from delegator):
     *   +0x84+0x10 = +0x94: hu_code_lo
     *   +0x84+0x14 = +0x98: hu_code_hi
     *   +0x84+0x1C = +0xA0: hu_secret_lo
     *   +0x84+0x20 = +0xA4: hu_secret_hi
     *
     * The 0x08 path uses a DIFFERENT device descriptor than the 0x60 path.
     * The 0x60 path uses the toolbox descriptor → tb_secret.
     * The 0x08 path uses the HU descriptor → hu_secret.
     *
     * BUT we already tested hu_secret and it doesn't work!
     *
     * UNLESS: the credential data at +0x84 in the HU descriptor is NOT
     * the delegator credentials. It might be a DIFFERENT set of credentials
     * that was stored during a different phase of initialization.
     */

    printf("\n=== Hypothesis: 0x08 uses hu_secret ===\n");
    printf("  This was already tested and FAILED.\n");
    printf("  The 0x08 body does NOT decrypt with hu_secret.\n");

    printf("\n=== Alternative: the credential data at +0x84 is modified ===\n");
    printf("  Maybe the HU device descriptor modifies the credentials\n");
    printf("  before storing them at +0x84.\n");
    printf("  The modification could be:\n");
    printf("  - XOR with a device-specific value\n");
    printf("  - Byte swap\n");
    printf("  - Derived from the SWID or IMEI\n");

    /* Let me check: what's at +0x18 in the credential object?
     * The bulk copy copies 0x22 dwords from source+0x10 to dest+0x10.
     * That's offsets +0x10 through +0x94 (0x88 bytes).
     * The field at +0x18 is between Code_hi (+0x14) and Secret_lo (+0x1C).
     * It's 4 bytes. What could it be?
     *
     * In the protocol builder:
     *   local_134 = *(undefined8 *)(iVar3 + 0x10);  // Code (8 bytes)
     *   local_12c = *(undefined4 *)(iVar3 + 0x18);  // This field!
     *
     * local_12c is used later but not for encryption.
     * It might be a flags field or a credential type indicator.
     */

    printf("\n=== Field at +0x18 in credential object ===\n");
    printf("  Read as: local_12c = *(uint32_t*)(cred + 0x18)\n");
    printf("  This is between Code_hi and Secret_lo.\n");
    printf("  Might be: credential type, flags, or padding.\n");
    printf("  In RANDOM mode: local_12c is set to 1 (CONCAT31 with 1).\n");
    printf("  In DEVICE mode: local_12c = *(cred + 0x18).\n");

    /* KEY INSIGHT: In the protocol builder, the key is allocated as 8 bytes:
     *   puVar6 = malloc(8);
     *   *puVar6 = *(uint32_t*)(iVar3 + 0x1C);   // Secret_lo
     *   puVar6[1] = *(uint32_t*)(iVar3 + 0x20);  // Secret_hi
     *   param_3[0x10] = puVar6;
     *
     * Then BOTH query and body are encrypted with this key:
     *   snakeoil(query, qlen, query, *puVar6, puVar6[1]);
     *   snakeoil(body, blen, body, *puVar6, puVar6[1]);
     *
     * But empirically, the query decrypts with CODE (not Secret).
     * This means either:
     * (a) The query is pre-encrypted with Code before this function
     * (b) Or this function encrypts with Secret, and the query was
     *     already XOR'd with Code, so the net effect is Code encryption
     *
     * Wait — SnakeOil is XOR-based. If the query is first encrypted
     * with Code, then encrypted again with Secret:
     *   result = SnakeOil(SnakeOil(plain, Code), Secret)
     * To decrypt: SnakeOil(SnakeOil(result, Secret), Code) = plain
     * But we decrypt with just Code and get the right result.
     * That means SnakeOil(result, Code) = plain
     * Which means result = SnakeOil(plain, Code)
     * So the Secret encryption is NOT applied to the query.
     *
     * This means the code path I'm looking at does NOT encrypt the query.
     * The query must be encrypted elsewhere, and this function only
     * encrypts the body.
     *
     * OR: piVar11[0x10] points to the CODE, not the Secret!
     * Let me re-read the DEVICE mode code:
     *   *puVar6 = *(uint32_t*)(iVar3 + 0x1C);
     *   puVar6[1] = *(uint32_t*)(iVar3 + 0x20);
     *
     * What if +0x1C/+0x20 is actually the CODE, not the Secret?
     * The debug log says:
     *   code   = {*(cred+0x10), *(cred+0x14)}
     *   secret = {*(cred+0x1C), *(cred+0x20)}
     *
     * But what if the debug log is WRONG about which is which?
     * Or what if the credential object stores them in a different order
     * than we think?
     */

    printf("\n=== CRITICAL REALIZATION ===\n");
    printf("  The protocol builder encrypts BOTH query and body with\n");
    printf("  the key from cred+0x1C/+0x20.\n");
    printf("  The query decrypts with tb_code.\n");
    printf("  Therefore: cred+0x1C/+0x20 = tb_code (NOT tb_secret)!\n");
    printf("  And cred+0x10/+0x14 = tb_secret (NOT tb_code)!\n");
    printf("\n");
    printf("  The debug log says 'code' is at +0x10 and 'secret' at +0x1C.\n");
    printf("  But the ENCRYPTION KEY is at +0x1C.\n");
    printf("  And the WIRE HEADER key is at... let me check.\n");

    /* In the protocol builder:
     *   local_134 = *(undefined8 *)(iVar3 + 0x10);  // "Code" per debug log
     *
     * local_134 is used for the wire header (bytes 4-11).
     * The wire header contains tb_code = 0x000D4EA65D36B98E.
     *
     * If +0x10 = "Code" = tb_code, then +0x1C = "Secret" = tb_secret.
     * But the encryption key is at +0x1C, and the query decrypts with tb_code.
     * CONTRADICTION!
     *
     * Unless the query is NOT encrypted by this function.
     * The query might be encrypted by a DIFFERENT function that uses Code.
     *
     * Let me verify: the body decrypts with tb_secret for 0x60 flows.
     * If +0x1C = tb_secret, then the body key IS tb_secret. ✓
     * And the query is encrypted elsewhere with tb_code. ✓
     *
     * So for the 0x08 path:
     *   +0x10/+0x14 = Code (goes into wire header) = tb_code (same for all flows)
     *   +0x1C/+0x20 = Secret (body encryption key) = ???
     *
     * The wire header key is ALWAYS tb_code (we verified this).
     * So +0x10/+0x14 = tb_code for ALL credential objects.
     * And +0x1C/+0x20 = the body key, which differs per credential object.
     *
     * For toolbox: +0x1C/+0x20 = tb_secret ✓
     * For 0x08:    +0x1C/+0x20 = ??? (unknown)
     *
     * WAIT. The wire header key is ALWAYS tb_code. But the credential
     * object for 0x08 is DIFFERENT. If +0x10 = Code = tb_code for all,
     * then the 0x08 credential object also has tb_code at +0x10.
     * But the 0x08 credential object has Name₃ (not tb_name).
     * So the credential object has: Name=Name₃, Code=tb_code, Secret=???
     *
     * This doesn't make sense. The delegator credentials have:
     * Name=hu_name, Code=hu_code, Secret=hu_secret.
     * If the 0x08 credential object uses delegator credentials,
     * then Code=hu_code, not tb_code.
     *
     * But the wire header is ALWAYS tb_code...
     * Unless the wire header is NOT from the credential object.
     * The wire header might be set separately, always using tb_code.
     */

    printf("\n=== Wire Header Analysis ===\n");
    printf("  Wire header bytes 4-11 = tb_code for ALL flows.\n");
    printf("  This is set in the wire protocol layer, NOT from the credential object.\n");
    printf("  The credential object's Code (+0x10) might be different.\n");
    printf("\n");
    printf("  For 0x08 credential object:\n");
    printf("    Name = Name₃ (constructed)\n");
    printf("    Code = hu_code (from delegator)\n");
    printf("    Secret = hu_secret (from delegator)\n");
    printf("\n");
    printf("  But hu_secret doesn't decrypt the 0x08 body!\n");
    printf("  UNLESS the body is encrypted TWICE:\n");
    printf("    1. First with hu_secret (credential Secret)\n");
    printf("    2. Then with tb_code (wire header key, applied to both query+body)\n");
    printf("\n");
    printf("  Let me test: decrypt with tb_code first, then hu_secret.\n");

    /* Test double decryption */
    /* Flow 737 encrypted body (first 20 bytes) */
    uint8_t enc737[] = {
        0x31,0xdc,0x59,0x8e,0xdc,0xb1,0x3a,0xd7,0x47,0x31,
        0x8a,0x60,0x5b,0xff,0x48,0x3c,0x3b,0xe1,0x0a,0xac
    };
    uint8_t tmp[20], result[20];

    /* Decrypt with tb_code first (undo the outer encryption) */
    uint32_t tc_lo = (uint32_t)tb_code;
    uint32_t tc_hi = (uint32_t)(tb_code >> 32);
    snakeoil(enc737, 20, tmp, tc_lo, tc_hi);
    printf("\n  After tb_code decrypt: ");
    for (int i = 0; i < 20; i++) printf("%02X ", tmp[i]);
    printf("\n");

    /* Then decrypt with hu_secret */
    uint32_t hs_lo = (uint32_t)hu_secret;
    uint32_t hs_hi = (uint32_t)(hu_secret >> 32);
    snakeoil(tmp, 20, result, hs_lo, hs_hi);
    printf("  After hu_secret decrypt: ");
    for (int i = 0; i < 20; i++) printf("%02X ", result[i]);
    printf("\n");
    printf("  As text: ");
    for (int i = 0; i < 20; i++)
        printf("%c", (result[i] >= 32 && result[i] < 127) ? result[i] : '.');
    printf("\n");

    if (result[0] == 0xD8 && result[1] == 0x02)
        printf("  *** MATCH: D8 02 header! ***\n");

    /* Also try: hu_secret first, then tb_code */
    snakeoil(enc737, 20, tmp, hs_lo, hs_hi);
    snakeoil(tmp, 20, result, tc_lo, tc_hi);
    printf("\n  hu_secret then tb_code: ");
    for (int i = 0; i < 20; i++) printf("%02X ", result[i]);
    printf("\n");
    if (result[0] == 0xD8 && result[1] == 0x02)
        printf("  *** MATCH: D8 02 header! ***\n");

    /* Try: tb_secret first, then hu_secret */
    uint32_t ts_lo = (uint32_t)tb_secret;
    uint32_t ts_hi = (uint32_t)(tb_secret >> 32);
    snakeoil(enc737, 20, tmp, ts_lo, ts_hi);
    snakeoil(tmp, 20, result, hs_lo, hs_hi);
    printf("\n  tb_secret then hu_secret: ");
    for (int i = 0; i < 20; i++) printf("%02X ", result[i]);
    printf("\n");
    if (result[0] == 0xD8 && result[1] == 0x02)
        printf("  *** MATCH: D8 02 header! ***\n");

    /* Try: hu_secret then tb_secret */
    snakeoil(enc737, 20, tmp, hs_lo, hs_hi);
    snakeoil(tmp, 20, result, ts_lo, ts_hi);
    printf("\n  hu_secret then tb_secret: ");
    for (int i = 0; i < 20; i++) printf("%02X ", result[i]);
    printf("\n");
    if (result[0] == 0xD8 && result[1] == 0x02)
        printf("  *** MATCH: D8 02 header! ***\n");

    /* Try: hu_code then tb_secret */
    uint32_t hc_lo = (uint32_t)hu_code;
    uint32_t hc_hi = (uint32_t)(hu_code >> 32);
    snakeoil(enc737, 20, tmp, hc_lo, hc_hi);
    snakeoil(tmp, 20, result, ts_lo, ts_hi);
    printf("\n  hu_code then tb_secret: ");
    for (int i = 0; i < 20; i++) printf("%02X ", result[i]);
    printf("\n");
    if (result[0] == 0xD8 && result[1] == 0x02)
        printf("  *** MATCH: D8 02 header! ***\n");

    /* Try: tb_secret then hu_code */
    snakeoil(enc737, 20, tmp, ts_lo, ts_hi);
    snakeoil(tmp, 20, result, hc_lo, hc_hi);
    printf("\n  tb_secret then hu_code: ");
    for (int i = 0; i < 20; i++) printf("%02X ", result[i]);
    printf("\n");
    if (result[0] == 0xD8 && result[1] == 0x02)
        printf("  *** MATCH: D8 02 header! ***\n");

    /* Try ALL 12 ordered pairs */
    uint64_t keys[] = {tb_code, tb_secret, hu_code, hu_secret};
    const char *knames[] = {"tb_code", "tb_secret", "hu_code", "hu_secret"};
    printf("\n=== All ordered pairs (decrypt A then B) ===\n");
    for (int a = 0; a < 4; a++) {
        for (int b = 0; b < 4; b++) {
            if (a == b) continue;
            uint32_t a_lo = (uint32_t)keys[a], a_hi = (uint32_t)(keys[a] >> 32);
            uint32_t b_lo = (uint32_t)keys[b], b_hi = (uint32_t)(keys[b] >> 32);
            snakeoil(enc737, 20, tmp, a_lo, a_hi);
            snakeoil(tmp, 20, result, b_lo, b_hi);
            int has_d8 = (result[0] == 0xD8);
            int printable = 0;
            for (int i = 4; i < 20; i++)
                if (result[i] >= 32 && result[i] < 127) printable++;
            if (has_d8 || printable > 8) {
                printf("  %s → %s: ", knames[a], knames[b]);
                for (int i = 0; i < 8; i++) printf("%02X ", result[i]);
                printf(" p=%d\n", printable);
            }
        }
    }

    return 0;
}
