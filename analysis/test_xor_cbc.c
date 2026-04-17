/* test_xor_cbc.c - Test XOR-CBC decryption of .lyc files with various keys
 *
 * The XOR-CBC algorithm from FUN_10158410:
 *   key = {k0, k1, k2, k3}  // 16 bytes
 *   for each 16-byte block:
 *     out[i] = in[i] ^ key[i]
 *     key[i] ^= out[i]
 *
 * The first uint32 of decrypted data must be 0x36c8b267.
 * This means: key[0] = encrypted[0] ^ 0x36c8b267
 * So key[0] is KNOWN for any given .lyc file!
 *
 * We need to find key[1], key[2], key[3].
 * The key is 16 bytes = MD5 of some string.
 * Since key[0] is known, we can verify MD5 candidates quickly.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned int u32;
typedef unsigned char u8;

/* MD5 from the DLL */
typedef void (__cdecl *MD5Fn)(int data, int len, u32 *result, int param4);

static void xor_cbc_decrypt(const u8 *in, int len, u8 *out, u32 k[4]) {
    u32 key[4] = {k[0], k[1], k[2], k[3]};
    for (int off = 0; off + 15 < len; off += 16) {
        u32 blk[4];
        memcpy(blk, in + off, 16);
        u32 o[4];
        for (int i = 0; i < 4; i++) {
            o[i] = blk[i] ^ key[i];
            key[i] ^= o[i];
        }
        memcpy(out + off, o, 16);
    }
}

int main(void) {
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) { printf("DLL load failed\n"); return 1; }
    u8 *base = (u8*)h;
    MD5Fn md5fn = (MD5Fn)(base + 0x157D40);

    /* Read .lyc file */
    FILE *f = fopen("C:\\global_config.lyc", "rb");
    if (!f) { printf("No .lyc\n"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 8, SEEK_SET);
    u8 *data = malloc(sz);
    int dlen = fread(data, 1, sz - 8, f);
    fclose(f);

    /* key[0] is determined by the magic */
    u32 enc0;
    memcpy(&enc0, data, 4);
    u32 key0 = enc0 ^ 0x36c8b267;
    printf("key[0] = 0x%08X\n", key0);

    /* Read device.nng */
    f = fopen("C:\\device.nng", "rb");
    u8 nng[268];
    int nng_len = 0;
    if (f) { nng_len = fread(nng, 1, 268, f); fclose(f); }

    /* Try MD5 of many strings - check if MD5[0] == key0 */
    int tested = 0, matched = 0;
    u32 result[4];
    u8 buf[256];

    /* Device identity strings */
    const char *strings[] = {
        "DaciaAutomotive", "DaciaAutomotiveDeviceCY20_ULC4dot5",
        "CK-A80R-YEC3-MYXL-18LN", "UU1DJF00869579646",
        "32483158423731362D42323938353431", "2H1XB716-B298541",
        "9DF60F15136D64AC7E234644DD228027", "1107299155",
        "m0$7j0n4(0n73n71I)", "NNGE",
        "Renault_Dacia_Global_Config_update",
        "Renault_Dacia_Global_Config_update.lyc",
        "LGe_Renault_ULC4DOT5_20CY_Primo_WEU_19Q4_HM_POI_KML_TMC_SPC_JV_iWEUHM@19Q4RenaultULC",
        "Renault_Dacia_ULC2_Language_Update",
        "1774273627_1", "1774273627",
        NULL
    };

    /* Try with various format strings */
    const char *formats[] = {
        "%s", "SPEEDx%sCAM", "SPEED%sCAM", "SPEEDx%s", "%sCAM",
        NULL
    };

    for (int si = 0; strings[si]; si++) {
        for (int fi = 0; formats[fi]; fi++) {
            int len = sprintf((char*)buf, formats[fi], strings[si]);
            md5fn((int)buf, len, result, 0);
            tested++;
            if (result[0] == key0) {
                printf("*** MD5 MATCH key[0]: fmt='%s' str='%s'\n", formats[fi], strings[si]);
                printf("    MD5: %08X %08X %08X %08X\n", result[0], result[1], result[2], result[3]);
                /* Try full decrypt */
                u32 key[4] = {result[0], result[1], result[2], result[3]};
                u8 dec[64];
                xor_cbc_decrypt(data, 48, dec, key);
                u32 magic;
                memcpy(&magic, dec, 4);
                printf("    Decrypted magic: 0x%08X %s\n", magic,
                       magic == 0x36c8b267 ? "*** CREDENTIAL FOUND! ***" : "(no match)");
                if (magic == 0x36c8b267) {
                    printf("    Full decrypt[0:40]: ");
                    for (int i = 0; i < 40; i++) printf("%02X", dec[i]);
                    printf("\n");
                    matched++;
                }
            }
        }
    }

    /* Try MD5 of binary data from device.nng */
    for (int off = 0; off < nng_len; off++) {
        for (int len = 1; len <= 32 && off + len <= nng_len; len++) {
            md5fn((int)(nng + off), len, result, 0);
            tested++;
            if (result[0] == key0) {
                printf("*** MD5 MATCH key[0]: nng[0x%02X:%d]\n", off, len);
                u32 key[4] = {result[0], result[1], result[2], result[3]};
                u8 dec[64];
                xor_cbc_decrypt(data, 48, dec, key);
                u32 magic;
                memcpy(&magic, dec, 4);
                printf("    magic: 0x%08X %s\n", magic,
                       magic == 0x36c8b267 ? "*** FOUND! ***" : "");
                if (magic == 0x36c8b267) matched++;
            }
        }
    }

    /* Try MD5 of "SPEEDx" + nng_section + "CAM" */
    for (int off = 0; off < nng_len; off++) {
        for (int len = 1; len <= 32 && off + len <= nng_len; len++) {
            u8 tmp[300];
            int tlen = sprintf((char*)tmp, "SPEEDx");
            memcpy(tmp + tlen, nng + off, len);
            tlen += len;
            tlen += sprintf((char*)tmp + tlen, "CAM");
            md5fn((int)tmp, tlen, result, 0);
            tested++;
            if (result[0] == key0) {
                printf("*** MD5 MATCH: SPEEDx+nng[0x%02X:%d]+CAM\n", off, len);
                u32 key[4] = {result[0], result[1], result[2], result[3]};
                u8 dec[64];
                xor_cbc_decrypt(data, 48, dec, key);
                u32 magic;
                memcpy(&magic, dec, 4);
                printf("    magic: 0x%08X %s\n", magic,
                       magic == 0x36c8b267 ? "*** FOUND! ***" : "");
                if (magic == 0x36c8b267) matched++;
            }
        }
    }

    printf("\nTested %d keys, %d full matches\n", tested, matched);
    FreeLibrary(h);
    free(data);
    return 0;
}
