#include <windows.h>
#include <stdio.h>

/* Write to file using Win32 API (printf hangs after LoadLibraryA) */
static HANDLE gf = INVALID_HANDLE_VALUE;
static void wlog(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    DWORD w;
    WriteFile(gf, buf, n, &w, NULL);
}

int main() {
    gf = CreateFileA("C:\\fields.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (gf == INVALID_HANDLE_VALUE) return 1;

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL %lu\r\n", GetLastError()); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;
    wlog("BASE 0x%08x\r\n", base);

    DWORD bss_lo = base + 0x314200, bss_hi = base + 0x32C400;
    DWORD rdata_lo = base + 0x2AE000, rdata_hi = base + 0x30A200;

    /* Triplet array at RVA 0x30DE08 */
    /* Each triplet: [handler_vtable:4][field_desc_ptr:4][sub_desc:4] = 12 bytes */
    DWORD *trip = (DWORD*)(base + 0x30DE08);

    wlog("\r\nTriplet array (global field registry):\r\n");
    wlog("Idx  Name                           TypeID  Version     SubDesc\r\n");
    wlog("---  ----                           ------  -------     -------\r\n");

    int i;
    for (i = 0; i < 80; i++) {
        DWORD handler = trip[i*3 + 0];
        DWORD fd_ptr  = trip[i*3 + 1];
        DWORD sub     = trip[i*3 + 2];

        if (handler == 0 && fd_ptr == 0) break;

        /* The field descriptor at fd_ptr has a name structure at fd[2] (offset 8) */
        /* The name structure contains a pointer to the actual string */
        DWORD *fd = (DWORD*)fd_ptr;

        /* fd layout (from analysis): */
        /* [0] linked_list_sentinel (0x7ecbeb44) */
        /* [1] serializer_func */
        /* [2] name_struct_ptr → name_struct[2] = string_ptr */
        /* [3] version (e.g. 0xFFFF0001) */
        /* [4] sub_type_desc_ptr */
        /* [5] next_ptr */

        /* Get name: fd[2] points to a name structure */
        /* The name structure has the string at offset 8 (name_struct[2]) */
        char namebuf[40] = "???";
        DWORD name_struct = fd[2];
        if (name_struct > base && name_struct < base + 0x400000) {
            DWORD *ns = (DWORD*)name_struct;
            /* The name struct has: [hash:4][len:4][string_ptr:4] or similar */
            /* Try reading the string pointer at various offsets */
            DWORD str_ptr = ns[2]; /* offset 8 */
            if (str_ptr > rdata_lo && str_ptr < rdata_hi) {
                char *s = (char*)str_ptr;
                int j;
                for (j = 0; j < 35 && s[j] >= 0x20 && s[j] <= 0x7e; j++)
                    namebuf[j] = s[j];
                namebuf[j] = 0;
            } else {
                /* Try the name struct itself as a string */
                char *s = (char*)name_struct;
                if (s[0] >= 'A' && s[0] <= 'z') {
                    int j;
                    for (j = 0; j < 35 && s[j] >= 0x20 && s[j] <= 0x7e; j++)
                        namebuf[j] = s[j];
                    namebuf[j] = 0;
                }
            }
        }

        /* Get version */
        DWORD version = fd[3];
        int ver_lo = version & 0xFFFF;
        int ver_hi = (version >> 16) & 0xFFFF;

        /* Get type_id from sub_type_desc */
        int type_id = -1;
        DWORD sub_type = fd[4];
        if (sub_type >= bss_lo && sub_type < bss_hi) {
            type_id = *((BYTE*)sub_type + 4);
        }

        /* Check if sub_desc (from triplet) has useful info */
        int sub_type2 = -1;
        if (sub >= bss_lo && sub < bss_hi) {
            sub_type2 = *((BYTE*)sub + 4);
        }

        wlog("[%2d] %-30s  tid=%d  ver=%d..%d  sub=0x%08x\r\n",
             i, namebuf, type_id, ver_lo, ver_hi, sub);
    }
    wlog("\r\nTotal: %d entries\r\n", i);

    /* Now dump the KNOWN field descriptors (the ones with readable names) */
    /* These are at fixed RVA offsets in rdata */
    wlog("\r\n--- Known field descriptors (from rdata scan) ---\r\n");

    /* Scan rdata for field descriptors with pattern: */
    /* [name_ptr in rdata][0][0][version][type_obj in BSS][serializer in text] */
    BYTE *rdata = (BYTE*)rdata_lo;
    DWORD rdata_size = rdata_hi - rdata_lo;
    int found = 0;

    DWORD j;
    for (j = 0; j + 24 <= rdata_size; j += 4) {
        DWORD np = *(DWORD*)(rdata + j);
        DWORD z1 = *(DWORD*)(rdata + j + 4);
        DWORD z2 = *(DWORD*)(rdata + j + 8);
        DWORD ver = *(DWORD*)(rdata + j + 12);
        DWORD to = *(DWORD*)(rdata + j + 16);

        if (z1 != 0 || z2 != 0) continue;
        if (!(np >= rdata_lo && np < rdata_hi)) continue;
        if (!(to >= bss_lo && to < bss_hi)) continue;
        if (ver != 0xFFFF0001 && ver != 0xFFFF0000 && ver != 0xFFFF0002) continue;

        char *s = (char*)np;
        if (s[0] < 'A' || s[0] > 'Z') continue;

        int tid = *((BYTE*)to + 4);
        char name[50] = {0};
        int k;
        for (k = 0; k < 45 && s[k] >= 0x20 && s[k] <= 0x7e; k++) name[k] = s[k];

        wlog("  %-35s tid=%d ver=0x%08x rdata+0x%05x\r\n", name, tid, ver, j);
        found++;
    }
    wlog("Found %d named field descriptors\r\n", found);

    FreeLibrary(h);
    CloseHandle(gf);
    return 0;
}
