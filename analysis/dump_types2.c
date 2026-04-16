#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }

    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* The descriptor at RVA 0x30DE08 is an array of 12-byte triplets:
       [handler_vtable:4][field_desc_ptr:4][sub_desc:4]
       Each field_desc_ptr points to a 24-byte field descriptor in rdata.
       The field descriptor has: [name_ptr:4][0:4][0:4][version:4][type_obj:4][serializer:4]
    */

    DWORD *triplets = (DWORD*)(base + 0x30DE08);
    DWORD rdata_lo = base + 0x2AE000;
    DWORD rdata_hi = base + 0x30A200;
    DWORD bss_lo = base + 0x314200;
    DWORD bss_hi = base + 0x32C400;

    printf("\nField descriptors from triplet array:\n");
    for (int i = 0; i < 200; i++) {
        DWORD handler = triplets[i*3 + 0];
        DWORD fd_ptr  = triplets[i*3 + 1];
        DWORD sub     = triplets[i*3 + 2];

        if (handler == 0) break;
        if (fd_ptr < rdata_lo || fd_ptr >= rdata_hi) continue;

        DWORD *fd = (DWORD*)fd_ptr;
        DWORD name_ptr = fd[0];
        DWORD version  = fd[3];
        DWORD type_obj = fd[4];
        DWORD ser_func = fd[5];

        char *name = "?";
        if (name_ptr >= rdata_lo && name_ptr < rdata_hi) {
            name = (char*)name_ptr;
        }

        int type_id = -1;
        if (type_obj >= bss_lo && type_obj < bss_hi) {
            type_id = *((BYTE*)type_obj + 4);
        }

        printf("  [%3d] %-35s type=%d ver=0x%08x handler=0x%08x\n",
               i, name, type_id, version, handler);
    }

    /* Now let me also find the BODY-specific descriptor.
       The body object's inner vtable at RVA 0x2BB1AC returns descriptor at RVA 0x30DE08.
       But the OUTER vtable at RVA 0x2BB1B4 returns descriptor at RVA 0x30DE14.
       Let me check both. */

    printf("\nOuter descriptor (RVA 0x30DE14):\n");
    triplets = (DWORD*)(base + 0x30DE14);
    for (int i = 0; i < 200; i++) {
        DWORD handler = triplets[i*3 + 0];
        DWORD fd_ptr  = triplets[i*3 + 1];
        DWORD sub     = triplets[i*3 + 2];

        if (handler == 0) break;
        if (fd_ptr < rdata_lo || fd_ptr >= rdata_hi) continue;

        DWORD *fd = (DWORD*)fd_ptr;
        DWORD name_ptr = fd[0];
        DWORD type_obj = fd[4];

        char *name = "?";
        if (name_ptr >= rdata_lo && name_ptr < rdata_hi) name = (char*)name_ptr;

        int type_id = -1;
        if (type_obj >= bss_lo && type_obj < bss_hi) type_id = *((BYTE*)type_obj + 4);

        printf("  [%3d] %-35s type=%d\n", i, name, type_id);
    }

    FreeLibrary(h);
    return 0;
}
