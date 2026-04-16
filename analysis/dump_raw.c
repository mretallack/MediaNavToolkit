#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }
    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* Dump the first 20 field descriptors from the triplet array at RVA 0x30DE08 */
    DWORD *trip = (DWORD*)(base + 0x30DE08);

    printf("\nFirst 10 triplets (12 bytes each):\n");
    for (int i = 0; i < 10; i++) {
        DWORD a = trip[i*3], b = trip[i*3+1], c = trip[i*3+2];
        printf("  [%d] 0x%08x 0x%08x 0x%08x\n", i, a, b, c);

        /* b is the field descriptor pointer - dump 24 bytes at that address */
        BYTE *fd = (BYTE*)b;
        printf("       fd: ");
        for (int j = 0; j < 24; j++) printf("%02x", fd[j]);
        printf("\n");

        /* Check if fd[0:4] is a string pointer */
        DWORD name_ptr = *(DWORD*)fd;
        /* Try reading as string */
        char *s = (char*)name_ptr;
        int is_str = 1;
        for (int j = 0; j < 4; j++) {
            if (s[j] < 0x20 || s[j] > 0x7e) { is_str = 0; break; }
        }
        if (is_str) printf("       name: %.40s\n", s);
    }

    /* Also dump the known "Country" field descriptor at 0x7ecbe940 (from earlier analysis) */
    /* RVA = 0x7ecbe940 - base */
    DWORD country_fd = 0x2BE940 + base;  /* approximate */
    /* Actually use the address we found: rdata offset */
    /* From earlier: Field at 0x7ecbe940: name='Country' */
    /* With base 0x7e9f0000: 0x7ecbe940 = base + 0x2CE940 */
    BYTE *cfd = (BYTE*)(base + 0x2CE940);
    printf("\nCountry field descriptor (RVA 0x2CE940):\n  ");
    for (int j = 0; j < 24; j++) printf("%02x", cfd[j]);
    printf("\n");
    DWORD cn = *(DWORD*)cfd;
    printf("  name_ptr=0x%08x -> %.20s\n", cn, (char*)cn);
    printf("  type_obj=0x%08x\n", *(DWORD*)(cfd+16));
    DWORD to = *(DWORD*)(cfd+16);
    printf("  type_obj bytes: ");
    for (int j = 0; j < 12; j++) printf("%02x", ((BYTE*)to)[j]);
    printf("\n  type_id=%d\n", ((BYTE*)to)[4]);

    FreeLibrary(h);
    return 0;
}
