#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE h;
    DWORD base, bss_size = 0x1A1F8;
    BYTE *bss;
    HANDLE f;
    DWORD w;
    int nz, i;

    h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) {
        printf("DONT_RESOLVE failed: %lu, trying normal...\n", GetLastError());
        h = LoadLibraryA("C:\\nngine.dll");
        if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }
        printf("Normal load OK\n");
    } else {
        printf("DONT_RESOLVE OK (DllMain skipped)\n");
    }

    base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    bss = (BYTE*)(base + 0x314200);
    nz = 0;
    for (i = 0; i < (int)bss_size; i++) if (bss[i]) nz++;
    printf("BSS: %d/%lu non-zero\n", nz, bss_size);

    f = CreateFileA("C:\\bss.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, bss, bss_size, &w, NULL);
        CloseHandle(f);
        printf("BSS written: %lu bytes\n", w);
    }

    f = CreateFileA("C:\\rdata.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, (BYTE*)(base + 0x2AE000), 0x5C200, &w, NULL);
        CloseHandle(f);
        printf("rdata written: %lu bytes\n", w);
    }

    if (nz > 0) {
        DWORD off = 0x327AC4 - 0x314200;
        printf("Country(0x327AC4): ");
        for (i = 0; i < 16; i++) printf("%02x", bss[off+i]);
        printf("\n  vtable=0x%08x bw=%d\n", *(DWORD*)(bss+off), bss[off+4]);
    }

    FreeLibrary(h);

    printf("\nNow trying WITH DllMain...\n");
    h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("DllMain load failed: %lu\n", GetLastError()); return 0; }

    base = (DWORD)h;
    printf("BASE2: 0x%08x\n", base);
    bss = (BYTE*)(base + 0x314200);
    nz = 0;
    for (i = 0; i < (int)bss_size; i++) if (bss[i]) nz++;
    printf("BSS after DllMain: %d non-zero\n", nz);

    if (nz > 0) {
        f = CreateFileA("C:\\bss_init.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            WriteFile(f, bss, bss_size, &w, NULL);
            CloseHandle(f);
            printf("BSS_INIT written: %lu bytes\n", w);
        }
        DWORD off = 0x327AC4 - 0x314200;
        printf("Country(0x327AC4): ");
        for (i = 0; i < 16; i++) printf("%02x", bss[off+i]);
        printf("\n  vtable=0x%08x bw=%d\n", *(DWORD*)(bss+off), bss[off+4]);
    }

    FreeLibrary(h);
    return 0;
}
