/*
 * snakeoil_hook.c — Hook FUN_101b3e10 (SnakeOil encrypt) in nngine.dll
 * to capture all encryption keys used during a session.
 *
 * Build: i686-w64-mingw32-gcc -O2 -o snakeoil_hook.exe snakeoil_hook.c -lkernel32
 * Run:   wine snakeoil_hook.exe
 *
 * The hook replaces the first bytes of FUN_101b3e10 with a JMP to our
 * trampoline, which logs the key (param_4, param_5) and then calls
 * the original function.
 */
#include <windows.h>
#include <stdio.h>

/* RVA of FUN_101b3e10 (SnakeOil encrypt) */
#define SNAKEOIL_RVA 0x1b3e10

static HANDLE g_log = INVALID_HANDLE_VALUE;
static unsigned char g_orig_bytes[5]; /* saved bytes for trampoline */
static void *g_snakeoil_addr;
static int g_call_count = 0;

static void log_msg(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (g_log != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_log, buf, n, &written, NULL);
    }
}

/*
 * FUN_101b3e10 signature (from Ghidra):
 *   void FUN_101b3e10(int param_1, int param_2, byte *param_3, uint param_4, uint param_5)
 *
 * param_1 = source data pointer
 * param_2 = length
 * param_3 = destination pointer (output)
 * param_4 = key_lo (eax seed)
 * param_5 = key_hi (esi seed)
 *
 * The key is: (param_5 << 32) | param_4
 */

/* Our hook function — called instead of the original */
static void __cdecl hook_snakeoil(unsigned char *src, int len, unsigned char *dst,
                                   unsigned int key_lo, unsigned int key_hi) {
    unsigned long long key = ((unsigned long long)key_hi << 32) | key_lo;
    g_call_count++;
    log_msg("[%d] SnakeOil: key=%llu (lo=0x%08X hi=0x%08X) len=%d src=0x%08X dst=0x%08X\r\n",
            g_call_count, key, key_lo, key_hi, len, (unsigned int)src, (unsigned int)dst);

    /* Show first 16 bytes of input */
    if (src && len > 0) {
        int show = len < 16 ? len : 16;
        log_msg("  input[0:%d]: ", show);
        for (int i = 0; i < show; i++)
            log_msg("%02X ", src[i]);
        log_msg("\r\n");
    }

    /* Restore original bytes, call original, re-hook */
    DWORD old;
    VirtualProtect(g_snakeoil_addr, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_snakeoil_addr, g_orig_bytes, 5);
    VirtualProtect(g_snakeoil_addr, 5, old, &old);

    /* Call original */
    typedef void (__cdecl *snakeoil_fn)(unsigned char*, int, unsigned char*, unsigned int, unsigned int);
    ((snakeoil_fn)g_snakeoil_addr)(src, len, dst, key_lo, key_hi);

    /* Re-install hook */
    VirtualProtect(g_snakeoil_addr, 5, PAGE_EXECUTE_READWRITE, &old);
    unsigned char jmp[5];
    jmp[0] = 0xE9; /* JMP rel32 */
    int rel = (int)hook_snakeoil - (int)g_snakeoil_addr - 5;
    memcpy(&jmp[1], &rel, 4);
    memcpy(g_snakeoil_addr, jmp, 5);
    VirtualProtect(g_snakeoil_addr, 5, old, &old);

    /* Show first 16 bytes of output */
    if (dst && len > 0) {
        int show = len < 16 ? len : 16;
        log_msg("  output[0:%d]: ", show);
        for (int i = 0; i < show; i++)
            log_msg("%02X ", dst[i]);
        log_msg("\r\n");
    }
}

int main(void) {
    /* Open log file */
    g_log = CreateFileA("C:\\snakeoil_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_log == INVALID_HANDLE_VALUE) {
        printf("Failed to open log file\n");
        return 1;
    }
    log_msg("SnakeOil Hook starting...\r\n");

    /* Load nngine.dll without DllMain (Mode B) */
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) {
        log_msg("Failed to load nngine.dll: %d\r\n", GetLastError());
        printf("Failed to load nngine.dll: %d\n", GetLastError());
        CloseHandle(g_log);
        return 1;
    }

    g_snakeoil_addr = (void*)((unsigned int)h + SNAKEOIL_RVA);
    log_msg("nngine.dll loaded at 0x%08X, SnakeOil at 0x%08X\r\n",
            (unsigned int)h, (unsigned int)g_snakeoil_addr);
    printf("nngine.dll loaded at 0x%08X\n", (unsigned int)h);

    /* Save original bytes */
    memcpy(g_orig_bytes, g_snakeoil_addr, 5);
    log_msg("Original bytes: %02X %02X %02X %02X %02X\r\n",
            g_orig_bytes[0], g_orig_bytes[1], g_orig_bytes[2],
            g_orig_bytes[3], g_orig_bytes[4]);

    /* Install JMP hook */
    DWORD old;
    VirtualProtect(g_snakeoil_addr, 5, PAGE_EXECUTE_READWRITE, &old);
    unsigned char jmp[5];
    jmp[0] = 0xE9;
    int rel = (int)hook_snakeoil - (int)g_snakeoil_addr - 5;
    memcpy(&jmp[1], &rel, 4);
    memcpy(g_snakeoil_addr, jmp, 5);
    VirtualProtect(g_snakeoil_addr, 5, old, &old);

    log_msg("Hook installed. Testing with known values...\r\n");

    /* Test: call SnakeOil with known key to verify hook works */
    unsigned char test_in[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char test_out[8] = {0};
    unsigned int test_lo = 0x5D36B98E; /* toolbox_code low */
    unsigned int test_hi = 0x000D4EA6; /* toolbox_code high */

    typedef void (__cdecl *snakeoil_fn)(unsigned char*, int, unsigned char*, unsigned int, unsigned int);
    ((snakeoil_fn)g_snakeoil_addr)(
        test_in, 8, test_out, test_lo, test_hi
    );

    log_msg("Test complete. Result: ");
    for (int i = 0; i < 8; i++)
        log_msg("%02X ", test_out[i]);
    log_msg("\r\n");

    printf("Hook test complete. Check C:\\snakeoil_log.txt\n");
    printf("Calls logged: %d\n", g_call_count);

    CloseHandle(g_log);
    FreeLibrary(h);
    return 0;
}
