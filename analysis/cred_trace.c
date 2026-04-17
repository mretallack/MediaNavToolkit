/*
 * cred_trace.c — Load nngine.dll with DllMain, hook SnakeOil,
 * and call the credential derivation functions to capture the third key.
 *
 * Strategy:
 * 1. Hook FUN_101b3e10 (SnakeOil) BEFORE loading nngine.dll
 * 2. Load nngine.dll with LoadLibraryA (Mode A — DllMain runs)
 * 3. DllMain initializes type descriptors and credential state
 * 4. Call the registration/delegator functions with known credentials
 * 5. The hook captures all SnakeOil keys used
 *
 * Since DllMain blocks stdio, all output goes to C:\cred_trace.log
 *
 * Build: i686-w64-mingw32-gcc -O2 -o cred_trace.exe cred_trace.c -lkernel32
 */
#include <windows.h>

#define SNAKEOIL_RVA 0x1b3e10

static HANDLE g_log = INVALID_HANDLE_VALUE;
static unsigned char g_orig_bytes[5];
static void *g_snakeoil_addr;
static HMODULE g_dll = NULL;
static int g_call_count = 0;

static void log_msg(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (g_log != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_log, buf, n, &written, NULL);
        FlushFileBuffers(g_log);
    }
}

static void log_hex(const char *label, unsigned char *data, int len) {
    log_msg("  %s[0:%d]: ", label, len > 32 ? 32 : len);
    int show = len < 32 ? len : 32;
    for (int i = 0; i < show; i++)
        log_msg("%02X ", data[i]);
    log_msg("\r\n");
}

/* Hook function for FUN_101b3e10 */
static void __cdecl hook_snakeoil(
    unsigned char *src, int len, unsigned char *dst,
    unsigned int key_lo, unsigned int key_hi)
{
    unsigned long long key = ((unsigned long long)key_hi << 32) | key_lo;
    g_call_count++;

    log_msg("[%d] SnakeOil encrypt: key_lo=0x%08X key_hi=0x%08X len=%d\r\n",
            g_call_count, key_lo, key_hi, len);

    /* Known keys for comparison */
    unsigned long long tb_code   = 3745651132643726ULL;
    unsigned long long tb_secret = 3037636188661496ULL;
    unsigned long long hu_code   = 3362879562238844ULL;
    unsigned long long hu_secret = 4196269328295954ULL;

    if (key == tb_code)        log_msg("  KEY = toolbox_code\r\n");
    else if (key == tb_secret) log_msg("  KEY = toolbox_secret\r\n");
    else if (key == hu_code)   log_msg("  KEY = hu_code\r\n");
    else if (key == hu_secret) log_msg("  KEY = hu_secret\r\n");
    else                       log_msg("  KEY = *** UNKNOWN *** %I64u\r\n", key);

    if (src && len > 0) log_hex("src", src, len);

    /* Restore, call original, re-hook */
    DWORD old;
    VirtualProtect(g_snakeoil_addr, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_snakeoil_addr, g_orig_bytes, 5);
    VirtualProtect(g_snakeoil_addr, 5, old, &old);

    typedef void (__cdecl *fn_t)(unsigned char*, int, unsigned char*, unsigned int, unsigned int);
    ((fn_t)g_snakeoil_addr)(src, len, dst, key_lo, key_hi);

    VirtualProtect(g_snakeoil_addr, 5, PAGE_EXECUTE_READWRITE, &old);
    unsigned char jmp[5] = {0xE9};
    int rel = (int)hook_snakeoil - (int)g_snakeoil_addr - 5;
    memcpy(&jmp[1], &rel, 4);
    memcpy(g_snakeoil_addr, jmp, 5);
    VirtualProtect(g_snakeoil_addr, 5, old, &old);

    if (dst && len > 0) log_hex("dst", dst, len);
}

static void install_hook(void) {
    memcpy(g_orig_bytes, g_snakeoil_addr, 5);
    DWORD old;
    VirtualProtect(g_snakeoil_addr, 5, PAGE_EXECUTE_READWRITE, &old);
    unsigned char jmp[5] = {0xE9};
    int rel = (int)hook_snakeoil - (int)g_snakeoil_addr - 5;
    memcpy(&jmp[1], &rel, 4);
    memcpy(g_snakeoil_addr, jmp, 5);
    VirtualProtect(g_snakeoil_addr, 5, old, &old);
}

int main(void) {
    g_log = CreateFileA("C:\\cred_trace.log", GENERIC_WRITE, FILE_SHARE_READ,
                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    log_msg("=== Credential Trace Starting ===\r\n");

    /* First load WITHOUT DllMain to get the base address and install hook */
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) {
        log_msg("FATAL: Cannot load nngine.dll: %d\r\n", GetLastError());
        CloseHandle(g_log);
        return 1;
    }
    g_snakeoil_addr = (void*)((unsigned int)h + SNAKEOIL_RVA);
    log_msg("nngine.dll loaded (no DllMain) at 0x%08X\r\n", (unsigned int)h);
    log_msg("SnakeOil at 0x%08X\r\n", (unsigned int)g_snakeoil_addr);

    /* Install hook */
    install_hook();
    log_msg("Hook installed\r\n");

    /* Free the no-DllMain copy */
    FreeLibrary(h);
    log_msg("Freed no-DllMain copy\r\n");

    /* Now load WITH DllMain — the hook is already in place at the same address */
    /* Wine loads DLLs at the same base address, so the hook should still work */
    log_msg("Loading nngine.dll WITH DllMain...\r\n");
    g_dll = LoadLibraryA("C:\\nngine.dll");
    if (!g_dll) {
        log_msg("FATAL: Cannot load nngine.dll with DllMain: %d\r\n", GetLastError());
        CloseHandle(g_log);
        return 1;
    }
    log_msg("nngine.dll loaded WITH DllMain at 0x%08X\r\n", (unsigned int)g_dll);
    log_msg("SnakeOil calls during DllMain: %d\r\n", g_call_count);

    /* The hook address might have changed if DLL loaded at different base */
    void *new_addr = (void*)((unsigned int)g_dll + SNAKEOIL_RVA);
    if (new_addr != g_snakeoil_addr) {
        log_msg("WARNING: DLL base changed! Old=0x%08X New=0x%08X\r\n",
                (unsigned int)g_snakeoil_addr, (unsigned int)new_addr);
        g_snakeoil_addr = new_addr;
        install_hook();
        log_msg("Hook re-installed at new address\r\n");
    }

    /* Now try to trigger credential derivation by calling internal functions */
    /* The DLL should have initialized its type system and credential state */

    log_msg("\r\n=== DllMain complete, %d SnakeOil calls captured ===\r\n", g_call_count);
    log_msg("Waiting 5 seconds for any background threads...\r\n");
    Sleep(5000);
    log_msg("Total SnakeOil calls: %d\r\n", g_call_count);

    FreeLibrary(g_dll);
    log_msg("Done.\r\n");
    CloseHandle(g_log);
    return 0;
}
