/* crt_patch2.c - Run constructors with crash protection */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static FILE *g_log = NULL;
static unsigned char *g_base = NULL;
static unsigned char g_orig[16];
static int g_call_count = 0;

void __cdecl hook_fn(unsigned char *src, int len, unsigned char *dst,
                     unsigned int key_lo, unsigned int key_hi) {
    g_call_count++;
    if (g_log) {
        fprintf(g_log, "key_lo=0x%08X key_hi=0x%08X key=%llu len=%d\n",
                key_lo, key_hi, ((unsigned long long)key_hi << 32) | key_lo, len);
        fflush(g_log);
    }
    DWORD p;
    VirtualProtect(g_base + 0x1B3E10, 16, PAGE_EXECUTE_READWRITE, &p);
    memcpy(g_base + 0x1B3E10, g_orig, 16);
    VirtualProtect(g_base + 0x1B3E10, 16, p, &p);
    ((void(__cdecl*)(unsigned char*,int,unsigned char*,unsigned int,unsigned int))
     (g_base + 0x1B3E10))(src, len, dst, key_lo, key_hi);
    VirtualProtect(g_base + 0x1B3E10, 16, PAGE_EXECUTE_READWRITE, &p);
    g_base[0x1B3E10] = 0xE9;
    *(int*)(g_base + 0x1B3E10 + 1) = (int)((unsigned char*)hook_fn - (g_base + 0x1B3E10 + 5));
    VirtualProtect(g_base + 0x1B3E10, 16, p, &p);
}

typedef void (*CtorFn)(void);

struct CtorArg { CtorFn fn; int ok; };

static DWORD WINAPI ctor_thread(LPVOID param) {
    struct CtorArg *arg = (struct CtorArg*)param;
    arg->fn();
    arg->ok = 1;
    return 0;
}

int main(void) {
    g_log = fopen("C:\\snakeoil_keys.log", "w");
    HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) { printf("Load failed\n"); return 1; }
    g_base = (unsigned char*)h;

    /* Hook SnakeOil */
    memcpy(g_orig, g_base + 0x1B3E10, 16);
    DWORD p;
    VirtualProtect(g_base + 0x1B3E10, 16, PAGE_EXECUTE_READWRITE, &p);
    g_base[0x1B3E10] = 0xE9;
    *(int*)(g_base + 0x1B3E10 + 1) = (int)((unsigned char*)hook_fn - (g_base + 0x1B3E10 + 5));
    VirtualProtect(g_base + 0x1B3E10, 16, p, &p);

    /* Skip C initializers - they have anti-debug checks */
    printf("Skipping C initializers (anti-debug)\n");

    /* Run C++ constructors: DAT_102ae30c to DAT_102af2fc */
    unsigned int *start = (unsigned int*)(g_base + 0x2ae30c);
    unsigned int *end = (unsigned int*)(g_base + 0x2af2fc);
    int total = 0, ok = 0, skip = 0, crash = 0;
    printf("Running C++ constructors (%d entries)...\n", (int)(end - start));
    fflush(stdout);

    for (unsigned int *ptr = start; ptr < end; ptr++) {
        if (*ptr == 0) continue;
        total++;
        CtorFn fn = (CtorFn)(*ptr);
        struct CtorArg arg = { fn, 0 };
        HANDLE t = CreateThread(NULL, 0, ctor_thread, &arg, 0, NULL);
        DWORD wait = WaitForSingleObject(t, 3000);
        if (wait == WAIT_TIMEOUT) {
            TerminateThread(t, 1);
            skip++;
        } else if (!arg.ok) {
            crash++;
        } else {
            ok++;
        }
        CloseHandle(t);
        /* Progress every 100 */
        if (total % 100 == 0) {
            printf("  [%d] ok=%d skip=%d crash=%d snakeoil=%d\n", total, ok, skip, crash, g_call_count);
            fflush(stdout);
        }
    }
    printf("Done: %d ok, %d timeout, %d crash, %d total, %d snakeoil calls\n",
           ok, skip, crash, total, g_call_count);

    fclose(g_log);
    g_log = NULL;
    FILE *f = fopen("C:\\snakeoil_keys.log", "r");
    if (f) {
        char line[256];
        printf("\n=== Captured SnakeOil keys ===\n");
        while (fgets(line, sizeof(line), f)) printf("%s", line);
        fclose(f);
    }

    FreeLibrary(h);
    return 0;
}
