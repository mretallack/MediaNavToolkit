#include <windows.h>
#include <stdio.h>

/* Hook the bit writer functions in nngine.dll to trace serialization */

static FILE *logf = NULL;
static DWORD nng_base = 0;

/* Original function bytes for unhooking */
static BYTE orig_1bit[8];
static BYTE orig_nmsb[8];
static BYTE orig_nlsb[8];

/* Trampoline buffers */
static BYTE tramp_1bit[32];
static BYTE tramp_nmsb[32];

/* write_1bit_lsb at RVA 0x1a9e80 */
/* __thiscall: ecx=bitstream, stack: value */
/* We hook by replacing first bytes with jmp to our code */

static DWORD addr_1bit, addr_nmsb;

/* Our hook for write_1bit_lsb */
__declspec(naked) void hook_1bit(void) {
    __asm {
        /* Save registers */
        pushad
        pushfd
        /* Log the call: ecx=bitstream, [esp+0x28]=value (after pushad+pushfd) */
        mov eax, [esp+0x28]  /* value parameter */
        push eax
        push ecx
        call log_1bit
        add esp, 8
        /* Restore and jump to original */
        popfd
        popad
        jmp [tramp_1bit]
    }
}

void __cdecl log_1bit(DWORD bitstream, DWORD value) {
    if (logf) fprintf(logf, "W1 %d\n", value & 1);
}

/* Our hook for write_nbits_msb at RVA 0x1a8150 */
/* __thiscall: ecx=bitstream, stack: value, nbits */
__declspec(naked) void hook_nmsb(void) {
    __asm {
        pushad
        pushfd
        mov eax, [esp+0x2C]  /* nbits */
        mov edx, [esp+0x28]  /* value */
        push eax
        push edx
        push ecx
        call log_nmsb
        add esp, 12
        popfd
        popad
        jmp [tramp_nmsb]
    }
}

void __cdecl log_nmsb(DWORD bitstream, DWORD value, DWORD nbits) {
    if (logf) fprintf(logf, "WN %u %u\n", nbits, value);
}

static void install_hook(BYTE *target, void *hook, BYTE *orig_save, BYTE *trampoline) {
    DWORD old_prot;
    /* Save original bytes */
    memcpy(orig_save, target, 5);
    /* Create trampoline: original bytes + jmp back */
    memcpy(trampoline, target, 5);
    trampoline[5] = 0xE9; /* jmp rel32 */
    DWORD rel = (DWORD)(target + 5) - (DWORD)(trampoline + 10);
    *(DWORD*)(trampoline + 6) = rel;
    /* Make trampoline executable */
    VirtualProtect(trampoline, 32, PAGE_EXECUTE_READWRITE, &old_prot);
    /* Patch target with jmp to hook */
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &old_prot);
    target[0] = 0xE9; /* jmp rel32 */
    *(DWORD*)(target + 1) = (DWORD)hook - (DWORD)(target + 5);
    VirtualProtect(target, 8, old_prot, &old_prot);
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        logf = fopen("C:\\trace.log", "w");
        if (logf) fprintf(logf, "Hook DLL loaded\n");

        /* Find nngine.dll */
        HMODULE nng = GetModuleHandleA("nngine.dll");
        if (!nng && logf) { fprintf(logf, "nngine.dll not loaded yet\n"); fclose(logf); return TRUE; }
        nng_base = (DWORD)nng;
        if (logf) fprintf(logf, "nngine base: 0x%08x\n", nng_base);

        /* Install hooks */
        addr_1bit = nng_base + 0x1a9e80;
        addr_nmsb = nng_base + 0x1a8150;

        install_hook((BYTE*)addr_1bit, hook_1bit, orig_1bit, tramp_1bit);
        install_hook((BYTE*)addr_nmsb, hook_nmsb, orig_nmsb, tramp_nmsb);

        if (logf) fprintf(logf, "Hooks installed\n");
    }
    if (reason == DLL_PROCESS_DETACH) {
        if (logf) { fprintf(logf, "Unloading\n"); fclose(logf); }
    }
    return TRUE;
}
