#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Patch the bit writer functions to log calls via INT3 + VEH */

static FILE *logf = NULL;
static DWORD nng_base = 0;
static DWORD addr_1bit, addr_nmsb;
static BYTE orig_1bit_byte, orig_nmsb_byte;

static LONG WINAPI veh_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD eip = ep->ContextRecord->Eip;

    if (eip == addr_1bit) {
        /* write_1bit_lsb: ecx=bitstream, [esp+4]=value */
        DWORD *stack = (DWORD*)ep->ContextRecord->Esp;
        int value = stack[1] & 1; /* [esp+4] after return addr */
        if (logf) fprintf(logf, "P %d\n", value); /* P = presence bit */
        /* Restore original byte and single-step */
        *(BYTE*)addr_1bit = orig_1bit_byte;
        ep->ContextRecord->EFlags |= 0x100; /* TF for single step */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (eip == addr_nmsb) {
        /* write_nbits_msb: ecx=bitstream, [esp+4]=value, [esp+8]=nbits */
        DWORD *stack = (DWORD*)ep->ContextRecord->Esp;
        DWORD value = stack[1];
        DWORD nbits = stack[2];
        if (logf) fprintf(logf, "V %u %u\n", nbits, value); /* V = value */
        *(BYTE*)addr_nmsb = orig_nmsb_byte;
        ep->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* Single-step exception: re-install breakpoint */
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        DWORD old;
        VirtualProtect((void*)addr_1bit, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)addr_1bit = 0xCC;
        VirtualProtect((void*)addr_1bit, 1, old, &old);
        VirtualProtect((void*)addr_nmsb, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)addr_nmsb = 0xCC;
        VirtualProtect((void*)addr_nmsb, 1, old, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    logf = fopen("C:\\trace.log", "w");

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { fprintf(logf, "FAIL\n"); fclose(logf); return 1; }
    nng_base = (DWORD)h;
    fprintf(logf, "BASE: 0x%08x\n", nng_base);

    addr_1bit = nng_base + 0x1a9e80;
    addr_nmsb = nng_base + 0x1a8150;

    /* Install VEH */
    AddVectoredExceptionHandler(1, veh_handler);

    /* Save original bytes and install INT3 */
    DWORD old;
    orig_1bit_byte = *(BYTE*)addr_1bit;
    VirtualProtect((void*)addr_1bit, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr_1bit = 0xCC;
    VirtualProtect((void*)addr_1bit, 1, old, &old);

    orig_nmsb_byte = *(BYTE*)addr_nmsb;
    VirtualProtect((void*)addr_nmsb, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr_nmsb = 0xCC;
    VirtualProtect((void*)addr_nmsb, 1, old, &old);

    fprintf(logf, "Breakpoints set at 0x%08x and 0x%08x\n", addr_1bit, addr_nmsb);

    /* Now call NngineStart to trigger serialization */
    typedef void (*fn_start)(void);
    fn_start start = (fn_start)GetProcAddress(h, "NngineStart");
    if (start) {
        fprintf(logf, "Calling NngineStart...\n");
        fflush(logf);
        start();
        fprintf(logf, "NngineStart returned\n");
    } else {
        fprintf(logf, "NngineStart not found\n");
    }

    fflush(logf);
    fclose(logf);
    FreeLibrary(h);
    return 0;
}
